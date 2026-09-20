#!/usr/bin/env bash
#
# install.sh - Instalador do ddns_manager (Linux) com cofre criptografado.
#
# Responsabilidades:
#   1. Detectar a arquitetura e baixar o binario adequado do release oficial.
#   2. Instalar o binario (padrao: ~/.local/bin) e validar a execucao.
#   3. Ler a Senha Mestra SEM eco e grava-la em arquivo 0600 (nao versionado).
#   4. Gerar wrapper, unit systemd (service + timer) e habilitar o agendamento.
#   5. Fallback para cron quando o systemd de usuario nao estiver disponivel.
#
# Seguranca:
#   - A senha nunca e exibida, registrada em log nem passada pela linha de comando.
#   - Arquivos de segredo sao criados com permissao restrita (0600) e diretorio 0700.
#   - O cofre (ddns_vault.enc) NUNCA e alterado ou removido por este script.
#
# Uso rapido:
#   ./install.sh                       # instala a ultima versao e agenda a cada 6 min
#   ./install.sh --nightly             # instala a ultima versao RC (pre-release)
#   ./install.sh --vault-dir ~/ddns    # informa o diretorio que contem o cofre
#   ./install.sh --password-stdin      # le a Senha Mestra do stdin (automacao)
#   ./install.sh --version v1.1.0 --interval 5
#   ./install.sh --uninstall           # remove agendamento e wrapper (mantem cofre)
#   ./install.sh --uninstall --purge   # remove tambem senha e binario
#
#   ./install.sh --help

set -euo pipefail

# ------------------------------------------------------------------ #
# Configuracao                                                       #
# ------------------------------------------------------------------ #
REPO="${DDNS_REPO:-vandinho10/ddns_manager}"
BIN_NAME="ddns_manager"
VAULT_FILE="ddns_vault.enc"
SERVICE_NAME="ddns-manager"
DEFAULT_INTERVAL_MIN=6

DEFAULT_BIN_DIR="$HOME/.local/bin"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/ddns_manager"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
WRAPPER="$CONFIG_DIR/${SERVICE_NAME}-run.sh"
PASSWORD_FILE="$CONFIG_DIR/password"
LOG_FILE="${XDG_STATE_HOME:-$HOME/.local/state}/ddns_manager/ddns_manager.log"
CRON_TAG="# ${SERVICE_NAME} (gerenciado por install.sh)"

# ------------------------------------------------------------------ #
# Estado (preenchido pelo CLI)                                       #
# ------------------------------------------------------------------ #
TAG=""
ARCH=""
NIGHTLY=0
BIN_DIR="$DEFAULT_BIN_DIR"
VAULT_DIR=""
INTERVAL_MIN="$DEFAULT_INTERVAL_MIN"
PASSWORD_SOURCE=""        # env | stdin | prompt
NO_TIMER=0
NO_LINGER=0
NO_TEST_RUN=0
UNINSTALL=0
PURGE=0
DRY_RUN=0
ASSUME_YES=0
WORK_DIR=""

# ------------------------------------------------------------------ #
# Saida / log                                                        #
# ------------------------------------------------------------------ #
if [[ -t 2 ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[34m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_RST=""
fi
log()  { printf '%s[*]%s %s\n'    "$C_BLU" "$C_RST" "$*" >&2; }
ok()   { printf '%s[OK]%s %s\n'   "$C_GRN" "$C_RST" "$*" >&2; }
warn() { printf '%s[!]%s %s\n'    "$C_YEL" "$C_RST" "$*" >&2; }
die()  { printf '%s[ERRO]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

cleanup() {
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    rm -rf -- "$WORK_DIR"
  fi
}
trap cleanup EXIT

usage() {
  cat >&2 <<'EOF'
Instalador do ddns_manager (Linux).

Opcoes:
  -v, --version TAG     Tag do release (padrao: ultima versao oficial).
      --nightly         Instala a ultima versao Release Candidate (RC).
  -a, --arch ARCH       Forca a arquitetura (x86_64 | aarch64 | arm32).
  -b, --bin-dir DIR     Diretorio de instalacao do binario (padrao: ~/.local/bin).
  -d, --vault-dir DIR   Diretorio que contem ddns_vault.enc (padrao: diretorio atual).
  -i, --interval MIN    Intervalo do agendamento em minutos (padrao: 6).
      --password-stdin  Le a Senha Mestra do stdin (sem eco; para automacao).
      --no-timer        Instala o binario/wrapper, mas nao cria o agendamento.
      --no-linger       Nao habilita o linger do systemd de usuario.
      --no-test-run     Nao executa uma atualizacao de teste ao final.
  -y, --yes             Nao pedir confirmacoes.
      --dry-run         Mostra o que seria feito, sem alterar o sistema.
      --uninstall       Remove agendamento, unidades e wrapper.
      --purge           Com --uninstall, remove tambem senha e binario.
  -h, --help            Exibe esta ajuda.

Variaveis de ambiente:
  DDNS_MASTER_PASSWORD  Se definida, e usada e gravada (nao pede senha).
  DDNS_REPO             Repositorio GitHub (padrao: vandinho10/ddns_manager).

O cofre NAO e criado nem removido por este script. Se ele nao existir,
o instalador oferece executa-lo o modo --add antes de prosseguir.
EOF
}

# ------------------------------------------------------------------ #
# Utilitarios                                                        #
# ------------------------------------------------------------------ #
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "comando obrigatorio nao encontrado: $1"
}

need_gh_auth() {
  command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1
}

# Le a Senha Mestra sem eco e com confirmacao.
prompt_password() {
  local p1="" p2=""
  printf 'Senha Mestra do cofre: ' >&2
  read_interactive -s p1
  printf '\n' >&2
  printf 'Confirme a Senha Mestra: ' >&2
  read_interactive -s p2
  printf '\n' >&2
  [[ -n "$p1" ]] \
    || die "sem terminal para ler a senha; informe a origem via --password-stdin ou DDNS_MASTER_PASSWORD"
  [[ "$p1" == "$p2" ]] || die "as senhas nao conferem"
  printf '%s' "$p1"
}

read_password() {
  local modo="$PASSWORD_SOURCE"
  if [[ -z "$modo" && -n "${DDNS_MASTER_PASSWORD:-}" ]]; then
    modo="env"
  fi
  case "$modo" in
    env)
      [[ -n "${DDNS_MASTER_PASSWORD:-}" ]] || die "DDNS_MASTER_PASSWORD nao definida"
      printf '%s' "$DDNS_MASTER_PASSWORD"
      ;;
    stdin)
      local pw
      IFS= read -r pw || true
      [[ -n "$pw" ]] || die "senha vazia no stdin"
      printf '%s' "$pw"
      ;;
    prompt|"")
      prompt_password
      ;;
    *)
      die "origem de senha invalida: $modo"
      ;;
  esac
}

# Escrita de arquivo ciente de --dry-run. Conteudo via stdin.
write_text() {
  local path="$1" mode="${2:-0644}"
  if (( DRY_RUN )); then
    log "dry-run: escreveria $path (modo $mode)"
    cat >/dev/null
    return 0
  fi
  mkdir -p -- "$(dirname -- "$path")"
  chmod 0700 -- "$(dirname -- "$path")"
  cat > "$path"
  chmod "$mode" -- "$path"
}

# Leitura interativa que funciona mesmo quando o script chega via pipe
# (curl | bash): usa /dev/tty quando disponivel, senao o stdin.
read_interactive() {
  local opt=""
  [[ "${1:-}" == "-s" ]] && { opt="-s"; shift; }
  if [[ -e /dev/tty ]]; then
    IFS= read -r $opt "$1" < /dev/tty
  else
    IFS= read -r $opt "$1"
  fi
}

# ------------------------------------------------------------------ #
# Deteccao de plataforma / tag                                       #
# ------------------------------------------------------------------ #
detect_arch() {
  [[ -z "$ARCH" ]] || return 0
  case "$(uname -m)" in
    x86_64|amd64)          ARCH="x86_64" ;;
    aarch64|arm64)         ARCH="aarch64" ;;
    armv7l|armv6l|armhf|arm) ARCH="arm32" ;;
    *) die "arquitetura nao suportada: $(uname -m) (use --arch)" ;;
  esac
}

detect_tag() {
  [[ -n "$TAG" ]] || return 0
  [[ "$TAG" == v* ]] || TAG="v$TAG"
}

latest_tag() {
  local tag=""
  # Prefere o endpoint "latest" (exclui pre-releases), que reflete a versao
  # estavel a ser instalada por padrao.
  if command -v curl >/dev/null 2>&1; then
    tag="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
      | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' \
      | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"//; s/"$//' | head -n1)" || true
  fi
  if [[ -z "$tag" ]] && need_gh_auth; then
    tag="$(gh release view -R "$REPO" --json tagName -q .tagName 2>/dev/null || true)"
  fi
  [[ -n "$tag" ]] || die "nao foi possivel determinar a ultima versao (informe --version)"
  printf '%s' "$tag"
}

# Ultima Release Candidate (RC). O endpoint "releases/latest" ignora
# pre-releases, entao a lista completa de releases e percorrida para
# encontrar a RC mais recente (padrao v<X.Y.Z>-rc.<N>).
latest_rc_tag() {
  local tag=""
  if command -v curl >/dev/null 2>&1; then
    tag="$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=30" 2>/dev/null \
      | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' \
      | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"//; s/"$//' \
      | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$' | head -n1)" || true
  fi
  if [[ -z "$tag" ]] && need_gh_auth; then
    tag="$(gh release list -R "$REPO" --json tagName \
      -q '.[].tagName' 2>/dev/null \
      | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$' | head -n1 || true)"
  fi
  [[ -n "$tag" ]] || die "nenhuma Release Candidate (RC) encontrada (informe --version)"
  printf '%s' "$tag"
}

download_asset() {
  local asset="$1" destdir="$2"
  mkdir -p -- "$destdir"
  if (( DRY_RUN )); then
    log "dry-run: baixaria $asset (tag $TAG)"
    return 0
  fi
  if need_gh_auth; then
    log "baixando $asset (tag $TAG) via gh..."
    gh release download "$TAG" -R "$REPO" -p "$asset" -D "$destdir" --clobber \
      || die "falha ao baixar $asset (a tag $TAG possui esse asset?)"
  else
    require_cmd curl
    local url="https://github.com/$REPO/releases/download/$TAG/$asset"
    log "baixando $url ... (silencioso)"
    curl -fsSL --retry 3 --connect-timeout 15 -o "$destdir/$asset" "$url" \
      || die "falha ao baixar $asset (verifique a tag/arquitetura)"
  fi
  [[ -s "$destdir/$asset" ]] || die "asset baixado esta vazio: $asset"
}

# ------------------------------------------------------------------ #
# Cofre                                                              #
# ------------------------------------------------------------------ #
resolve_vault_dir() {
  if [[ -n "$VAULT_DIR" ]]; then
    [[ -d "$VAULT_DIR" ]] || die "diretorio do cofre inexistente: $VAULT_DIR"
  else
    VAULT_DIR="$PWD"
  fi
  if [[ ! -f "$VAULT_DIR/$VAULT_FILE" ]]; then
    warn "cofre nao encontrado em $VAULT_DIR/$VAULT_FILE"
    if (( ASSUME_YES )) || (( DRY_RUN )); then
      die "crie o cofre antes: (cd '$VAULT_DIR' && '$BIN_DIR/$BIN_NAME' --add)"
    fi
    if [[ ! -e /dev/tty && ! -t 0 ]]; then
      die "sem terminal interativo e sem cofre em $VAULT_DIR/$VAULT_FILE. Crie-o antes: (cd '$VAULT_DIR' && '$BIN_DIR/$BIN_NAME' --add)"
    fi
    local resp=""
    printf 'Deseja criar o cofre agora executando "%s --add"? [s/N] ' "$BIN_NAME" >&2
    read_interactive resp
    if [[ "$resp" =~ ^[sSyY]$ ]]; then
      # O --add e interativo (lê a Senha Mestra no stdin); sob curl|bash o
      # stdin eh o pipe do script, entao redirecionamos para o terminal real.
      if [[ -e /dev/tty ]]; then
        ( cd "$VAULT_DIR" && "$BIN_DIR/$BIN_NAME" --add ) < /dev/tty
      else
        ( cd "$VAULT_DIR" && "$BIN_DIR/$BIN_NAME" --add )
      fi
      [[ -f "$VAULT_DIR/$VAULT_FILE" ]] || die "cofre nao foi criado"
    elif [[ -n "$resp" ]]; then
      die "cancelado pelo usuario. Crie o cofre com: (cd '$VAULT_DIR' && '$BIN_DIR/$BIN_NAME' --add)"
    else
      die "cofre nao encontrado em $VAULT_DIR/$VAULT_FILE. Crie-o antes: (cd '$VAULT_DIR' && '$BIN_DIR/$BIN_NAME' --add)"
    fi
  fi
}

validate_password() {
  local pw="$1"
  ( cd "$VAULT_DIR" && DDNS_MASTER_PASSWORD="$pw" "$BIN_DIR/$BIN_NAME" --list ) >/dev/null 2>&1
}

# ------------------------------------------------------------------ #
# systemd / cron                                                     #
# ------------------------------------------------------------------ #
systemd_user_available() {
  command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1
}

write_wrapper() {
  write_text "$WRAPPER" 0700 <<EOF
#!/usr/bin/env bash
# Gerado por install.sh - nao editar manualmente.
set -euo pipefail
DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
DDNS_MASTER_PASSWORD="\$(cat "\$DIR/password")"
export DDNS_MASTER_PASSWORD
exec "$BIN_DIR/$BIN_NAME" "\$@"
EOF
}

write_service() {
  write_text "$SYSTEMD_USER_DIR/$SERVICE_NAME.service" 0644 <<EOF
[Unit]
Description=Atualizacao DDNS do cofre ddns_manager
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$VAULT_DIR
ExecStart=$WRAPPER
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
EOF
}

write_timer() {
  write_text "$SYSTEMD_USER_DIR/$SERVICE_NAME.timer" 0644 <<EOF
[Unit]
Description=Executa o ddns_manager a cada ${INTERVAL_MIN} minutos

[Timer]
OnBootSec=2min
OnUnitActiveSec=${INTERVAL_MIN}min
AccuracySec=30s
RandomizedDelaySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

install_systemd() {
  if (( DRY_RUN )); then
    log "dry-run: daemon-reload + enable --now $SERVICE_NAME.timer"
    return 0
  fi
  systemctl --user daemon-reload
  systemctl --user enable --now "$SERVICE_NAME.timer"
  if (( ! NO_LINGER )); then
    loginctl enable-linger "$USER" >/dev/null 2>&1 \
      && ok "linger habilitado para $USER (roda sem sessao aberta)" \
      || warn "nao foi possivel habilitar linger (agendamento para ao encerrar a sessao)"
  fi
}

install_cron() {
  require_cmd crontab
  local linha="*/$INTERVAL_MIN * * * * cd '$VAULT_DIR' && '$WRAPPER' >> '$LOG_FILE' 2>&1"
  if (( DRY_RUN )); then
    log "dry-run: crontab += [$CRON_TAG] $linha"
    return 0
  fi
  {
    crontab -l 2>/dev/null | grep -vF "$CRON_TAG" | grep -vF "$WRAPPER" || true
    printf '%s\n%s\n' "$CRON_TAG" "$linha"
  } | crontab -
  mkdir -p -- "$(dirname -- "$LOG_FILE")"
  ok "agendamento via cron instalado (log: $LOG_FILE)"
}

remove_cron() {
  command -v crontab >/dev/null 2>&1 || return 0
  local atual
  atual="$(crontab -l 2>/dev/null || true)"
  if printf '%s\n' "$atual" | grep -qF "$CRON_TAG"; then
    if (( DRY_RUN )); then
      log "dry-run: removeria entrada de cron"
      return 0
    fi
    printf '%s\n' "$atual" | grep -vF "$CRON_TAG" | grep -vF "$WRAPPER" | crontab - || true
  fi
}

# ------------------------------------------------------------------ #
# Instalacao / desinstalacao                                         #
# ------------------------------------------------------------------ #
do_install() {
  detect_arch
  if [[ -n "$TAG" ]]; then
    detect_tag
  elif (( NIGHTLY )); then
    TAG="$(latest_rc_tag)"
  else
    TAG="$(latest_tag)"
  fi
  local asset="ddns_manager-linux-$ARCH"
  log "versao: $TAG | arquitetura: $ARCH | binario: $BIN_DIR/$BIN_NAME"

  require_cmd install
  mkdir -p -- "$BIN_DIR"

  WORK_DIR=""
  local base
  for base in "${TMPDIR:-}" "$HOME/.cache"; do
    [[ -n "$base" ]] || continue
    mkdir -p -- "$base" 2>/dev/null || continue
    if WORK_DIR="$(mktemp -d "$base/ddns_manager.XXXXXX" 2>/dev/null)"; then
      break
    fi
    WORK_DIR=""
  done
  [[ -n "$WORK_DIR" ]] || die "nao foi possivel criar diretorio temporario"
  download_asset "$asset" "$WORK_DIR"

  if (( ! DRY_RUN )); then
    install -m 0755 -- "$WORK_DIR/$asset" "$BIN_DIR/$BIN_NAME"
  else
    log "dry-run: instalaria $BIN_DIR/$BIN_NAME"
  fi

  local versao_instalada="?"
  if (( ! DRY_RUN )); then
    versao_instalada="$("$BIN_DIR/$BIN_NAME" --version 2>&1 | awk '{print $NF}')" \
      || die "o binario instalado nao executa corretamente"
    ok "binario instalado: $BIN_DIR/$BIN_NAME ($versao_instalada)"
  fi

  resolve_vault_dir
  log "cofre: $VAULT_DIR/$VAULT_FILE"

  local senha
  senha="$(read_password)"
  if (( ! DRY_RUN )); then
    validate_password "$senha" || die "senha incorreta para o cofre existente"
    ok "senha valida (cofre descriptografado com sucesso)"
  fi

  # Diretorio e arquivo de segredo (0600).
  if (( DRY_RUN )); then
    log "dry-run: gravaria $PASSWORD_FILE (modo 0600)"
  else
    mkdir -p -- "$CONFIG_DIR"
    chmod 0700 -- "$CONFIG_DIR"
    umask 077
    printf '%s' "$senha" > "$PASSWORD_FILE"
    chmod 0600 -- "$PASSWORD_FILE"
  fi
  unset senha

  write_wrapper
  ok "wrapper de execucao: $WRAPPER"

  if (( NO_TIMER )); then
    warn "--no-timer: agendamento nao criado"
    return 0
  fi

  if systemd_user_available; then
    write_service
    write_timer
    install_systemd
    ok "systemd user timer ativo (intervalo de ${INTERVAL_MIN} min)"
    if (( ! NO_TEST_RUN && ! DRY_RUN )); then
      log "executando uma atualizacao de teste..."
      if systemctl --user start "$SERVICE_NAME.service"; then
        ok "teste concluido (veja: journalctl --user -u $SERVICE_NAME.service)"
      else
        warn "o teste retornou falha; consulte o journal: journalctl --user -u $SERVICE_NAME.service"
      fi
    fi
  else
    warn "systemd de usuario indisponivel; usando cron como fallback"
    install_cron
  fi
}

do_uninstall() {
  if systemd_user_available; then
    if (( DRY_RUN )); then
      log "dry-run: desabilitaria/removeria unidades systemd"
    else
      systemctl --user disable --now "$SERVICE_NAME.timer" >/dev/null 2>&1 || true
      systemctl --user stop "$SERVICE_NAME.service" >/dev/null 2>&1 || true
      rm -f -- "$SYSTEMD_USER_DIR/$SERVICE_NAME.timer" "$SYSTEMD_USER_DIR/$SERVICE_NAME.service"
      systemctl --user daemon-reload >/dev/null 2>&1 || true
      ok "unidades systemd removidas"
    fi
  fi
  remove_cron

  if (( DRY_RUN )); then
    log "dry-run: removeria $WRAPPER"
    (( PURGE )) && log "dry-run: removeria $PASSWORD_FILE e $BIN_DIR/$BIN_NAME"
    return 0
  fi

  rm -f -- "$WRAPPER"
  if (( PURGE )); then
    rm -f -- "$PASSWORD_FILE" "$BIN_DIR/$BIN_NAME"
    warn "--purge: senha e binario removidos. O cofre NAO foi alterado."
  else
    log "senha e binario mantidos (use --purge para remove-los)."
  fi
  ok "desinstalacao concluida; cofre intacto em $VAULT_DIR/$VAULT_FILE"
}

# ------------------------------------------------------------------ #
# CLI                                                                #
# ------------------------------------------------------------------ #
parse_args() {
  while (( $# > 0 )); do
    case "$1" in
      -v|--version)     TAG="${2:?}"; shift 2 ;;
      --nightly)        NIGHTLY=1; shift ;;
      -a|--arch)        ARCH="${2:?}"; shift 2 ;;
      -b|--bin-dir)     BIN_DIR="${2:?}"; shift 2 ;;
      -d|--vault-dir)   VAULT_DIR="${2:?}"; shift 2 ;;
      -i|--interval)    INTERVAL_MIN="${2:?}"; shift 2 ;;
      --password-stdin) PASSWORD_SOURCE="stdin"; shift ;;
      --no-timer)       NO_TIMER=1; shift ;;
      --no-linger)      NO_LINGER=1; shift ;;
      --no-test-run)    NO_TEST_RUN=1; shift ;;
      -y|--yes)         ASSUME_YES=1; shift ;;
      --dry-run)        DRY_RUN=1; shift ;;
      --uninstall)      UNINSTALL=1; shift ;;
      --purge)          PURGE=1; shift ;;
      -h|--help)        usage; exit 0 ;;
      *) die "opcao desconhecida: $1 (use --help)" ;;
    esac
  done

  [[ "$INTERVAL_MIN" =~ ^[0-9]+$ ]] && (( INTERVAL_MIN > 0 )) \
    || die "--interval deve ser um inteiro positivo"
  (( INTERVAL_MIN < 60 )) || warn "intervalo de ${INTERVAL_MIN} min pode sobrecarregar o provedor DNS"
  [[ "$BIN_DIR" = /* ]] || BIN_DIR="$PWD/$BIN_DIR"
  [[ -z "$TAG" || "$NIGHTLY" -eq 0 ]] \
    || die "--version e --nightly sao mutuamente exclusivos"
}

main() {
  parse_args "$@"

  if (( UNINSTALL )); then
    if [[ -n "$VAULT_DIR" ]]; then
      [[ -d "$VAULT_DIR" ]] || die "diretorio do cofre inexistente: $VAULT_DIR"
    else
      VAULT_DIR="$PWD"
    fi
    do_uninstall
    return 0
  fi

  do_install

  # Aviso de PATH.
  if (( ! DRY_RUN )) && [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    warn "$BIN_DIR nao esta no PATH desta sessao"
    log  "adicione ao shell rc: export PATH=\"$BIN_DIR:\$PATH\""
  fi
}

main "$@"

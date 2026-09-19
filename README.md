# ddns_manager — DDNS Seguro via Worker Cloudflare (C++17)

**ddns_manager** é um cliente de atualização dinâmica de DNS (DDNS) em
**C++17** que descobre os IPs públicos atuais (`https://api.ipify.org` e
`https://api6.ipify.org`) e notifica um Worker do Cloudflare com o payload
`POST` JSON no formato `{"auth_key":..., "domains":{<domínio>:{ipv4, ipv6}}}`,
atualizando os registros **A** e **AAAA** de cada domínio. O cadastro de
domínios é mantido em um **cofre de credenciais totalmente criptografado**
(`ddns_vault.enc`) com **AES-256-CBC + PBKDF2-HMAC-SHA256**, protegido por uma
única **Senha Mestra**.

Foi refatorado para ser compilável no maior número possível de distribuições
Linux (Ubuntu, Debian, Fedora, Arch, Alpine, openSUSE etc.) **e no Windows**,
usando apenas APIs nativas: **OpenSSL (EVP) + libcurl** no POSIX e
**WinHTTP + CNG (bcrypt)** no Windows — com **zero dependências externas de
build** (parser/serializador JSON mínimo embutido). O formato do cofre
criptografado é idêntico entre todas as plataformas.

## Recursos

- **Gestão dinâmica de credenciais via CLI** — `--add`/`--update`, `--list`,
  `--remove`, sem recompilar ou recriar o cofre.
- **Atualização A + AAAA** — detecta IPv4 e IPv6 públicos e envia ambos no
  formato aceito pelo Worker (`domains.<nome>.ipv4/ipv6`), atualizando os
  registros correspondentes.
- **Criptografia robusta** — AES-256-CBC + PBKDF2-HMAC-SHA256 (salt 8 bytes
  aleatório, 120.000 iterações), única Senha Mestra; arquivo gravado com
  permissão `0600`.
- **Segredos protegidos** — senha digitada **sem eco** no terminal
  (`termios`); suporte a `DDNS_MASTER_PASSWORD` (variável de ambiente) para
  automação via cron/systemd.
- **Compatibilidade multi-distro** — OpenSSL 1.1.x e 3.x, libcurl presente
  nos repositórios oficiais; JSON embutido dispensa download de dependências.
- **Suporte nativo ao Windows** — transporte WinHTTP e criptografia CNG
  (bcrypt.dll): binário 100% estático, sem dependência de terceiros; o mesmo
  cofre `ddns_vault.enc` funciona nas duas plataformas.
- **Saída para automação** — código de saída `0` somente quando todos os
  domínios são atualizados com sucesso.

## Instalação automática (Linux)

O script `scripts/install.sh` baixa o binário do release adequado à
arquitetura, instala em `~/.local/bin`, lê a Senha Mestra **sem eco** e
configura o agendamento periódico via **systemd user timer** (com fallback para
**cron**). O cofre nunca é criado nem removido pelo script.

Instalação em uma única linha (baixa e executa a última versão do instalador):

```bash
curl -fsSL https://raw.githubusercontent.com/vandinho10/ddns_manager/main/scripts/install.sh | bash -s -- --vault-dir "$PWD" --interval 6
```

> Segurança: executar scripts via `curl | bash` assume confiança no repositório.
> Recomenda-se baixar (`curl -fsSL -o install.sh URL`) e revisar o conteúdo
> antes da primeira execução — o próprio instalador também aceita `--dry-run`.

```bash
# Última versão, cofre no diretório atual, execução a cada 6 min (padrão)
./scripts/install.sh

# Cofre em outro diretório e intervalo customizado
./scripts/install.sh --vault-dir ~/Documentos/docker_projects_dev --interval 6

# Automação: senha via stdin (sem eco) ou variável de ambiente
echo "$DDNS_MASTER_PASSWORD" | ./scripts/install.sh --password-stdin
DDNS_MASTER_PASSWORD=... ./scripts/install.sh

# Simular sem alterar o sistema / remover
./scripts/install.sh --dry-run
./scripts/install.sh --uninstall            # mantém senha e binário
./scripts/install.sh --uninstall --purge    # remove senha e binário
```

Opções relevantes: `--version`, `--arch`, `--bin-dir`, `--vault-dir`,
`--interval`, `--no-timer`, `--no-linger`, `--no-test-run`, `--yes`, `--purge`,
`--dry-run`, `--help`.

Arquivos gerados:

| Caminho | Permissão | Descrição |
|---|---|---|
| `~/.local/bin/ddns_manager` | `0755` | binário do release |
| `~/.config/ddns_manager/password` | `0600` | Senha Mestra (criada via entrada sem eco) |
| `~/.config/ddns_manager/ddns-manager-run.sh` | `0700` | wrapper que injeta a senha no ambiente |
| `~/.config/systemd/user/ddns-manager.{service,timer}` | `0644` | agendamento periódico |

Para operar o serviço:

```bash
systemctl --user list-timers ddns-manager.timer
systemctl --user start ddns-manager.service     # execução imediata (teste)
journalctl --user -u ddns-manager.service -f    # logs
```

Pré-requisito: um cofre já existente (`ddns_manager --add`) no diretório
apontado por `--vault-dir`. Se ausente, o instalador oferece criá-lo.

## Compilação

Pré-requisitos: `g++` (C++17), headers do **OpenSSL** e da **libcurl**.

```bash
make              # build otimizado de release (v1.2.0)
make check        # análise estática -Werror (zero warnings)
make test         # suíte table-driven (133 checks)
make sanitize     # AddressSanitizer + UndefinedBehaviorSanitizer
make install      # instala em /usr/local/bin/ddns_manager (requer sudo)
```

Compilação manual:

```bash
g++ -std=c++17 -O2 -o ddns_manager \
  main.cpp vault.cpp http.cpp json_min.cpp -lssl -lcrypto -lcurl
```

Verificação de compatibilidade multi-distro:

```bash
# Ubuntu / Debian / Linux Mint / Raspberry Pi OS
sudo apt update && sudo apt install -y build-essential libssl-dev libcurl4-openssl-dev

# Fedora / RHEL / Rocky Linux / CentOS
sudo dnf install -y gcc-c++ openssl-devel libcurl-devel

# Arch Linux / Manjaro
sudo pacman -S --needed base-devel openssl curl

# Alpine Linux (containers Docker)
apk add build-base openssl-dev curl-dev
```

Windows (binário estático via mingw-w64):

```bash
# Debian/Ubuntu (ambas as arquiteturas)
sudo apt install -y g++-mingw-w64-x86-64 g++-mingw-w64-i686 make

# x86_64
make TARGET_OS=Windows_NT CXX=x86_64-w64-mingw32-g++-posix all

# x86 (32 bits)
make TARGET_OS=Windows_NT CXX=i686-w64-mingw32-g++-posix all
```

O resultado é `ddns_manager.exe`, **100% estático** (sem DLLs de terceiros),
usando WinHTTP e CNG do próprio Windows. O binário de release também é
gerado automaticamente pela CI (GitHub Actions).

## Uso

```bash
./ddns_manager --add      # cria ou atualiza o cofre (interativo)
./ddns_manager --list     # lista API URL e domínios cadastrados
./ddns_manager --remove <dominio>   # remove um domínio do cofre
./ddns_manager            # obtém IP público e atualiza todos os domínios
./ddns_manager --help     # ajuda
./ddns_manager --version  # versão
```

Exemplo de sessão interativa `--add`:

```
$ ./ddns_manager --add
Digite a Senha Mestra do Cofre:            ██████████
URL Base do Worker: https://seu-worker.workers.dev/
Nome completo do Dominio/Subdominio (ex: alfa.domain1.com.br): alfa.example.com
Chave de Autenticacao (auth_key) para este dominio: chave-secreta

[SUCESSO] Dominio 'alfa.example.com' gravado de forma criptografada (ddns_vault.enc).
```

Para adicionar outro domínio basta rodar `--add` novamente (o cofre é aberto
com a mesma Senha Mestra e o novo domínio é inserido sem apagar os anteriores).

## Automação (cron / systemd)

```bash
# job diário: exporta a senha mestra apenas no processo do comando
DDNS_MASTER_PASSWORD='sua-senha-mestra' /usr/local/bin/ddns_manager
```

O exit code é `0` apenas quando o IP foi obtido e **todos** os domínios foram
atualizados com sucesso — ideal para detecção de falha em agendadores.

## Segurança

- O cofre `ddns_vault.enc` **não é texto puro** e é criado com permissão
  `0600` no POSIX (somente o dono); no Windows herda a ACL padrão do usuário.
- O formato criptográfico (salt 8 bytes + AES-256-CBC PKCS#7, PBKDF2-HMAC-
  SHA256 120.000 iterações) é **idêntico** no OpenSSL (POSIX) e no CNG
  (Windows): o cofre é portável entre plataformas.
- A Senha Mestra nunca é exibida; na leitura interativa o eco é desabilitado.
- `auth_key` e senha nunca são exibidos em `--list`.
- O valor de `DDNS_MASTER_PASSWORD` vive apenas por processo (não persiste).

## Documentação

- `docs/README.md` — documentação técnica (entradas/saídas, formato do cofre).
- `CHANGELOG.md` — histórico de versões (Keep a Changelog).
- `TODO.md` — pendências e próximos passos.
- `PLANNER.md` — planejamento e escopo inicial.

## Licença

MIT — ver `LICENSE` e `NOTICE`.
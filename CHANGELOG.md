# Changelog — ddns_manager

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

## [Unreleased]

### Added

- **Regras de acionamento do Worker** (item 4 da análise): o estado de
  execução é persistido em `ddns_state.json` (permissão `0600`, gitignored) e
  define quando o Worker é chamado entre execuções periódicas:
  - **Regra 4.1** — execução sem alteração de IP e sem erro: Worker **não**
    é acionado.
  - **Regra 4.2** — alteração de IP ou erro: Worker é acionado e abre-se a
    janela pós-evento.
  - **Regra 4.2.1** — as 4 execuções seguintes após uma alteração/erro são
    usadas para re-verificação, acionando o Worker.
  - **Regra 4.3** — após 5 execuções consecutivas sem alteração e sem erro,
    o Worker é acionado por periodicidade (sincronização preventiva).
- Funções de estado em `estado.cpp`: `carregar_estado`, `salvar_estado`,
  `ip_publico_mudou` e `decidir_acionar`, com recuperação de arquivo ausente
  ou corrompido e saneamento de contadores fora dos limites.
- **Seleção de tipos por domínio**: `--add`/`--update` agora pergunta (ou
  recebe via `--types A,AAAA`) quais registros atualizar por domínio — `A`
  (IPv4), `AAAA` (IPv6) ou ambos. O cofre passa a armazenar
  `{auth_key, types}` e o payload ao Worker envia somente os IPs dos tipos
  declarados.
- Suíte de testes ampliada para 196 checks (semântica do estado: comparação de
  IPs, regras 4.1/4.2/4.2.1/4.3, sequências completas, persistência JSON e
  retrocompatibilidade do cofre legado).

### Changed

- **Retrocompatibilidade do cofre**: o formato antigo (string = `auth_key`
  pura, v1.2.0) continua sendo aceito por `ler_config_dominio` e é
  automaticamente migrado para `{auth_key, types:[A,AAAA]}` quando `--add`
  ou o modo de atualização reescrevem o cofre — sem quebra de dados existentes
  e sem exigir intervenção manual.

### Added

- **Flag `--nightly` no instalador**: instala automaticamente a última versão
  Release Candidate (RC) publicada, percorrendo a lista de releases do GitHub
  (o endpoint `releases/latest` ignora pré-releases). É mutuamente exclusiva
  com `--version`.

### Security

- `auth_key` agora é lida com **digitação oculta** (eco desabilitado), de forma
  consistente com a Senha Mestra. Continua armazenada apenas no cofre
  criptografado, oculta em `--list` e trafegando somente via HTTPS no payload.

## [1.2.0] - 2026-09-19

### Added

- Script `scripts/install.sh`: instalação automatizada do binário por
  arquitetura, leitura da Senha Mestra sem eco, wrapper seguro e agendamento
  periódico via **systemd user timer** (fallback para **cron**), com suporte a
  `--uninstall`/`--purge` e `--dry-run`.

## [1.1.0] - 2026-09-19

### Added

- Detecção de IPv6 público (`https://api6.ipify.org`) e envio simultâneo de
  registros **A** (IPv4) e **AAAA** (IPv6).

### Changed

- Payload ao Worker alinhado ao novo receptor Cloudflare:
  `{"auth_key":..., "domains":{<domínio>:{ipv4?, ipv6?}}}` em substituição a
  `{domain, auth_key, new_ip}`.
- Domínios com a mesma `auth_key` são agrupados em um único lote por
  requisição (o Worker valida a mesma chave para todos os domínios do corpo).
- A resposta do Worker passa a ser interpretada por domínio via `results[]`
  (`success:false` + `error`, ou `updates[]` com `success`/`errors`), já que o
  HTTP `200` ocorre mesmo com falha individual de registros.
- Falha de comunicação/parse da resposta agora marca a execução como falha
  (exit code não-zero).
- Suíte de testes ampliada de 101 para 133 checks (payload, IPv6, arrays JSON
  e interpretação de respostas de sucesso, domínio não autorizado e erro de
  update).

## [1.0.0] - 2026-09-19

### Added

- Utilitário C++17 `ddns_manager`: atualização dinâmica de DNS via Worker do
  Cloudflare com gestão dinâmica de credenciais por linha de comando.
- **Cofre criptografado** `ddns_vault.enc`: AES-256-CBC + PBKDF2-HMAC-SHA256
  (salt 8 bytes aleatório, 120.000 iterações), única Senha Mestra, arquivo
  gravado com permissão `0600`.
- **Comandos CLI**: `--add`/`--update` (insere ou atualiza domínio),
  `--list` (lista API URL e domínios), `--remove <domínio>`, `--help`,
  `--version` e o modo padrão de atualização de IP.
- **Cobertura multi-distro**: apenas APIs nativas do OpenSSL (EVP, compatível
  com 1.1.x e 3.x) e libcurl; parser/serializador **JSON mínimo embutido**
  (sem dependência externa de `nlohmann/json.hpp`).
- **Senha mestra sem eco** no terminal (`termios`) e suporte à variável de
  ambiente `DDNS_MASTER_PASSWORD` para automação (cron/systemd).
- Validação de IPv4 do IP público obtido via `https://api.ipify.org`.
- **Assinatura multi-plataforma**: cofre criptografado AES-256-CBC + PBKDF2
  com formato de arquivo **idêntico em todas as plataformas**; POSIX usa
  OpenSSL EVP e Windows usa **CNG nativo (bcrypt.dll)** — o mesmo
  `ddns_vault.enc` é lido/gravado em ambos os ambientes.
- **Suporte nativo ao Windows**: transporte HTTP via **WinHTTP** (GET/POST
  JSON) e senha mestra sem eco via console API; binário Windows 100% estático
  (sem dependência de terceiros), compilável com mingw-w64 (`x86_64` e
  `i686`).
- **CI de release multi-plataforma** via GitHub Actions: Linux x86_64, aarch64
  e arm32 (containers `debian:bookworm-slim` com QEMU) + Windows amd64/x86
  (cross-compile mingw-w64).
- Makefile parametrizado alvo `TARGET_OS=Windows_NT` (binário Windows) com
  alvos `all`, `check` (-Werror), `test`, `sanitize`, `version`, `install` e
  `clean`.
- Suíte de testes tabelados (101 checks): parser JSON (objetos, arrays,
  escapes, unicode, erros de sintaxe), criptografia roundtrip (fronteiras de
  bloco, senha incorreta, salt aleatório, derivação determinística) e acesso
  ao cofre (roundtrip multi-domínio, senha incorreta, cofre corrompido).
- Documentação completa: `README.md`, `CHANGELOG.md`, `TODO.md`, `PLANNER.md`
  e `docs/README.md`; artefatos `LICENSE` e `NOTICE`.
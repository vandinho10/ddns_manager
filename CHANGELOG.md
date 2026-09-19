# Changelog — ddns_manager

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

## [Unreleased]

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
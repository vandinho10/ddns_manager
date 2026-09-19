# PLANNER — ddns_manager

## Objetivo

Prover um utilitário de linha de comando que atualiza dinamicamente registros
DNS através de um Worker do Cloudflare, com um cofre de credenciais
criptografado (AES-256-CBC + PBKDF2) e gestão completa por CLI.

## Justificativa

A atualização manual de DNS (DDNS) é propensa a erro e expõe credenciais.
O `ddns_manager` consolida a operação em um binário C++ leve, compilável nas
principais distros Linux com zero dependências externas de build, protegendo
as chaves com criptografia real e uma única Senha Mestra.

## Escopo

- [x] Utilitário C++17 (`main.cpp`, `vault.cpp`, `http.cpp`, `json_min.hpp`).
- [x] Cofre criptografado com AES-256-CBC + PBKDF2-HMAC-SHA256 (120.000 iterações),
      formato portável entre plataformas (OpenSSL EVP no POSIX / CNG no Windows).
- [x] Comandos `--add`/`--update`, `--list`, `--remove`, `--help`, `--version`.
- [x] Suporte nativo ao **Windows** (WinHTTP + CNG, binário estático via
      mingw-w64 x86_64 e i686), compilado via `TARGET_OS=Windows_NT`.
- [x] Suíte de testes tabelados, sanitizers e CI de release multi-plataforma
      (Linux x86_64/aarch64/arm32 + Windows amd64/x86).
- [x] Registro do repositório como submódulo no monorepo (`compiled/ddns_manager`).

## Fora de escopo

- Integração ao `docker-compose.yaml` como job agendado (fase futura).
- Notificações via Telegram (fase futura).
# TODO — ddns_manager

## A definir

- [ ] Avaliar suporte a notificação via Telegram em caso de falha de update.

## Concluído

- [x] Instalador `scripts/install.sh`: baixa binário por arquitetura, grava a
      Senha Mestra sem eco e agenda a execução periódica via systemd user
      timer (fallback cron) — v1.2.0.
- [x] Alinhamento ao receptor Cloudflare: payload
      `{"auth_key","domains":{...}}`, detecção IPv4/IPv6 e lote por `auth_key`
      (v1.1.0).
- [x] Publicação dos binários (linux-x86_64, linux-aarch64, linux-arm32,
      windows-amd64, windows-x86) em release do GitHub via CI (v1.1.0).
- [x] Implementação do cofre criptografado (AES-256-CBC + PBKDF2) e dos
      comandos `--add`, `--update`, `--list`, `--remove` (v1.0.0).
- [x] JSON mínimo embutido (zero dependência externa de build).
- [x] Senha mestra sem eco no terminal + `DDNS_MASTER_PASSWORD` para
      automação.
- [x] Suporte nativo ao Windows (WinHTTP + CNG, binário estático via
      mingw-w64 x86_64 e i686), cofre interoperável com o POSIX.
- [x] CI de release multi-plataforma e suíte de testes tabelados.
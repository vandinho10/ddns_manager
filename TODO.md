# TODO — ddns_manager

## A definir

- [ ] Avaliar suporte a notificação via Telegram em caso de falha de update.

## Concluído

- [x] Promover v1.3.0-rc.2 (regras 4.1-4.3 + `--update`, flag `--nightly`) para
      a versão oficial v1.3.0 após validação em produção.
- [x] Validar a flag `--nightly` do instalador em ambiente real (bash) após a
      publicação do RC no GitHub.
- [x] Ajustar `--update` para manter os valores atuais quando os campos forem
      deixados em branco (apenas o domínio é obrigatório), seguindo o padrão da
      URL do Worker — candidato v1.3.0-rc.2.
- [x] Regras de acionamento do Worker 4.1/4.2/4.2.1/4.3 com estado persistido
      em `ddns_state.json` (`0600`, gitignored), migração automática do cofre
      legado (string → `{auth_key, types}`) e suíte expandida para 196 checks
      — candidato v1.3.0-rc.1.
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
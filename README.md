# ddns_manager — DDNS Seguro via Worker Cloudflare (C++17)

**ddns_manager** é um cliente de atualização dinâmica de DNS (DDNS) em
**C++17** que descobre o IP público atual (`https://api.ipify.org`), notifica
um Worker do Cloudflare (`POST` JSON com `domain`, `auth_key` e `new_ip`) e
mantém o cadastro de domínios em um **cofre de credenciais totalmente
criptografado** (`ddns_vault.enc`) com **AES-256-CBC + PBKDF2-HMAC-SHA256**,
protegido por uma única **Senha Mestra**.

Foi refatorado para ser compilável no maior número possível de distribuições
Linux (Ubuntu, Debian, Fedora, Arch, Alpine, openSUSE etc.) **e no Windows**,
usando apenas APIs nativas: **OpenSSL (EVP) + libcurl** no POSIX e
**WinHTTP + CNG (bcrypt)** no Windows — com **zero dependências externas de
build** (parser/serializador JSON mínimo embutido). O formato do cofre
criptografado é idêntico entre todas as plataformas.

## Recursos

- **Gestão dinâmica de credenciais via CLI** — `--add`/`--update`, `--list`,
  `--remove`, sem recompilar ou recriar o cofre.
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

## Compilação

Pré-requisitos: `g++` (C++17), headers do **OpenSSL** e da **libcurl**.

```bash
make              # build otimizado de release (v1.0.0)
make check        # análise estática -Werror (zero warnings)
make test         # suíte table-driven (101 checks)
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
# Documentação Técnica — ddns_manager

## Visão geral

`ddns_manager` é uma CLI em C++17 que obtém o IP público via
`https://api.ipify.org` e o repassa a um Worker do Cloudflare através de
`POST application/json`, atualizando o registro DNS de cada domínio cadastrado
em um cofre criptografado.

## Arquitetura

```
┌────────────┐   ┌──────────────────────────┐   ┌─────────────────────────────┐
│  main.cpp  │──▶│        vault.cpp         │──▶│  ddns_vault.enc (0600)      │
│  (CLI)     │   │  AES-256-CBC + PBKDF2    │   │  salt(8) + ciphertext       │
└─────┬──────┘   │   POSIX: OpenSSL EVP     │   └─────────────────────────────┘
      │          │   Win:  CNG (bcrypt)     │
      │          └──────────────────────────┘
      │          ┌──────────────────────────┐   ┌─────────────────────────────┐
      └─────────▶│        http.cpp          │──▶│  Cloudflare Worker (POST)   │
                 │  POSIX: libcurl          │   │  {domain, auth_key, new_ip} │
                 │  Win:   WinHTTP nativo   │   └─────────────────────────────┘
                 └──────────────────────────┘
```

## Mapeamento de plataformas

| Camada | POSIX (Linux/macOS/BSD) | Windows |
|---|---|---|
| HTTP (GET/POST JSON) | libcurl | WinHTTP nativo |
| Criptografia (AES-256-CBC/PBKDF2) | OpenSSL EVP (1.1.x e 3.x) | CNG (bcrypt.dll) |
| Senha sem eco | `termios` | Console API (`SetConsoleMode`) |
| Permissão do cofre | `0600` | ACL padrão do usuário |
| Dependências de build | `libssl-dev`, `libcurl4-openssl-dev` | nenhuma (API do sistema) |

O binário Windows é compilado com mingw-w64 (`TARGET_OS=Windows_NT`) e é
**100% estático** (sem DLLs de terceiros).

## Entradas e saídas

| Direção | Item | Formato | Exemplo |
|---|---|---|---|
| Entrada | IP público | GET `https://api.ipify.org` | `2001:db8::1` (IPv4 alvo) |
| Entrada | Senha Mestra | env `DDNS_MASTER_PASSWORD` ou terminal sem eco | — |
| Saída | Payload ao Worker | `POST` JSON | `{"domain":"alfa.example.com","auth_key":"k","new_ip":"203.0.113.9"}` |
| Persistente | Cofre | binário, modo `0600` | `ddns_vault.enc` |

## Formato do cofre

O conteúdo (antes da cifragem) é um objeto JSON:

```json
{
  "api_url": "https://seu-worker.workers.dev/",
  "domains": {
    "alfa.example.com": "auth_key-do-alfa",
    "beta.example.com.br": "auth_key-do-beta"
  }
}
```

Formato em disco do `ddns_vault.enc`:

| Offset | Tamanho | Conteúdo |
|---|---|---|
| 0 | 8 bytes | Salt aleatório (PBKDF2) |
| 8 | N bytes | Ciphertext AES-256-CBC (padding PKCS#7) |

Derivação de chave: `PBKDF2-HMAC-SHA256(senha, salt, 120.000 iterações)`
→ 32 bytes de chave + 16 bytes de IV.

> **Portabilidade do cofre:** este formato segue estritamente os padrões
> PBKDF2 e AES-256-CBC (PKCS#7). Por isso o `ddns_vault.enc` gravado no
> Linux (OpenSSL EVP) é lido normalmente no Windows (CNG) e vice-versa —
> apenas implementações nativas de cada plataforma sobre o mesmo padrão.

## Mapeamento de comandos

| Comando | Ação | Exit code |
|---|---|---|
| (sem argumento) | Obtém IP e atualiza todos os domínios | `0` ok / `1` falha |
| `--add` / `--update` | Insere ou atualiza um domínio no cofre | `0` ok |
| `--list` | Lista API URL e domínios (auth_key oculta) | `0` ok |
| `--remove <domínio>` | Remove um domínio | `0` ok / `1` falha |
| `--help` | Exibe ajuda | `0` |
| `--version` | Exibe versão | `0` |
| argumento desconhecido | — | `1` |

## Dependências

- **Compilação (POSIX):** `g++` (C++17), headers OpenSSL (`libssl-dev`) e
  libcurl (`libcurl4-openssl-dev`). Nenhuma biblioteca de terceiros ou
  download de cabeçalhos.
- **Compilação (Windows):** mingw-w64 (`TARGET_OS=Windows_NT`) — apenas as
  APIs do Windows (WinHTTP + CNG), sem dependências externas.
- **Runtime:** OpenSSL 1.1.x/3.x e libcurl (POSIX); WinHTTP/CNG do próprio
  Windows (nenhuma DLL de terceiros).

## Teste e deploy

```bash
make check        # análise estática com -Werror
make test         # suíte table-driven (101 checks)
make sanitize     # ASan + UBSan
make install      # instala em /usr/local/bin/ddns_manager (requer sudo)

# Windows (mingw-w64): binário estático ddns_manager.exe
make TARGET_OS=Windows_NT CXX=x86_64-w64-mingw32-g++-posix all
```

Validação end-to-end (2026-09-19):

```
$ ddns_manager --add
[SUCESSO] Dominio 'alfa.unifesp.br' gravado de forma criptografada (ddns_vault.enc).

$ ddns_manager --list
API URL: http://127.0.0.1:8099/update
Dominios cadastrados:
  - alfa.unifesp.br (auth_key armazenada)

$ DDNS_MASTER_PASSWORD='...' ddns_manager
[INFO] IP Publico detectado: 203.0.113.9
[SUCESSO] Dominio 'alfa.unifesp.br' atualizado para o IP 203.0.113.9
```

## Próximos passos

- Publicar binários em release do GitHub (CI multi-arquitetura).
- Integração como job agendado no monorepo.
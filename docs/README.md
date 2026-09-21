# Documentação Técnica — ddns_manager

## Visão geral

`ddns_manager` é uma CLI em C++17 que obtém os IPs públicos IPv4/IPv6 via
`https://api.ipify.org` e `https://api6.ipify.org` e os repassa a um Worker do
Cloudflare através de `POST application/json` no formato
`{"auth_key":..., "domains":{<domínio>:{ipv4?, ipv6?}}}` — atualizando os
registros **A** e **AAAA** de cada domínio cadastrado no cofre criptografado.

## Arquitetura

```
┌────────────┐   ┌──────────────────────────┐   ┌─────────────────────────────┐
│  main.cpp  │──▶│        vault.cpp         │──▶│  ddns_vault.enc (0600)      │
│  (CLI)     │   │  AES-256-CBC + PBKDF2    │   │  salt(8) + ciphertext       │
└─────┬──────┘   │   POSIX: OpenSSL EVP     │   └─────────────────────────────┘
      │          │   Win:  CNG (bcrypt)     │
      │          └──────────────────────────┘
      │          ┌──────────────────────────┐   ┌─────────────────────────────┐
      └─────────▶│       estado.cpp         │──▶│  ddns_state.json (0600)     │
                 │  regras 4.1/4.2/4.2.1/4.3│   │  ultimos IPs + contadores   │
                 └──────────────────────────┘
                 ┌──────────────────────────┐   ┌─────────────────────────────┐
                 │         http.cpp         │──▶│  Cloudflare Worker (POST)   │
                 │  POSIX: libcurl          │   │  {"auth_key","domains":{...}│
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
| Entrada | IP público IPv4 | GET `https://api.ipify.org` | `203.0.113.9` |
| Entrada | IP público IPv6 | GET `https://api6.ipify.org` | `2001:db8::1` |
| Entrada | Senha Mestra | env `DDNS_MASTER_PASSWORD` ou terminal sem eco | — |
| Saída | Payload ao Worker | `POST` JSON | `{"auth_key":"k","domains":{"alfa.example.com":{"ipv4":"203.0.113.9","ipv6":"2001:db8::1"}}}` |
| Persistente | Cofre | binário, modo `0600` | `ddns_vault.enc` |

### Payload enviado ao Worker

Uma requisição por `auth_key` (domínios com a mesma chave são agrupados em um
lote). Campos de IP vazios/indisponíveis são omitidos:

```json
{
  "auth_key": "chave-secreta",
  "domains": {
    "alfa.example.com": { "ipv4": "203.0.113.9", "ipv6": "2001:db8::1" },
    "beta.example.com.br": { "ipv4": "203.0.113.9" }
  }
}
```

O Worker responde `200` com `{"success":true,"results":[...]}` mesmo quando há
falha em registros individuais; por isso o cliente avalia o campo `results`:

| Entrada de `results[]` | Significado |
|---|---|
| `{domain, success:false, error}` | Domínio não listado/não autorizado |
| `{domain, updates:[{type,content,success,errors?}]}` | `success:false` em qualquer update indica falha no registro (detalhe em `errors`) |

O exit code é `0` somente quando todos os domínios tiveram `updates[].success`
verdadeiro.

## Formato do cofre

O conteúdo (antes da cifragem) é um objeto JSON:

```json
{
  "api_url": "https://seu-worker.workers.dev/",
  "domains": {
    "alfa.example.com": { "auth_key": "chave-alfa", "types": ["A", "AAAA"] },
    "beta.example.com.br": { "auth_key": "chave-beta", "types": ["AAAA"] }
  }
}
```

**Retrocompatibilidade:** o formato antigo (v1.2.0), que armazenava o domínio
como string (`"alfa.example.com": "auth_key-do-alfa"`), continua sendo aceito
na leitura (`ler_config_dominio` interpreta a string como `auth_key` com tipos
padrão `A,AAAA`). Quando `--add` ou o modo de atualização reescrevem o cofre
(salvar_cofre), o domínio legado é automaticamente migrado para o objeto
`{auth_key, types:[A,AAAA]}` — sem perda de dados e sem intervenção manual.

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

## Estado de execução e acionamento do Worker

O `ddns_manager` decide **se** o Worker deve ser chamado em cada execução
periódica. As regras resolvem a tensão entre não desperdiçar chamadas na
Cloudflare e garantir resiliência a falhas e mudanças:

| Regra | Condição | Ação |
|---|---|---|
| **4.1** | Última execução sem alteração de IP e sem erro | **Não** acionar o Worker |
| **4.2** | Houve alteração de IP **ou** erro | Acionar o Worker e abrir a janela pós-evento |
| **4.2.1** | Execuções seguintes a uma alteração/erro (na janela) | Acionar o Worker (re-verificação) |
| **4.3** | 5 execuções consecutivas sem alteração e sem erro | Acionar o Worker (sync periódico) |

O estado é persistido em `ddns_state.json` (permissão `0600`, gitignored) e
contém os últimos IPs conhecidos, o número de execuções na janela pós-evento
e o contador de execuções silenciosas:

```json
{"ipv4":"203.0.113.9","ipv6":"2001:db8::1","execpos":2,"quiet":0}
```

Semântica dos campos:

| Campo | Tipo | Descrição |
|---|---|---|
| `ipv4` / `ipv6` | string | Últimos IPs públicos conhecidos (vazio = nunca obtido) |
| `execpos` | inteiro (`0..4`) | Execuções restantes da janela pós-evento (4.2.1) |
| `quiet` | inteiro (≥ 0) | Execuções consecutivas sem alteração e sem erro (4.1/4.3) |

Regras de transição implementadas em `decidir_acionar` (`estado.cpp`):

- `mudou || erro` → aciona o Worker, `execpos = 4`, `quiet = 0`;
- senão, se `execpos > 0` → aciona e decrementa `execpos`;
- senão, `quiet++`; se `quiet >= 5` → aciona e zera `quiet`;
- senão (regra 4.1) → não aciona.

Arquivo ausente ou corrompido (JSON inválido) inicia com o estado padrão
(IPs vazios, `execpos = 0`, `quiet = 0`), garantindo a sincronização inicial
na primeira execução válida. Falhas de obtenção de IP ou comunicação com o
Worker registram erro no estado (abrindo a janela pós-evento), de modo que a
próxima execução re-tente o envio.

## Mapeamento de comandos

| Comando | Ação | Exit code |
|---|---|---|
| (sem argumento) | Obtém IP e atualiza todos os domínios | `0` ok / `1` falha |
| `--add` / `--update` | Insere um domínio novo ou atualiza um existente (campos em branco mantêm os valores atuais) | `0` ok |
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
make test         # suíte table-driven (191 checks)
make sanitize     # ASan + UBSan
make install      # instala em /usr/local/bin/ddns_manager (requer sudo)

# Windows (mingw-w64): binário estático ddns_manager.exe
make TARGET_OS=Windows_NT CXX=x86_64-w64-mingw32-g++-posix all
```

Validação end-to-end (2026-09-19), com Worker local simulando o receptor:

```
$ ddns_manager --add
[SUCESSO] Dominio 'alfa.e2e.local' gravado de forma criptografada (ddns_vault.enc).

$ ddns_manager --list
API URL: http://127.0.0.1:8082
Dominios cadastrados:
  - alfa.e2e.local (auth_key armazenada)

$ DDNS_MASTER_PASSWORD='...' ddns_manager
[INFO] IPv4 publico detectado: 191.184.213.114
[INFO] IPv6 publico detectado: 2804:14d:daa5:402d:21e:6ff:fe51:2456
[SUCESSO] Dominio 'alfa.e2e.local' atualizado (A: 191.184.213.114) (AAAA: 2804:14d:daa5:402d:21e:6ff:fe51:2456)
```

Payload efetivamente recebido pelo Worker:

```json
{"auth_key": "chave-dev", "domains": {"alfa.e2e.local": {"ipv4": "191.184.213.114", "ipv6": "2804:14d:daa5:402d:21e:6ff:fe51:2456"}}}
```

## Próximos passos

- Integração como job agendado no monorepo.
- Lançamento do Release Candidate v1.3.0-rc.2 (regras 4.1-4.3 e `--update`
  com manutenção dos valores atuais) para seguida promoção a v1.3.0 estável.
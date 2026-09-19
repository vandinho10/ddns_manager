// Implementacao do cofre criptografado do ddns_manager.
// AES-256-CBC + PBKDF2-HMAC-SHA256, formato de arquivo identico em todas as
// plataformas: 8 bytes de salt + ciphertext (padding PKCS#7).
//
// POSIX: OpenSSL EVP (compativel com 1.1.x e 3.x).
// Windows: CNG nativo (bcrypt.dll), sem dependencia de terceiros.

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
// Suprime avisos de deprecacao do OpenSSL 3.x em APIs como PKCS5_PBKDF2_HMAC,
// mantendo compatibilidade com o 1.1.x.
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#endif

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

#include "ddns_manager.hpp"

namespace ddns {

namespace {

#ifdef _WIN32
// Descritor de arquivo CRT (mesma semantica do POSIX dentro de _open/_read).
using FD = int;

int abrir_leitura(const char* caminho)
{
    return ::_open(caminho, _O_RDONLY | _O_BINARY);
}

int abrir_escrita_novo(const char* caminho)
{
    // Windows nao possui mascara 0600 do POSIX; restringe ao dono via ACL
    // padrao e sistema de arquivos NTFS.
    return ::_open(caminho, _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY,
                   _S_IREAD | _S_IWRITE);
}

int ler_desc(FD fd, void* buf, size_t n)
{
    return ::_read(fd, buf, static_cast<unsigned int>(n));
}

int escrever_desc(FD fd, const void* buf, size_t n)
{
    return ::_write(fd, buf, static_cast<unsigned int>(n));
}

bool obter_tamanho(FD fd, long& tamanho)
{
    struct _stat st = {};
    if (::_fstat(fd, &st) != 0)
        return false;
    tamanho = static_cast<long>(st.st_size);
    return true;
}

void fechar_desc(FD fd) { ::_close(fd); }

bool arquivo_existe_nativo(const char* caminho)
{
    return ::_access(caminho, 0) == 0;
}

void remover_arquivo_nativo(const char* caminho) { ::_unlink(caminho); }

#else // POSIX

using FD = int;

int abrir_leitura(const char* caminho)
{
    return ::open(caminho, O_RDONLY);
}

int abrir_escrita_novo(const char* caminho)
{
    // Permissao 0600: somente o dono le/escreve o cofre.
    return ::open(caminho, O_WRONLY | O_CREAT | O_TRUNC, 0600);
}

int ler_desc(FD fd, void* buf, size_t n)
{
    return static_cast<int>(::read(fd, buf, n));
}

int escrever_desc(FD fd, const void* buf, size_t n)
{
    return static_cast<int>(::write(fd, buf, n));
}

bool obter_tamanho(FD fd, long& tamanho)
{
    struct stat st = {};
    if (::fstat(fd, &st) != 0)
        return false;
    tamanho = static_cast<long>(st.st_size);
    return true;
}

void fechar_desc(FD fd) { ::close(fd); }

bool arquivo_existe_nativo(const char* caminho)
{
    return ::access(caminho, F_OK) == 0;
}

void remover_arquivo_nativo(const char* caminho) { ::unlink(caminho); }

#endif

bool escrever_completo(FD fd, const void* buf, size_t len)
{
    const unsigned char* p = static_cast<const unsigned char*>(buf);
    size_t restante = len;
    while (restante > 0)
    {
        const int n = escrever_desc(fd, p, restante);
        if (n <= 0)
            return false;
        p += static_cast<size_t>(n);
        restante -= static_cast<size_t>(n);
    }
    return true;
}

bool ler_arquivo(const std::string& caminho, std::vector<unsigned char>& dados)
{
    const FD fd = abrir_leitura(caminho.c_str());
    if (fd < 0)
        return false;
    long tamanho = 0;
    if (!obter_tamanho(fd, tamanho) || tamanho <= 0)
    {
        fechar_desc(fd);
        return false;
    }
    dados.resize(static_cast<size_t>(tamanho));
    size_t lidos = 0;
    while (lidos < dados.size())
    {
        const int n = ler_desc(fd, dados.data() + lidos, dados.size() - lidos);
        if (n <= 0)
        {
            fechar_desc(fd);
            return false;
        }
        lidos += static_cast<size_t>(n);
    }
    fechar_desc(fd);
    return true;
}

bool gerar_salt(unsigned char salt[8])
{
#ifdef _WIN32
    return BCryptGenRandom(nullptr, salt, 8,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    return RAND_bytes(salt, 8) == 1;
#endif
}

// AES-256-CBC com padding PKCS#7. Preenche saida e total (bytes do resultado).
bool encriptar_bloco(const unsigned char* chave, const unsigned char* iv,
                     const unsigned char* entrada, int tamanho,
                     std::vector<unsigned char>& saida, int& total)
{
    total = 0;
#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        return false;
    // Valor do modo CBC: mesma cadeia no SDK do Windows e no mingw-w64.
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                      reinterpret_cast<PUCHAR>(
                          const_cast<wchar_t*>(L"ChainingModeCBC")),
                      sizeof(L"ChainingModeCBC"), 0);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS st = BCryptGenerateSymmetricKey(
        alg, &hKey, nullptr, 0, const_cast<PUCHAR>(chave), 32, 0);

    if (st == 0)
    {
        saida.resize(static_cast<size_t>(tamanho) + 16);
        ULONG cb = 0;
        st = BCryptEncrypt(hKey, const_cast<PUCHAR>(entrada),
                           static_cast<ULONG>(tamanho), nullptr,
                           const_cast<PUCHAR>(iv), 16, saida.data(),
                           static_cast<ULONG>(saida.size()), &cb,
                           BCRYPT_BLOCK_PADDING);
        if (st == 0)
            total = static_cast<int>(cb);
        BCryptDestroyKey(hKey);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return st == 0;
#else
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        return false;
    saida.resize(static_cast<size_t>(tamanho) +
                 EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, chave, iv) == 1;
    if (ok)
        ok = EVP_EncryptUpdate(ctx, saida.data(), &len, entrada, tamanho) == 1;
    if (ok)
    {
        total = len;
        ok = EVP_EncryptFinal_ex(ctx, saida.data() + total, &len) == 1;
    }
    if (ok)
        total += len;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
#endif
}

bool decriptar_bloco(const unsigned char* chave, const unsigned char* iv,
                     const unsigned char* entrada, int tamanho,
                     std::vector<unsigned char>& saida, int& total)
{
    total = 0;
#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        return false;
    // Valor do modo CBC: mesma cadeia no SDK do Windows e no mingw-w64.
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                      reinterpret_cast<PUCHAR>(
                          const_cast<wchar_t*>(L"ChainingModeCBC")),
                      sizeof(L"ChainingModeCBC"), 0);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS st = BCryptGenerateSymmetricKey(
        alg, &hKey, nullptr, 0, const_cast<PUCHAR>(chave), 32, 0);

    if (st == 0)
    {
        saida.resize(static_cast<size_t>(tamanho));
        ULONG cb = 0;
        st = BCryptDecrypt(hKey, const_cast<PUCHAR>(entrada),
                           static_cast<ULONG>(tamanho), nullptr,
                           const_cast<PUCHAR>(iv), 16, saida.data(),
                           static_cast<ULONG>(saida.size()), &cb,
                           BCRYPT_BLOCK_PADDING);
        if (st == 0)
            total = static_cast<int>(cb);
        BCryptDestroyKey(hKey);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return st == 0;
#else
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        return false;
    saida.resize(static_cast<size_t>(tamanho));
    int len = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, chave, iv) == 1;
    if (ok)
        ok = EVP_DecryptUpdate(ctx, saida.data(), &len, entrada, tamanho) == 1;
    if (ok)
    {
        total = len;
        ok = EVP_DecryptFinal_ex(ctx, saida.data() + total, &len) == 1;
    }
    if (ok)
        total += len;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
#endif
}

} // namespace

bool derivar_chave_iv(const std::string& senha, const unsigned char* salt,
                      unsigned char* chave, unsigned char* iv,
                      unsigned int iteracoes)
{
    if (senha.empty())
        return false;

    unsigned char material[48]; // 32 de chave + 16 de IV em uma unica derivacao
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hPrf = nullptr;
    if (BCryptOpenAlgorithmProvider(&hPrf, BCRYPT_PBKDF2_ALGORITHM, nullptr, 0) != 0)
        return false;
    // Propriedade "Hash Algorithm" (literal: ausente no mingw-w64).
    BCryptSetProperty(hPrf, L"Hash Algorithm",
                      reinterpret_cast<PUCHAR>(
                          const_cast<wchar_t*>(BCRYPT_SHA256_ALGORITHM)),
                      sizeof(BCRYPT_SHA256_ALGORITHM), 0);

    const NTSTATUS st = BCryptDeriveKeyPBKDF2(
        hPrf,
        reinterpret_cast<PUCHAR>(const_cast<char*>(senha.data())),
        static_cast<ULONG>(senha.size()),
        const_cast<PUCHAR>(salt), 8,
        static_cast<ULONGLONG>(iteracoes),
        material, sizeof(material), 0);
    BCryptCloseAlgorithmProvider(hPrf, 0);
    if (st != 0)
        return false;
#else
    if (1 != PKCS5_PBKDF2_HMAC(senha.c_str(), static_cast<int>(senha.size()),
                               salt, 8, static_cast<int>(iteracoes),
                               EVP_sha256(), sizeof(material), material))
        return false;
#endif

    std::memcpy(chave, material, 32);
    std::memcpy(iv, material + 32, 16);
    return true;
}

bool criptografar_arquivo(const std::string& texto, const std::string& senha,
                          const std::string& caminho)
{
    if (senha.empty())
        return false;

    unsigned char salt[8];
    if (!gerar_salt(salt))
        return false;

    unsigned char chave[32];
    unsigned char iv[16];
    if (!derivar_chave_iv(senha, salt, chave, iv, PBKDF2_ITERACOES))
        return false;

    std::vector<unsigned char> cifra;
    int total = 0;
    if (!encriptar_bloco(chave, iv,
                         reinterpret_cast<const unsigned char*>(texto.data()),
                         static_cast<int>(texto.size()), cifra, total))
        return false;

    const FD fd = abrir_escrita_novo(caminho.c_str());
    if (fd < 0)
        return false;
    const bool escrito = escrever_completo(fd, salt, sizeof salt) &&
                         escrever_completo(fd, cifra.data(),
                                           static_cast<size_t>(total));
    fechar_desc(fd);
    if (!escrito)
        remover_arquivo_nativo(caminho.c_str());
    return escrito;
}

bool descriptografar_arquivo(const std::string& senha,
                             const std::string& caminho, std::string& saida)
{
    std::vector<unsigned char> buffer;
    if (!ler_arquivo(caminho, buffer))
        return false;
    if (buffer.size() <= 8)
        return false; // deve haver salt (8) + pelo menos um bloco

    unsigned char chave[32];
    unsigned char iv[16];
    if (!derivar_chave_iv(senha, buffer.data(), chave, iv, PBKDF2_ITERACOES))
        return false;

    std::vector<unsigned char> plano;
    int total = 0;
    if (!decriptar_bloco(chave, iv, buffer.data() + 8,
                         static_cast<int>(buffer.size() - 8), plano, total))
        return false;

    saida.assign(reinterpret_cast<const char*>(plano.data()),
                 static_cast<size_t>(total));
    return true;
}

bool carregar_cofre(const std::string& senha, const std::string& caminho,
                    json::Value& cofre)
{
    std::string decifrado;
    if (!descriptografar_arquivo(senha, caminho, decifrado))
        return false;
    try
    {
        cofre = json::Value::parse(decifrado);
    }
    catch (const json::Erro&)
    {
        return false;
    }
    return cofre.is_objeto();
}

bool salvar_cofre(const json::Value& cofre, const std::string& senha,
                  const std::string& caminho)
{
    return criptografar_arquivo(cofre.dump(), senha, caminho);
}

bool arquivo_existe(const std::string& caminho)
{
    return arquivo_existe_nativo(caminho.c_str());
}

std::string obter_senha_mestra()
{
    // Preferencia para automacao (cron/systemd): variavel de ambiente.
    const char* env = std::getenv("DDNS_MASTER_PASSWORD");
    if (env != nullptr && *env != '\0')
        return env;

#ifdef _WIN32
    // Desabilita o eco de digitacao no console do Windows.
    HANDLE hIn = ::GetStdHandle(STD_INPUT_HANDLE);
    DWORD modo_antigo = 0;
    const bool console_ok =
        hIn != INVALID_HANDLE_VALUE && ::GetConsoleMode(hIn, &modo_antigo);
    if (console_ok)
        ::SetConsoleMode(hIn, modo_antigo & ~ENABLE_ECHO_INPUT);
#else
    const bool console_ok = ::isatty(STDIN_FILENO) != 0;
    termios antigo = {};
    if (console_ok)
    {
        if (::tcgetattr(STDIN_FILENO, &antigo) != 0)
            return "";
        termios novo = antigo;
        novo.c_lflag &= static_cast<tcflag_t>(~ECHO);
        ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &novo);
    }
#endif

    std::string senha;
    std::getline(std::cin, senha);

#ifdef _WIN32
    if (console_ok)
    {
        ::SetConsoleMode(hIn, modo_antigo);
        std::cout << "\n";
    }
#else
    if (console_ok)
    {
        ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &antigo);
        std::cout << "\n";
    }
#endif
    return senha;
}

std::string trim(const std::string& texto)
{
    size_t ini = texto.find_first_not_of(" \t\r\n");
    if (ini == std::string::npos)
        return "";
    size_t fim = texto.find_last_not_of(" \t\r\n");
    return texto.substr(ini, fim - ini + 1);
}

} // namespace ddns
#include "selfupdate.hpp"

#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace selfupdate
{

namespace
{

const char *API_HOST = "https://api.github.com";

std::string aparar(const std::string &s)
{
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a])))
        ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1])))
        --b;
    return s.substr(a, b - a);
}

std::string so_hex_minusculo(const std::string &s)
{
    std::string hex;
    for (char c : s)
        if (std::isxdigit(static_cast<unsigned char>(c)))
            hex += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return hex;
}

std::string repo_slug(const Contexto &ctx)
{
    if (!ctx.env_repo.empty())
        if (const char *e = std::getenv(ctx.env_repo.c_str()))
            if (*e)
                return e;
    return ctx.repo_padrao;
}

// ---------- SHA-256 (FIPS 180-4) ----------

constexpr std::array<uint32_t, 64> K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void sha256_bloco(std::array<uint32_t, 8> &h, const unsigned char *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t(p[i * 4]) << 24) | (uint32_t(p[i * 4 + 1]) << 16) |
               (uint32_t(p[i * 4 + 2]) << 8) | uint32_t(p[i * 4 + 3]);
    for (int i = 16; i < 64; ++i)
    {
        const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i)
    {
        const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = hh + S1 + ch + K[static_cast<size_t>(i)] + w[i];
        const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = S0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

// ---------- instalação ----------

fs::path caminho_executavel_atual(const char *argv0)
{
#ifdef _WIN32
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH)
        return fs::path(buf);
#else
    std::error_code ec;
    fs::path self = fs::read_symlink("/proc/self/exe", ec);
    if (!ec && !self.empty())
        return self;
#endif
    if (argv0 && *argv0)
    {
        std::error_code ec;
        fs::path p(argv0);
        return p.is_absolute() ? p : fs::absolute(p, ec);
    }
    return {};
}

void tornar_executavel(const fs::path &p)
{
#ifndef _WIN32
    std::error_code ec;
    fs::permissions(p,
                    fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec |
                        fs::perms::others_read | fs::perms::others_exec,
                    fs::perm_options::replace, ec);
#else
    (void)p;
#endif
}

// Aspas para o shell da plataforma: no sh, aspas simples com ' interno escapado;
// no cmd.exe, aspas duplas (caminho com " é recusado).
bool aspas_shell(const std::string &s, std::string &out)
{
#ifdef _WIN32
    if (s.find('"') != std::string::npos)
        return false;
    out = "\"" + s + "\"";
#else
    out = "'";
    for (char c : s)
        out += (c == '\'') ? std::string("'\\''") : std::string(1, c);
    out += "'";
#endif
    return true;
}

// Roda `<binario> --version`; o novo binário só fica se responder com sucesso.
bool binario_responde(const fs::path &bin)
{
    std::string q;
    if (!aspas_shell(bin.string(), q))
        return false;
#ifdef _WIN32
    const std::string cmd = "\"" + q + " --version >nul 2>nul\"";
#else
    const std::string cmd = q + " --version >/dev/null 2>&1";
#endif
    return std::system(cmd.c_str()) == 0;
}

// Troca o binário mantendo o anterior em `<destino>.old` (rollback manual).
// Se o novo não responder a --version, o anterior volta automaticamente.
bool substituir_binario(const std::string &app, const fs::path &destino,
                        const std::string &conteudo)
{
    std::error_code ec;
    const fs::path backup = destino.string() + ".old";
    const fs::path staged = destino.string() + ".new";

    {
        std::ofstream out(staged, std::ios::binary | std::ios::trunc);
        if (!out.write(conteudo.data(), static_cast<std::streamsize>(conteudo.size())))
        {
            std::cerr << app << ": falha ao gravar " << staged.string() << "\n";
            return false;
        }
    }
    tornar_executavel(staged);

    fs::remove(backup, ec);
    ec.clear();
    fs::rename(destino, backup, ec);
    if (ec)
    {
        std::cerr << app << ": nao foi possivel mover o binario atual: " << ec.message()
                  << "\n  Arquivo novo em: " << staged.string() << "\n";
        return false;
    }
    fs::rename(staged, destino, ec);
    if (ec || !binario_responde(destino))
    {
        std::cerr << app << ": novo binario falhou; restaurando o anterior\n";
        std::error_code ec2;
        fs::remove(destino, ec2);
        fs::rename(backup, destino, ec2);
        return false;
    }
    return true;
}

bool confirmar(const std::string &pergunta)
{
    std::cout << pergunta << " [s/N] " << std::flush;
    std::string resp;
    if (!std::getline(std::cin, resp))
        return false;
    resp = aparar(resp);
    const char c = resp.empty() ? 'n'
                                : static_cast<char>(std::tolower(static_cast<unsigned char>(resp[0])));
    return c == 's' || c == 'y';
}

void usage(const Contexto &ctx)
{
    std::cerr << "Uso: " << ctx.app << " update [check] [--yes] [--quiet]\n"
              << "  check    Apenas consulta a versao remota (nao instala)\n"
              << "  --yes    Instala sem perguntar\n"
              << "  --quiet  Sem perguntas e so imprime quando atualiza ou falha (timer)\n"
              << "\n"
              << "Saida de 'check': 0 = atualizado, 2 = ha versao nova, 1 = erro\n"
              << "Fonte: https://github.com/" << repo_slug(ctx) << "/releases/latest\n"
              << "Override: " << ctx.env_repo << "=owner/repo\n";
}

const std::pair<std::string, std::string> *
achar_asset(const std::vector<std::pair<std::string, std::string>> &assets, const std::string &nome)
{
    for (const auto &a : assets)
        if (a.first == nome)
            return &a;
    return nullptr;
}

} // namespace

// ---------- funções puras ----------

SemVer parse_semver(std::string s)
{
    SemVer v;
    s = aparar(s);
    if (!s.empty() && (s[0] == 'v' || s[0] == 'V'))
        s = s.substr(1);
    const size_t corte = s.find_first_of("-+");
    if (corte != std::string::npos)
        s = s.substr(0, corte);

    int parts[3] = {0, 0, 0};
    int idx = 0;
    std::string cur;
    for (size_t i = 0; i <= s.size(); ++i)
    {
        const char c = i < s.size() ? s[i] : '.';
        if (c == '.')
        {
            if (idx >= 3 || cur.empty() || cur.size() > 6)
                return v;
            parts[idx++] = std::stoi(cur);
            cur.clear();
        }
        else if (std::isdigit(static_cast<unsigned char>(c)))
            cur += c;
        else
            return v;
    }
    if (idx != 3)
        return v;
    v.major = parts[0];
    v.minor = parts[1];
    v.patch = parts[2];
    v.ok = true;
    return v;
}

int cmp_semver(const SemVer &a, const SemVer &b)
{
    if (a.major != b.major)
        return a.major < b.major ? -1 : 1;
    if (a.minor != b.minor)
        return a.minor < b.minor ? -1 : 1;
    if (a.patch != b.patch)
        return a.patch < b.patch ? -1 : 1;
    return 0;
}

std::string nome_artefato(const std::string &app)
{
#ifdef _WIN32
#if defined(_M_X64) || defined(__x86_64__) || defined(__amd64__)
    return app + "-windows-amd64.exe";
#else
    return app + "-windows-x86.exe";
#endif
#else
#if defined(__x86_64__) || defined(__amd64__)
    return app + "-linux-x86_64";
#elif defined(__aarch64__) || defined(__arm64__)
    return app + "-linux-aarch64";
#elif defined(__arm__)
    return app + "-linux-arm32";
#else
    return {};
#endif
#endif
}

std::string json_string_field(const std::string &json, const std::string &key)
{
    const std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos)
        return {};
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos)
        return {};
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos)
        return {};
    size_t end = pos + 1;
    while (end < json.size() && json[end] != '"')
        end += (json[end] == '\\') ? 2 : 1;
    if (end >= json.size())
        return {};
    return json.substr(pos + 1, end - pos - 1);
}

// O nome vem do basename de "browser_download_url" (não depende da distância
// até "name", que varia com o objeto "uploader").
std::vector<std::pair<std::string, std::string>> json_assets(const std::string &json)
{
    std::vector<std::pair<std::string, std::string>> out;
    const std::string key = "\"browser_download_url\"";
    size_t pos = 0;
    while (true)
    {
        const size_t k = json.find(key, pos);
        if (k == std::string::npos)
            break;
        const size_t colon = json.find(':', k + key.size());
        const size_t u1 = colon == std::string::npos ? colon : json.find('"', colon + 1);
        const size_t u2 = u1 == std::string::npos ? u1 : json.find('"', u1 + 1);
        if (u2 == std::string::npos)
            break;
        const std::string url = json.substr(u1 + 1, u2 - u1 - 1);
        const size_t barra = url.find_last_of('/');
        const std::string nome = barra == std::string::npos ? url : url.substr(barra + 1);
        if (!nome.empty())
            out.emplace_back(nome, url);
        pos = u2 + 1;
    }
    return out;
}

// SHA256SUMS: linhas "hash  nome" ou "hash *nome"
std::string hash_em_sumas(const std::string &sumas, const std::string &nome)
{
    std::istringstream iss(sumas);
    std::string line;
    while (std::getline(iss, line))
    {
        line = aparar(line);
        if (line.empty() || line[0] == '#')
            continue;
        const size_t sp = line.find_first_of(" \t");
        if (sp == std::string::npos)
            continue;
        std::string rest = aparar(line.substr(sp));
        if (!rest.empty() && rest[0] == '*')
            rest = rest.substr(1);
        const size_t slash = rest.find_last_of("/\\");
        if (slash != std::string::npos)
            rest = rest.substr(slash + 1);
        if (rest == nome)
        {
            const std::string hex = so_hex_minusculo(line.substr(0, sp));
            return hex.size() == 64 ? hex : std::string();
        }
    }
    return {};
}

std::string sha256_hex(const std::string &dados)
{
    std::array<uint32_t, 8> h = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    const auto *p = reinterpret_cast<const unsigned char *>(dados.data());
    const size_t n = dados.size();
    size_t i = 0;
    for (; i + 64 <= n; i += 64)
        sha256_bloco(h, p + i);

    unsigned char fim[128] = {0};
    const size_t resto = n - i;
    for (size_t j = 0; j < resto; ++j)
        fim[j] = p[i + j];
    fim[resto] = 0x80;
    const size_t total = resto < 56 ? 64 : 128;
    const uint64_t bits = static_cast<uint64_t>(n) * 8;
    for (int j = 0; j < 8; ++j)
        fim[total - 1 - static_cast<size_t>(j)] = static_cast<unsigned char>(bits >> (8 * j));
    sha256_bloco(h, fim);
    if (total == 128)
        sha256_bloco(h, fim + 64);

    static const char *dig = "0123456789abcdef";
    std::string out;
    for (uint32_t v : h)
        for (int s = 28; s >= 0; s -= 4)
            out += dig[(v >> s) & 0xf];
    return out;
}

// ---------- comando ----------

int comando_update(const Contexto &ctx, int argc, char *argv[], int primeiro)
{
    bool so_check = false;
    bool yes = false;
    bool quiet = false;
    for (int i = primeiro; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "check")
            so_check = true;
        else if (arg == "--yes" || arg == "-y")
            yes = true;
        else if (arg == "--quiet" || arg == "-q")
            quiet = yes = true;
        else if (arg == "-h" || arg == "--help")
        {
            usage(ctx);
            return EXIT_SUCCESS;
        }
        else
        {
            std::cerr << ctx.app << ": argumento desconhecido em update -> " << arg << "\n";
            usage(ctx);
            return EXIT_FAILURE;
        }
    }
    auto info = [&](const std::string &msg) {
        if (!quiet)
            std::cout << msg << "\n";
    };

    const SemVer local = parse_semver(ctx.versao);
    if (!local.ok)
    {
        std::cerr << ctx.app << ": versao local invalida -> " << ctx.versao << "\n";
        return EXIT_FAILURE;
    }
    const std::string repo = repo_slug(ctx);
    info("Local:  v" + ctx.versao + "\nRepo:   " + repo);

    // releases/latest já exclui pre-releases e rascunhos.
    std::string erro;
    const std::string body =
        ctx.http_get(std::string(API_HOST) + "/repos/" + repo + "/releases/latest", erro);
    if (body.empty())
    {
        std::cerr << ctx.app << ": falha ao consultar a release: " << erro << "\n";
        return EXIT_FAILURE;
    }
    const std::string tag = json_string_field(body, "tag_name");
    const SemVer remoto = parse_semver(tag);
    if (!remoto.ok)
    {
        std::cerr << ctx.app << ": tag invalida na release -> '" << tag << "'\n";
        return EXIT_FAILURE;
    }
    info("Remoto: " + tag);

    if (cmp_semver(local, remoto) >= 0)
    {
        info("Ja esta na versao mais recente.");
        return EXIT_SUCCESS;
    }
    info("Atualizacao disponivel: v" + ctx.versao + " -> " + tag);
    if (so_check)
        return EXIT_UPDATE_DISPONIVEL;

    const std::string artefato = nome_artefato(ctx.app);
    const auto assets = json_assets(body);
    const auto *asset = artefato.empty() ? nullptr : achar_asset(assets, artefato);
    const auto *sums = achar_asset(assets, "SHA256SUMS");
    if (asset == nullptr || sums == nullptr)
    {
        std::cerr << ctx.app << ": release " << tag << " sem '"
                  << (asset == nullptr ? artefato : std::string("SHA256SUMS"))
                  << "'; atualizacao abortada\n";
        return EXIT_FAILURE;
    }

    if (!yes && !confirmar("Baixar e instalar agora?"))
    {
        std::cout << "Cancelado.\n";
        return EXIT_SUCCESS;
    }

    const fs::path self = caminho_executavel_atual(argv[0]);
    if (self.empty())
    {
        std::cerr << ctx.app << ": nao foi possivel determinar o caminho do executavel\n";
        return EXIT_FAILURE;
    }

    // A verificação do SHA256 é obrigatória: sem hash conferido, nada é instalado.
    const std::string sumas = ctx.http_get(sums->second, erro);
    const std::string esperado = hash_em_sumas(sumas, artefato);
    if (esperado.empty())
    {
        std::cerr << ctx.app << ": hash de '" << artefato << "' ausente em SHA256SUMS\n";
        return EXIT_FAILURE;
    }
    const std::string binario = ctx.http_get(asset->second, erro);
    if (binario.empty())
    {
        std::cerr << ctx.app << ": falha no download: " << erro << "\n";
        return EXIT_FAILURE;
    }
    const std::string obtido = sha256_hex(binario);
    if (obtido != esperado)
    {
        std::cerr << ctx.app << ": SHA256 nao confere\n  esperado: " << esperado
                  << "\n  obtido:   " << obtido << "\n";
        return EXIT_FAILURE;
    }

    if (!substituir_binario(ctx.app, self, binario))
        return EXIT_FAILURE;

    // Mesmo no --quiet, a troca de versão aparece no log do timer.
    std::cout << ctx.app << ": atualizado de v" << ctx.versao << " para " << tag
              << " (anterior em " << self.string() << ".old)\n";
    return EXIT_SUCCESS;
}

} // namespace selfupdate

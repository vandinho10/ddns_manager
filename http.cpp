// Transporte HTTP do ddns_manager.
// Windows: WinHTTP nativo (binario estatico, sem dependencia de terceiros).
// POSIX (Linux/macOS/BSD): libcurl (presente nas principais distros).

#include "ddns_manager.hpp"

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#include <vector>
#else
#include <curl/curl.h>

#include <cctype>
#include <cstring>
#endif

namespace ddns {

#ifdef _WIN32

namespace {

// Converte UTF-8 multibyte para cadeia wide (requerida pelo WinHTTP).
std::wstring utf8_para_wide(const std::string& s)
{
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(static_cast<size_t>(n > 0 ? n : 1), L'\0');
    if (n > 0)
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    const size_t fim = w.find(L'\0');
    if (fim != std::wstring::npos)
        w.resize(fim);
    return w;
}

struct UrlInfo
{
    std::wstring host;
    std::wstring path;
    INTERNET_PORT porta = 80;
    bool https = false;
};

// Decompõe a URL em host, porta, caminho e esquema (http/https).
bool crkar_url(const std::string& url, UrlInfo& info)
{
    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t whost[256] = L"";
    wchar_t wpath[2048] = L"";
    uc.lpszHostName = whost;
    uc.dwHostNameLength = 255;
    uc.lpszUrlPath = wpath;
    uc.dwUrlPathLength = 2047;

    const std::wstring wurl = utf8_para_wide(url);
    if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.size()), 0, &uc))
        return false;

    info.host = whost;
    info.path = wpath[0] != L'\0' ? wpath : L"/";
    info.porta = uc.nPort;
    info.https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    return true;
}

// Executa uma requisicao WinHTTP completa. Retorna true quando o servidor
// respondeu com 2xx. Preenche codigo_http e resposta em qualquer cenário.
bool requisicao_winhttp(const std::string& url, bool post,
                        const std::string& corpo, long timeout_s,
                        long& codigo_http, std::string& resposta)
{
    codigo_http = 0;
    resposta.clear();

    UrlInfo info;
    if (url.empty() || !crkar_url(url, info))
    {
        resposta = "URL invalida: " + url;
        return false;
    }

    std::wstring ua(L"ddns_manager/");
    for (const char* v = DDNS_VERSION; *v != '\0'; ++v)
        ua += static_cast<wchar_t>(*v);

    HINTERNET sess = WinHttpOpen(ua.c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (sess == nullptr)
    {
        resposta = "WinHTTP: falha ao abrir a sessao (" +
                   std::to_string(GetLastError()) + ")";
        return false;
    }

    const DWORD tempo_ms = static_cast<DWORD>(timeout_s * 1000);
    WinHttpSetTimeouts(sess, 0, tempo_ms, tempo_ms, tempo_ms);

    HINTERNET conn = WinHttpConnect(sess, info.host.c_str(), info.porta, 0);
    if (conn == nullptr)
    {
        resposta = "WinHTTP: falha na conexao (" +
                   std::to_string(GetLastError()) + ")";
        WinHttpCloseHandle(sess);
        return false;
    }

    const DWORD flags = info.https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(conn, post ? L"POST" : L"GET",
                                       info.path.c_str(), nullptr,
                                       WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (req == nullptr)
    {
        resposta = "WinHTTP: falha ao criar a requisicao (" +
                   std::to_string(GetLastError()) + ")";
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);
        return false;
    }

    // Segue redirecionamentos como a libcurl fazia (FOLLOWLOCATION).
    DWORD politica_redirect = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(req, WINHTTP_OPTION_REDIRECT_POLICY,
                     &politica_redirect, sizeof(politica_redirect));

    BOOL envio = FALSE;
    if (post)
    {
        static const wchar_t C_TIPO[] = L"Content-Type: application/json\r\n";
        envio = WinHttpSendRequest(
            req, C_TIPO, -1L,
            const_cast<char*>(corpo.data()), static_cast<DWORD>(corpo.size()),
            static_cast<DWORD>(corpo.size()), 0);
    }
    else
    {
        envio = WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    }

    if (!envio || !WinHttpReceiveResponse(req, nullptr))
    {
        resposta = "WinHTTP: falha na requisicao (" +
                   std::to_string(GetLastError()) + ")";
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);
        return false;
    }

    DWORD status = 0;
    DWORD tamanho = sizeof(status);
    WinHttpQueryHeaders(req,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        &status, &tamanho, WINHTTP_NO_HEADER_INDEX);

    codigo_http = static_cast<long>(status);

    std::string body;
    bool falha_leitura = false;
    for (;;)
    {
        DWORD disponivel = 0;
        if (!WinHttpQueryDataAvailable(req, &disponivel))
        {
            resposta = "WinHTTP: falha ao consultar dados (" +
                       std::to_string(GetLastError()) + ")";
            falha_leitura = true;
            break;
        }
        if (disponivel == 0)
            break;
        std::vector<char> buffer(disponivel);
        DWORD lido = 0;
        if (!WinHttpReadData(req, buffer.data(), disponivel, &lido))
        {
            resposta = "WinHTTP: falha ao ler resposta (" +
                       std::to_string(GetLastError()) + ")";
            falha_leitura = true;
            break;
        }
        if (lido == 0)
            break;
        body.append(buffer.data(), lido);
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(sess);

    if (falha_leitura)
        return false;

    resposta = body;
    return status >= 200 && status < 300;
}

} // namespace

std::string http_get(const std::string& url, long timeout_s)
{
    long codigo = 0;
    std::string resposta;
    if (!requisicao_winhttp(url, false, "", timeout_s, codigo, resposta))
        return {};
    return resposta;
}

bool http_post_json(const std::string& url, const std::string& corpo,
                    long timeout_s, long& codigo_http, std::string& resposta)
{
    return requisicao_winhttp(url, true, corpo, timeout_s, codigo_http, resposta);
}

#else // POSIX: libcurl

namespace {

// Garante inicialização única e segura da libcurl.
bool curl_inicializada()
{
    static const bool ok = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
    return ok;
}

size_t callback_escrita(void* conteudo, size_t tamanho, size_t nmemb, void* userd)
{
    const size_t total = tamanho * nmemb;
    if (userd == nullptr || total == 0)
        return 0;
    static_cast<std::string*>(userd)->append(
        static_cast<const char*>(conteudo), total);
    return total;
}

} // namespace

std::string http_get(const std::string& url, long timeout_s)
{
    if (url.empty() || !curl_inicializada())
        return "";
    CURL* curl = curl_easy_init();
    if (curl == nullptr)
        return "";

    std::string buffer;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback_escrita);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_s);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ddns_manager/" DDNS_VERSION);

    const CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK)
        return "";
    return buffer;
}

bool http_post_json(const std::string& url, const std::string& corpo,
                    long timeout_s, long& codigo_http, std::string& resposta)
{
    codigo_http = 0;
    if (url.empty() || !curl_inicializada())
    {
        resposta = "url vazia ou libcurl indisponivel";
        return false;
    }
    CURL* curl = curl_easy_init();
    if (curl == nullptr)
    {
        resposta = "falha ao inicializar handle curl";
        return false;
    }

    curl_slist* cabecalhos = nullptr;
    cabecalhos = curl_slist_append(cabecalhos, "Content-Type: application/json");

    std::string buffer;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, cabecalhos);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, corpo.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                     static_cast<long>(corpo.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback_escrita);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_s);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ddns_manager/" DDNS_VERSION);

    const CURLcode res = curl_easy_perform(curl);
    long http = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
    curl_easy_cleanup(curl);
    curl_slist_free_all(cabecalhos);

    resposta = buffer;
    codigo_http = http;
    return res == CURLE_OK && http >= 200 && http < 300;
}

#endif // _WIN32

std::string parear_ip(const std::string& corpo)
{
    std::string texto = corpo;
    // Remove espacos em branco e quebras de linha das extremidades.
    size_t ini = texto.find_first_not_of(" \t\r\n");
    if (ini == std::string::npos)
        return "";
    size_t fim = texto.find_last_not_of(" \t\r\n");
    return texto.substr(ini, fim - ini + 1);
}

bool eh_ipv4(const std::string& texto)
{
    if (texto.empty() || texto.size() > 15)
        return false;
    int partes = 0;
    size_t i = 0;
    while (i < texto.size())
    {
        if (partes >= 4)
            return false;
        size_t j = i;
        while (j < texto.size() && std::isdigit(static_cast<unsigned char>(texto[j])))
            ++j;
        if (j == i || j - i > 3)
            return false;
        const int valor = std::stoi(texto.substr(i, j - i));
        if (valor > 255)
            return false;
        ++partes;
        i = j;
        if (i < texto.size())
        {
            if (texto[i] != '.')
                return false;
            ++i;
        }
    }
    return partes == 4;
}

bool obter_ip_publico(std::string& ip)
{
    const std::string corpo = http_get("https://api.ipify.org", TIMEOUT_HTTP);
    if (corpo.empty())
        return false;
    ip = parear_ip(corpo);
    return eh_ipv4(ip);
}

bool notificar_worker(const std::string& api_url, const std::string& dominio,
                      const std::string& auth_key, const std::string& novo_ip,
                      std::string& erro)
{
    // Payload esperado pelo Worker: {"domain":..., "auth_key":..., "new_ip":...}
    json::Value payload = json::Value::objeto();
    payload.set("domain", json::Value::de_string(dominio));
    payload.set("auth_key", json::Value::de_string(auth_key));
    payload.set("new_ip", json::Value::de_string(novo_ip));

    long http = 0;
    std::string resposta;
    if (!http_post_json(api_url, payload.dump(), TIMEOUT_HTTP, http, resposta))
    {
        std::string detalhe = ::ddns::trim(resposta);
        erro = "HTTP " + std::to_string(http);
        if (!detalhe.empty())
            erro += " - " + detalhe;
        return false;
    }
    return true;
}

} // namespace ddns
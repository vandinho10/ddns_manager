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

bool eh_ipv6(const std::string& texto)
{
    if (texto.empty())
        return false;
    bool tem_dois_pontos = false;
    bool ultimo_era_ponto = false;
    int pontos_seguidos = 0;
    for (char c : texto)
    {
        if (c == ':')
        {
            tem_dois_pontos = true;
            if (ultimo_era_ponto)
                ++pontos_seguidos;
            else
                pontos_seguidos = 1;
            ultimo_era_ponto = true;
            continue;
        }
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                         (c >= 'A' && c <= 'F');
        if (!hex)
            return false;
        ultimo_era_ponto = false;
    }
    // Permite "::" (compressao) mas nao ":::" nem ":" repetido incorretamente.
    return tem_dois_pontos && pontos_seguidos <= 2;
}

bool obter_ip_publico(std::string& ip)
{
    const std::string corpo = http_get("https://api.ipify.org", TIMEOUT_HTTP);
    if (corpo.empty())
        return false;
    ip = parear_ip(corpo);
    return eh_ipv4(ip);
}

bool obter_ipv6_publico(std::string& ip)
{
    const std::string corpo = http_get("https://api6.ipify.org", TIMEOUT_HTTP);
    if (corpo.empty())
        return false;
    ip = parear_ip(corpo);
    return eh_ipv6(ip);
}

namespace {

// Converte para minusculas sem depender de <cctype> (portavel p/ mingw).
std::string para_minusculas(const std::string& s)
{
    std::string out = s;
    for (char& c : out)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c + ('a' - 'A'));
    return out;
}

// Extrai a mensagem de erro de uma entrada de "updates" do Worker.
std::string mensagem_erro_update(const json::Value& upd)
{
    if (upd.tem("error"))
        return upd.as_string("error", "atualizacao falhou");
    if (upd.tem("errors") && upd.get("errors").is_array() && upd.get("errors").size() > 0)
    {
        std::string out;
        const json::Value& erros = upd.get("errors");
        const size_t limite = erros.size() < 3 ? erros.size() : 3;
        for (size_t i = 0; i < limite; ++i)
        {
            const json::Value& e = erros.item(i);
            std::string msg;
            if (e.is_objeto() && e.tem("message"))
                msg = e.as_string("message", "");
            else if (e.is_string() || e.is_outro())
                msg = e.raw();
            if (!msg.empty())
            {
                if (!out.empty())
                    out += "; ";
                out += msg;
            }
        }
        if (!out.empty())
            return out;
    }
    return "atualizacao falhou";
}

} // namespace

std::string montar_payload_worker(const std::string& auth_key,
                                  const std::vector<DadosDominio>& dominios)
{
    json::Value dominio_payload = json::Value::objeto();
    for (const auto& d : dominios)
    {
        json::Value ips = json::Value::objeto();
        if (!d.ipv4.empty())
            ips.set("ipv4", json::Value::de_string(d.ipv4));
        if (!d.ipv6.empty())
            ips.set("ipv6", json::Value::de_string(d.ipv6));
        dominio_payload.set(d.dominio, ips);
    }
    json::Value payload = json::Value::objeto();
    payload.set("auth_key", json::Value::de_string(auth_key));
    payload.set("domains", dominio_payload);
    return payload.dump();
}

bool interpretar_resposta_worker(const std::string& resposta,
                                 const std::vector<DadosDominio>& dominios,
                                 std::vector<ResultadoDominio>& resultados)
{
    resultados.clear();

    json::Value corpo;
    try
    {
        corpo = json::Value::parse(resposta);
    }
    catch (const json::Erro&)
    {
        return false;
    }

    if (!corpo.is_objeto() || !corpo.tem("results") || !corpo.get("results").is_array())
        return false;

    // O Worker responde 2xx mesmo quando ha falhas por dominio; o estado real
    // esta em "results[]": each entry {domain} com "success":false+"error" ou
    // "updates":[{type,content,success,errors?},...].
    const json::Value& results = corpo.get("results");
    for (const auto& d : dominios)
    {
        ResultadoDominio rd;
        rd.dominio = d.dominio;
        rd.sucesso = false;

        const std::string alvo = para_minusculas(::ddns::trim(d.dominio));
        for (size_t i = 0; i < results.size(); ++i)
        {
            const json::Value& r = results.item(i);
            if (!r.is_objeto())
                continue;
            const std::string nome = para_minusculas(::ddns::trim(r.as_string("domain", "")));
            if (nome != alvo)
                continue;

            if (r.tem("updates") && r.get("updates").is_array())
            {
                const json::Value& updates = r.get("updates");
                if (updates.size() == 0)
                {
                    rd.erro = "nenhum registro configurado para o dominio";
                }
                else
                {
                    for (size_t j = 0; j < updates.size(); ++j)
                    {
                        const json::Value& u = updates.item(j);
                        const bool sucesso = u.is_objeto() && u.tem("success") &&
                                             u.get("success").raw() == "true";
                        if (sucesso)
                            continue;
                        rd.erro = mensagem_erro_update(u);
                        break;
                    }
                    rd.sucesso = rd.erro.empty();
                }
            }
            else if (r.tem("success") && r.get("success").raw() == "true")
            {
                rd.sucesso = true;
            }
            else
            {
                rd.erro = r.as_string("error", "dominio nao autorizado ou nao listado");
            }
            break;
        }

        if (rd.erro.empty() && !rd.sucesso)
            rd.erro = "sem resposta do Worker para o dominio";
        resultados.push_back(rd);
    }

    return true;
}

bool notificar_worker(const std::string& api_url, const std::string& auth_key,
                      const std::vector<DadosDominio>& dominios,
                      std::vector<ResultadoDominio>& resultados,
                      std::string& erro)
{
    resultados.clear();
    erro.clear();

    const std::string corpo = montar_payload_worker(auth_key, dominios);

    long http = 0;
    std::string resposta;
    if (!http_post_json(api_url, corpo, TIMEOUT_HTTP, http, resposta))
    {
        std::string detalhe = ::ddns::trim(resposta);
        erro = "HTTP " + std::to_string(http);
        if (!detalhe.empty())
            erro += " - " + detalhe;
        return false;
    }

    if (!interpretar_resposta_worker(resposta, dominios, resultados))
    {
        erro = "resposta do Worker em formato invalido: " + ::ddns::trim(resposta);
        return false;
    }
    return true;
}

} // namespace ddns
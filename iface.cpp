// Selecao de interface de rede do ddns_manager.
// POSIX: lista via getifaddrs (nomes do kernel, ex.: "eth0", "wlan0").
// Windows: lista via GetAdaptersAddresses (nomes amigaveis do adaptador).
// A interface escolhida e persistida no cofre e usada como origem das
// requisicoes (CURLOPT_INTERFACE / WINHTTP_OPTION_LOCAL_ADDRESS).

#include "ddns_manager.hpp"

#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <cstring>
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
#endif

namespace ddns {

bool nome_iface_valido(const std::string& nome)
{
    if (nome.empty() || nome.size() > 64)
        return false;
    for (char c : nome)
    {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'
                        || c == ':';
        if (!ok)
            return false;
    }
    return true;
}

bool listar_interfaces_ativas(std::vector<std::string>& nomes)
{
    nomes.clear();

#ifdef _WIN32
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                        GAA_FLAG_SKIP_DNS_SERVER;
    ULONG tamanho = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &tamanho) !=
        ERROR_BUFFER_OVERFLOW || tamanho == 0)
    {
        return false;
    }

    std::vector<unsigned char> buffer(tamanho);
    PIP_ADAPTER_ADDRESSES aa = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, aa, &tamanho) != ERROR_SUCCESS)
        return false;

    for (PIP_ADAPTER_ADDRESSES p = aa; p != nullptr; p = p->Next)
    {
        if (p->OperStatus != IfOperStatusUp)
            continue;
        if (p->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        bool tem_endereco = false;
        for (PIP_ADAPTER_UNICAST_ADDRESS u = p->FirstUnicastAddress;
             u != nullptr; u = u->Next)
        {
            const auto fam = u->Address.lpSockaddr ? u->Address.lpSockaddr->sa_family : AF_UNSPEC;
            if (fam == AF_INET || fam == AF_INET6)
            {
                tem_endereco = true;
                break;
            }
        }
        if (!tem_endereco)
            continue;

        // AdapterName e PCHAR em todas as toolchains (mingw e MSVC), ao
        // contrario de FriendlyName (WCHAR no MSVC, CHAR no mingw).
        if (p->AdapterName != nullptr && p->AdapterName[0] != '\0')
            nomes.push_back(p->AdapterName);
    }
#else
    struct ifaddrs* lista = nullptr;
    if (getifaddrs(&lista) != 0)
        return false;

    for (struct ifaddrs* it = lista; it != nullptr; it = it->ifa_next)
    {
        if (it->ifa_addr == nullptr || it->ifa_name == nullptr)
            continue;
        const int fam = it->ifa_addr->sa_family;
        if (fam != AF_INET && fam != AF_INET6)
            continue;
        const unsigned int flags = it->ifa_flags;
        const bool up = (flags & IFF_UP) != 0;
        const bool loopback = (flags & IFF_LOOPBACK) != 0;
        if (!up || loopback)
            continue;
        nomes.push_back(it->ifa_name);
    }
    freeifaddrs(lista);

    std::sort(nomes.begin(), nomes.end());
    nomes.erase(std::unique(nomes.begin(), nomes.end()), nomes.end());
#endif

    return !nomes.empty();
}

bool obter_endereco_local(const std::string& iface, std::string& ipv4,
                          std::string& ipv6)
{
    ipv4.clear();
    ipv6.clear();
    if (iface.empty())
        return false;

#ifdef _WIN32
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                        GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_PREFIX;
    ULONG tamanho = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &tamanho) !=
        ERROR_BUFFER_OVERFLOW || tamanho == 0)
    {
        return false;
    }

    std::vector<unsigned char> buffer(tamanho);
    PIP_ADAPTER_ADDRESSES aa = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, aa, &tamanho) != ERROR_SUCCESS)
        return false;

    for (PIP_ADAPTER_ADDRESSES p = aa; p != nullptr; p = p->Next)
    {
        const std::string nome = (p->AdapterName != nullptr) ? std::string(p->AdapterName) : "";
        if (iface != nome)
            continue;

        for (PIP_ADAPTER_UNICAST_ADDRESS u = p->FirstUnicastAddress;
             u != nullptr; u = u->Next)
        {
            const auto fam = u->Address.lpSockaddr ? u->Address.lpSockaddr->sa_family : AF_UNSPEC;
            char buf[INET6_ADDRSTRLEN] = "";
            if (fam == AF_INET && ipv4.empty())
            {
                const auto* sa = reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr);
                if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf)) != nullptr)
                    ipv4 = buf;
            }
            else if (fam == AF_INET6 && ipv6.empty())
            {
                const auto* sa = reinterpret_cast<const sockaddr_in6*>(u->Address.lpSockaddr);
                if (inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof(buf)) != nullptr)
                    ipv6 = buf;
            }
        }
        return true;
    }
    return false;
#else
    struct ifaddrs* lista = nullptr;
    if (getifaddrs(&lista) != 0)
        return false;

    bool encontrada = false;
    for (struct ifaddrs* it = lista; it != nullptr; it = it->ifa_next)
    {
        if (it->ifa_addr == nullptr || it->ifa_name == nullptr)
            continue;
        if (iface != it->ifa_name)
            continue;
        encontrada = true;

        const int fam = it->ifa_addr->sa_family;
        char buf[INET6_ADDRSTRLEN] = "";
        if (fam == AF_INET && ipv4.empty())
        {
            const auto* sa = reinterpret_cast<const sockaddr_in*>(it->ifa_addr);
            if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf)) != nullptr)
                ipv4 = buf;
        }
        else if (fam == AF_INET6 && ipv6.empty())
        {
            const auto* sa = reinterpret_cast<const sockaddr_in6*>(it->ifa_addr);
            if (inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof(buf)) != nullptr)
                ipv6 = buf;
        }
    }
    freeifaddrs(lista);
    return encontrada && (!ipv4.empty() || !ipv6.empty());
#endif
}

} // namespace ddns
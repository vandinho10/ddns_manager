// Implementacao do estado de execucao persistido e das regras de acionamento
// do Worker (4.1, 4.2, 4.2.1 e 4.3).
//
// O estado registra, entre execucoes do daemon, os ultimos IPs publicos
// conhecidos e os contadores que controlam quando o Worker deve ser acionado:
// o arquivo ddns_state.json e reescrito a cada execucao com os IPs atuais e
// a janela pos-evento restante.

#include "ddns_manager.hpp"

#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace ddns {

namespace {

// --- I/O de arquivo identico ao cofre (vault.cpp), porem em texto puro -----

int abrir_leitura(const char* caminho)
{
#ifdef _WIN32
    return ::_open(caminho, _O_RDONLY | _O_BINARY);
#else
    return ::open(caminho, O_RDONLY);
#endif
}

int abrir_escrita(const char* caminho)
{
#ifdef _WIN32
    return ::_open(caminho, _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY,
                   _S_IREAD | _S_IWRITE);
#else
    // Permissao 0600: somente o dono le/escreve o estado de execucao.
    return ::open(caminho, O_WRONLY | O_CREAT | O_TRUNC, 0600);
#endif
}

int ler_desc(int fd, void* buf, size_t n)
{
#ifdef _WIN32
    return ::_read(fd, buf, static_cast<unsigned int>(n));
#else
    return static_cast<int>(::read(fd, buf, n));
#endif
}

int escrever_desc(int fd, const void* buf, size_t n)
{
#ifdef _WIN32
    return ::_write(fd, buf, static_cast<unsigned int>(n));
#else
    return static_cast<int>(::write(fd, buf, n));
#endif
}

void fechar_desc(int fd)
{
#ifdef _WIN32
    ::_close(fd);
#else
    ::close(fd);
#endif
}

bool ler_arquivo(const std::string& caminho, std::string& saida)
{
    const int fd = abrir_leitura(caminho.c_str());
    if (fd < 0)
        return false;
    std::string buffer;
    char tmp[1024];
    bool ok = false;
    for (;;)
    {
        const int n = ler_desc(fd, tmp, sizeof tmp);
        if (n < 0)
            break;
        if (n == 0)
        {
            ok = true;
            break;
        }
        buffer.append(tmp, static_cast<size_t>(n));
    }
    fechar_desc(fd);
    if (ok)
        saida.swap(buffer);
    return ok;
}

bool escrever_arquivo(const std::string& caminho, const std::string& conteudo)
{
    const int fd = abrir_escrita(caminho.c_str());
    if (fd < 0)
        return false;
    const char* p = conteudo.data();
    size_t restante = conteudo.size();
    bool ok = true;
    while (restante > 0)
    {
        const int n = escrever_desc(fd, p, restante);
        if (n <= 0)
        {
            ok = false;
            break;
        }
        p += static_cast<size_t>(n);
        restante -= static_cast<size_t>(n);
    }
    fechar_desc(fd);
    if (!ok)
    {
#ifdef _WIN32
        ::_unlink(caminho.c_str());
#else
        ::unlink(caminho.c_str());
#endif
    }
    return ok;
}

int ler_int(const json::Value& v, const std::string& chave, int padrao)
{
    if (!v.tem(chave))
        return padrao;
    const std::string texto = v.as_string(chave, "");
    if (texto.empty())
        return padrao;
    try
    {
        return std::stoi(texto);
    }
    catch (const std::exception&)
    {
        return padrao;
    }
}

} // namespace

void carregar_estado(const std::string& caminho, EstadoExecucao& estado)
{
    estado = EstadoExecucao();
    std::string texto;
    if (!ler_arquivo(caminho, texto))
        return; // primeira execucao: estado padrao

    try
    {
        const json::Value v = json::Value::parse(texto);
        if (!v.is_objeto())
            return;
        estado.ipv4 = v.as_string("ipv4", "");
        estado.ipv6 = v.as_string("ipv6", "");
        estado.execpos = ler_int(v, "execpos", 0);
        estado.quiet = ler_int(v, "quiet", 0);
        if (estado.execpos < 0)
            estado.execpos = 0;
        if (estado.quiet < 0)
            estado.quiet = 0;
        if (estado.execpos > JANELA_POS_EVENTO)
            estado.execpos = JANELA_POS_EVENTO;
    }
    catch (const json::Erro&)
    {
        estado = EstadoExecucao(); // arquivo corrompido: reinicia o estado
    }
}

bool salvar_estado(const std::string& caminho, const EstadoExecucao& estado)
{
    json::Value v = json::Value::objeto();
    v.set("ipv4", json::Value::de_string(estado.ipv4));
    v.set("ipv6", json::Value::de_string(estado.ipv6));
    v.set("execpos", json::Value::de_literal(std::to_string(estado.execpos)));
    v.set("quiet", json::Value::de_literal(std::to_string(estado.quiet)));
    return escrever_arquivo(caminho, v.dump());
}

bool ip_publico_mudou(const EstadoExecucao& estado, const std::string& ipv4,
                      const std::string& ipv6, bool tem_ipv4, bool tem_ipv6)
{
    // Primeira execucao sem historico: os IPs vazios do estado tornam qualquer
    // obtencao atual uma mudanca, acionando a sincronizacao inicial.
    if (tem_ipv4 && ipv4 != estado.ipv4)
        return true;
    if (tem_ipv6 && ipv6 != estado.ipv6)
        return true;
    return false;
}

bool decidir_acionar(const EstadoExecucao& estado_ant, bool mudou, bool erro,
                     EstadoExecucao& estado_novo)
{
    estado_novo = estado_ant;
    if (mudou || erro)
    {
        // Regra 4.2: alteracao de IP ou erro na ultima execucao -> acionar e
        // abre a janela pós-evento para as proximas JANELA_POS_EVENTO trocas.
        estado_novo.execpos = JANELA_POS_EVENTO;
        estado_novo.quiet = 0;
        return true;
    }
    if (estado_novo.execpos > 0)
    {
        // Regra 4.2.1: dentro da janela pos-evento -> acionar (re-verificacao).
        --estado_novo.execpos;
        return true;
    }
    // Regra 4.3: sem alteracao/erro nas ultimas execucoes -> sync periodico.
    estado_novo.quiet += 1;
    if (estado_novo.quiet >= QUIET_TRIGGER_THRESHOLD)
    {
        estado_novo.quiet = 0;
        return true;
    }
    // Regra 4.1: sem alteracao e sem erro (e fora de janela e periodicidade).
    return false;
}

} // namespace ddns
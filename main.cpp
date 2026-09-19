// Ponto de entrada e comandos de linha de comando do ddns_manager.
#include "ddns_manager.hpp"

#include <cstdlib>
#include <iostream>
#include <map>
#include <vector>

namespace ddns {

void imprimir_ajuda(const char* prog)
{
    std::cout << "=== DDNS Manager Seguro (C++) ===\n";
    std::cout << "Uso: " << prog << " [comando]\n\n";
    std::cout << "Comandos:\n";
    std::cout << "  " << prog << "                Executa a varredura e atualiza o IP atual no Cloudflare.\n";
    std::cout << "  " << prog << " --add          Adiciona ou atualiza dominios de acesso no cofre criptografado.\n";
    std::cout << "  " << prog << " --list         Lista os dominios salvos no cofre.\n";
    std::cout << "  " << prog << " --remove <dom> Remove um dominio do cofre.\n";
    std::cout << "  " << prog << " --help         Exibe esta ajuda.\n";
    std::cout << "  " << prog << " --version      Exibe a versao.\n";
}

void imprimir_versao(const char* prog)
{
    std::cout << prog << " v" << DDNS_VERSION << "\n";
}

namespace {

bool prompt_dados(json::Value& cofre, std::string& api_url, std::string& dominio,
                  std::string& auth_key)
{
    std::cout << "URL Base do Worker";
    if (cofre.tem("api_url"))
        std::cout << " (atual: " << cofre.as_string("api_url", "") << " - Enter mantem)";
    std::cout << ": ";
    std::getline(std::cin, api_url);
    api_url = trim(api_url);
    if (api_url.empty() && cofre.tem("api_url"))
        api_url = cofre.as_string("api_url", "");
    if (api_url.empty())
    {
        std::cerr << "[ERRO] URL do Worker nao informada.\n";
        return false;
    }

    std::cout << "Nome completo do Dominio/Subdominio (ex: alfa.domain1.com.br): ";
    std::getline(std::cin, dominio);
    dominio = trim(dominio);
    if (dominio.empty())
    {
        std::cerr << "[ERRO] Dominio nao informado.\n";
        return false;
    }

    std::cout << "Chave de Autenticacao (auth_key) para este dominio: ";
    std::getline(std::cin, auth_key);
    auth_key = trim(auth_key);
    if (auth_key.empty())
    {
        std::cerr << "[ERRO] auth_key nao informada.\n";
        return false;
    }
    return true;
}

} // namespace

int cmd_adicionar(const std::string& caminho)
{
    std::cout << "Digite a Senha Mestra do Cofre: ";
    const std::string senha = obter_senha_mestra();
    if (senha.empty())
    {
        std::cerr << "[ERRO] Senha mestra vazia. Abortando.\n";
        return EXIT_FAILURE;
    }

    json::Value cofre = json::Value::objeto();
    const bool cofre_existente = arquivo_existe(caminho);
    if (cofre_existente)
    {
        if (!carregar_cofre(senha, caminho, cofre))
        {
            std::cerr << "[ERRO] Senha incorreta ou cofre corrompido (" << caminho
                      << ").\n";
            return EXIT_FAILURE;
        }
        std::cout << "[INFO] Cofre existente aberto com sucesso.\n";
    }
    else
    {
        std::cout << "[INFO] Cofre novo: será criado em " << caminho << ".\n";
    }

    std::string api_url;
    std::string dominio;
    std::string auth_key;
    if (!prompt_dados(cofre, api_url, dominio, auth_key))
        return EXIT_FAILURE;

    cofre.set("api_url", json::Value::de_string(api_url));

    json::Value dominios = json::Value::objeto();
    if (cofre.tem("domains") && cofre.get("domains").is_objeto())
        dominios = cofre.get("domains");
    dominios.set(dominio, json::Value::de_string(auth_key));
    cofre.set("domains", dominios);

    if (salvar_cofre(cofre, senha, caminho))
    {
        std::cout << "\n[SUCESSO] Dominio '" << dominio
                  << "' gravado de forma criptografada (" << caminho << ").\n";
        return EXIT_SUCCESS;
    }
    std::cerr << "\n[ERRO] Falha ao gravar o cofre criptografado.\n";
    return EXIT_FAILURE;
}

int cmd_listar(const std::string& caminho)
{
    std::cout << "Digite a Senha Mestra do Cofre: ";
    const std::string senha = obter_senha_mestra();

    json::Value cofre;
    if (!carregar_cofre(senha, caminho, cofre))
    {
        std::cerr << "[ERRO] Senha incorreta ou cofre vazio/inexistente.\n";
        return EXIT_FAILURE;
    }

    std::cout << "\n--- Configuracoes Armazenadas ---\n";
    std::cout << "API URL: " << cofre.as_string("api_url", "N/A") << "\n";
    std::cout << "Dominios cadastrados:\n";
    if (cofre.tem("domains") && cofre.get("domains").is_objeto())
    {
        const json::Value& dominios = cofre.get("domains");
        for (json::Value::iterator it = dominios.begin(); it != dominios.end(); ++it)
        {
            // Exibe o dominio; a auth_key permanece oculta.
            std::cout << "  - " << it->first << " (auth_key armazenada)\n";
        }
        if (dominios.size() == 0)
            std::cout << "  (nenhum)\n";
    }
    else
    {
        std::cout << "  (nenhum)\n";
    }
    return EXIT_SUCCESS;
}

int cmd_remover(const std::string& dominio, const std::string& caminho)
{
    std::cout << "Digite a Senha Mestra do Cofre: ";
    const std::string senha = obter_senha_mestra();

    json::Value cofre;
    if (!carregar_cofre(senha, caminho, cofre))
    {
        std::cerr << "[ERRO] Senha incorreta ou cofre vazio/inexistente.\n";
        return EXIT_FAILURE;
    }

    if (!cofre.tem("domains") || !cofre.get("domains").tem(dominio))
    {
        std::cerr << "[AVISO] Dominio '" << dominio << "' nao encontrado no cofre.\n";
        return EXIT_SUCCESS;
    }

    json::Value dominios = cofre.get("domains");
    dominios.remover(dominio);
    cofre.set("domains", dominios);

    if (salvar_cofre(cofre, senha, caminho))
    {
        std::cout << "[SUCESSO] Dominio '" << dominio << "' removido do cofre.\n";
        return EXIT_SUCCESS;
    }
    std::cerr << "[ERRO] Falha ao gravar o cofre apos a remocao.\n";
    return EXIT_FAILURE;
}

int cmd_atualizar(const std::string& caminho)
{
    std::cout << "Digite a Senha Mestra para descriptografar o cofre: ";
    const std::string senha = obter_senha_mestra();

    json::Value cofre;
    if (!carregar_cofre(senha, caminho, cofre))
    {
        std::cerr << "[ERRO] Senha incorreta ou arquivo de cofre nao encontrado ("
                  << caminho << ")!\n";
        std::cerr << "Dica: execute '" << caminho << " --add' para criar o cofre.\n";
        return EXIT_FAILURE;
    }

    const std::string api_url = cofre.as_string("api_url", "");
    if (api_url.empty())
    {
        std::cerr << "[ERRO] api_url nao configurada no cofre. Use --add.\n";
        return EXIT_FAILURE;
    }
    if (!cofre.tem("domains") || cofre.get("domains").size() == 0)
    {
        std::cerr << "[ERRO] Nenhum dominio cadastrado no cofre. Use --add.\n";
        return EXIT_FAILURE;
    }

    std::cout << "[INFO] Obtendo IPs publicos (IPv4 e IPv6)...\n";
    std::string ipv4;
    std::string ipv6;
    const bool tem_ipv4 = obter_ip_publico(ipv4);
    const bool tem_ipv6 = obter_ipv6_publico(ipv6);
    if (!tem_ipv4 && !tem_ipv6)
    {
        std::cerr << "[ERRO] Nao foi possivel obter IP publico (IPv4/IPv6).\n";
        return EXIT_FAILURE;
    }
    if (tem_ipv4)
        std::cout << "[INFO] IPv4 publico detectado: " << ipv4 << "\n";
    if (tem_ipv6)
        std::cout << "[INFO] IPv6 publico detectado: " << ipv6 << "\n";

    // Agrupa os dominios por auth_key: o Worker valida a mesma auth_key para
    // todo o lote, entao dominios com chaves distintas exigem requisicoes
    // separadas (mapa auth_key -> dominios).
    std::map<std::string, std::vector<DadosDominio>> lotes;
    const json::Value& dominios = cofre.get("domains");
    for (json::Value::iterator it = dominios.begin(); it != dominios.end(); ++it)
    {
        const json::Value& valor = it->second;
        if (!valor.is_string())
        {
            std::cerr << "[ERRO] Dominio '" << it->first
                      << "' sem auth_key valida no cofre. Ignorado.\n";
            continue;
        }
        DadosDominio d;
        d.dominio = it->first;
        d.ipv4 = tem_ipv4 ? ipv4 : "";
        d.ipv6 = tem_ipv6 ? ipv6 : "";
        lotes[valor.como_string()].push_back(d);
    }
    if (lotes.empty())
    {
        std::cerr << "[ERRO] Nenhum dominio valido cadastrado no cofre. Use --add.\n";
        return EXIT_FAILURE;
    }

    bool falhas = false;
    for (auto& par : lotes)
    {
        std::string erro;
        std::vector<ResultadoDominio> resultados;
        if (!notificar_worker(api_url, par.first, par.second, resultados, erro))
        {
            std::cerr << "[ERRO] Falha de comunicacao com o Worker (lote de "
                      << par.second.size() << " dominio(s)): " << erro << "\n";
            falhas = true;
            continue;
        }
        for (const auto& r : resultados)
        {
            if (r.sucesso)
            {
                std::cout << "[SUCESSO] Dominio '" << r.dominio << "' atualizado";
                if (tem_ipv4)
                    std::cout << " (A: " << ipv4 << ")";
                if (tem_ipv6)
                    std::cout << " (AAAA: " << ipv6 << ")";
                std::cout << "\n";
            }
            else
            {
                std::cerr << "[ERRO] Dominio '" << r.dominio << "': " << r.erro << "\n";
                falhas = true;
            }
        }
    }
    return falhas ? EXIT_FAILURE : EXIT_SUCCESS;
}

} // namespace ddns

int main(int argc, char* argv[])
{
    using namespace ddns;

    if (argc > 1)
    {
        const std::string arg1 = argv[1];
        if (arg1 == "--help" || arg1 == "-h")
        {
            imprimir_ajuda(argv[0]);
            return EXIT_SUCCESS;
        }
        if (arg1 == "--version" || arg1 == "-v")
        {
            imprimir_versao(argv[0]);
            return EXIT_SUCCESS;
        }
        if (arg1 == "--add" || arg1 == "--update")
            return cmd_adicionar(ARQUIVO_VAULT);
        if (arg1 == "--list")
            return cmd_listar(ARQUIVO_VAULT);
        if (arg1 == "--remove")
        {
            if (argc < 3)
            {
                std::cerr << "[ERRO] Uso: " << argv[0] << " --remove <dominio>\n";
                return EXIT_FAILURE;
            }
            return cmd_remover(argv[2], ARQUIVO_VAULT);
        }
        std::cerr << "[ERRO] Argumento desconhecido: " << arg1 << "\n";
        imprimir_ajuda(argv[0]);
        return EXIT_FAILURE;
    }

    return cmd_atualizar(ARQUIVO_VAULT);
}
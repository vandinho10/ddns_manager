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
    std::cout << "  " << prog << " --add [--types A,AAAA] [--iface auto|eth0]  Adiciona um dominio novo no cofre criptografado.\n";
    std::cout << "  " << prog << " --update [--types A,AAAA] [--iface auto|eth0] Atualiza um dominio; campos em branco mantem os valores atuais.\n";
    std::cout << "  " << prog << "                          --types: registros a atualizar (A, AAAA ou A,AAAA; padrao pergunta).\n";
    std::cout << "  " << prog << "                          --iface: placa de rede usada para obter os IPs (auto = rota padrao).\n";
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

// Retorna true se o dominio ja esta cadastrado no cofre (em qualquer formato,
// objeto atual ou string legada).
bool cofre_existente_dominio(const json::Value& cofre, const std::string& dominio)
{
    return cofre.tem("domains") && cofre.get("domains").is_objeto()
        && cofre.get("domains").tem(dominio);
}

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

    if (cofre_existente_dominio(cofre, dominio))
    {
        // Update de dominio existente: campos em branco mantem os valores
        // atuais (mesmo comportamento da URL do Worker).
        std::cout << "Chave de Autenticacao (auth_key) para este dominio"
                     " (Enter para manter a atual): ";
    }
    else
    {
        std::cout << "Chave de Autenticacao (auth_key) para este dominio (digitacao oculta): ";
    }
    auth_key = trim(ler_linha_sem_eco());
    return true;
}

// Pergunta os tipos de registro ("A", "AAAA" ou ambos). Em update de dominio
// existente, entrada vazia mantem os tipos atuais; em dominio novo, vazia
// equivale ao padrao A,AAAA. Sinaliza em "vazio" quando o usuario nao digitou.
bool prompt_tipos(std::vector<std::string>& types, bool& vazio)
{
    vazio = false;
    std::cout << "Tipos de registro a atualizar (A, AAAA ou A,AAAA; "
                 "Enter = manter atual): ";
    std::string entrada;
    std::getline(std::cin, entrada);
    entrada = trim(entrada);
    if (entrada.empty())
    {
        vazio = true;
        return true;
    }
    return parsear_tipos(entrada, types);
}

// Pergunta qual placa de rede usar para obter os IPs. Com uma unica placa
// elegivel a escolha e automatica; com nenhuma, "auto" (rota padrao); com
// multiplas, apresenta a lista e solicita uma escolha valida.
std::string prompt_iface(const std::string& atual)
{
    std::vector<std::string> interfaces;
    if (!listar_interfaces_ativas(interfaces) || interfaces.empty())
        return "auto";
    if (interfaces.size() == 1)
    {
        std::cout << "[INFO] Placa de rede ativa detectada: " << interfaces[0]
                  << " (usada para obter os IPs).\n";
        return interfaces[0];
    }

    // Multiplas placas: apresenta as opcoes e solicita a escolha.
    std::cout << "Placa(s) de rede ativa(s):\n";
    for (size_t i = 0; i < interfaces.size(); ++i)
        std::cout << "  " << (i + 1) << ") " << interfaces[i] << "\n";
    std::cout << "  A) auto (rota padrao do sistema)\n";

    std::string legenda = "Placa para obter os IPs";
    if (!atual.empty() && atual != "auto")
        legenda += " (atual: " + atual + ")";
    legenda += " [numero, nome, ou auto; Enter mantem]: ";
    std::cout << legenda;

    std::string escolha;
    std::getline(std::cin, escolha);
    escolha = trim(escolha);
    if (escolha.empty())
        return atual.empty() ? "auto" : atual;

    for (size_t i = 0; i < interfaces.size(); ++i)
    {
        if (escolha == std::to_string(i + 1))
            return interfaces[i];
    }
    if (escolha == "auto" || escolha == "A" || escolha == "a" || escolha == "0")
        return "auto";
    if (nome_iface_valido(escolha))
        return escolha;
    std::cout << "[AVISO] Nome de placa desconhecido ('" << escolha
              << "'); usando auto.\n";
    return "auto";
}

} // namespace

int cmd_adicionar(const std::string& caminho, const std::string& tipos_flag,
                  const std::string& iface_flag)
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

    // Update de dominio existente: campos em branco mantem os valores atuais.
    const bool ja_existe = cofre_existente_dominio(cofre, dominio);

    json::Value config_atual;
    if (ja_existe)
        config_atual = cofre.get("domains").get(dominio);

    ConfigDominio cfg_atual;
    const bool tem_atual = ja_existe && ler_config_dominio(config_atual, cfg_atual);

    if (auth_key.empty())
    {
        if (tem_atual)
        {
            auth_key = cfg_atual.auth_key;
            std::cout << "[INFO] auth_key mantida (Enter).\n";
        }
        else
        {
            std::cerr << "[ERRO] auth_key nao informada para o novo dominio " << dominio
                      << ".\n";
            return EXIT_FAILURE;
        }
    }

    std::vector<std::string> types;
    if (!tipos_flag.empty())
    {
        if (!parsear_tipos(tipos_flag, types))
        {
            std::cerr << "[ERRO] --types invalido. Use A, AAAA ou A,AAAA.\n";
            return EXIT_FAILURE;
        }
    }
    else
    {
        bool tipos_vazio = false;
        if (!prompt_tipos(types, tipos_vazio))
        {
            std::cerr << "[ERRO] Tipos de registro invalidos. Use A, AAAA ou A,AAAA.\n";
            return EXIT_FAILURE;
        }
        if (tipos_vazio && tem_atual)
        {
            types = cfg_atual.types;
            std::cout << "[INFO] Tipos mantidos: " << tipos_para_texto(types) << " (Enter).\n";
        }
    }

    // Selecao da placa de rede usada para obter os IPs (armazenada no cofre).
    // "auto" = rota padrao do sistema (independente da placa escolhida).
    const std::string atual = cofre.as_string("iface", "");
    std::string iface;
    if (!iface_flag.empty())
    {
        if (iface_flag != "auto" && !nome_iface_valido(iface_flag))
        {
            std::cerr << "[ERRO] --iface invalido. Use auto ou um nome de placa.\n";
            return EXIT_FAILURE;
        }
        iface = iface_flag;
    }
    else if (atual.empty() || atual == "auto")
    {
        // Sem selecao previa: com uma unica placa ativa usa-a; multiplas
        // placas exigem escolha; nenhuma placa elegivel -> auto.
        iface = prompt_iface(atual);
    }
    else
    {
        iface = atual;
    }
    cofre.set("iface", json::Value::de_string(iface));

    cofre.set("api_url", json::Value::de_string(api_url));

    ConfigDominio cfg;
    cfg.auth_key = auth_key;
    cfg.types = types;

    json::Value dominios = json::Value::objeto();
    if (cofre.tem("domains") && cofre.get("domains").is_objeto())
        dominios = cofre.get("domains");
    dominios.set(dominio, montar_valor_dominio(cfg));
    cofre.set("domains", dominios);

    if (salvar_cofre(cofre, senha, caminho))
    {
        std::cout << "\n[SUCESSO] Dominio '" << dominio << "' gravado de forma"
                  << " criptografada (" << caminho << ") com tipos: "
                  << tipos_para_texto(types) << ".\n";
        std::cout << "[INFO] Placa de rede para os IPs: "
                  << (iface == "auto" ? "auto (rota padrao)" : iface) << ".\n";
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
    const std::string iface = cofre.as_string("iface", "");
    const bool iface_auto = iface.empty() || iface == "auto";
    std::cout << "Placa de rede (IPs): "
              << (iface_auto ? "auto (rota padrao)" : iface) << "\n";
    std::cout << "Dominios cadastrados:\n";
    if (cofre.tem("domains") && cofre.get("domains").is_objeto())
    {
        const json::Value& dominios = cofre.get("domains");
        for (json::Value::iterator it = dominios.begin(); it != dominios.end(); ++it)
        {
            // Exibe o dominio e seus tipos; a auth_key permanece oculta.
            ConfigDominio cfg;
            std::string tipos;
            if (ler_config_dominio(it->second, cfg))
                tipos = tipos_para_texto(cfg.types);
            else
                tipos = "desconhecido";
            std::cout << "  - " << it->first << " (auth_key armazenada; tipos: "
                      << tipos << ")\n";
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

    // Placa de rede selecionada para obter os IPs (chave ausente = auto).
    const std::string iface = cofre.as_string("iface", "");

    // Carrega o estado persistido da ultima execucao (regras 4.1-4.3).
    EstadoExecucao estado;
    carregar_estado(ARQUIVO_ESTADO, estado);

    std::cout << "[INFO] Obtendo IPs publicos (IPv4 e IPv6)"
              << (iface.empty() || iface == "auto" ? "" : " via " + iface)
              << "...\n";
    std::string ipv4;
    std::string ipv6;
    const bool tem_ipv4 = obter_ip_publico(ipv4, iface);
    const bool tem_ipv6 = obter_ipv6_publico(ipv6, iface);
    if (!tem_ipv4 && !tem_ipv6)
    {
        // Falha total de obtencao: registra o erro no estado para que a
        // proxima execucao seja tratada dentro da janela pos-evento (4.2).
        EstadoExecucao novo;
        (void)decidir_acionar(estado, false, true, novo);
        salvar_estado(ARQUIVO_ESTADO, novo);
        std::cerr << "[ERRO] Nao foi possivel obter IP publico (IPv4/IPv6).\n";
        return EXIT_FAILURE;
    }
    if (tem_ipv4)
        std::cout << "[INFO] IPv4 publico detectado: " << ipv4 << "\n";
    if (tem_ipv6)
        std::cout << "[INFO] IPv6 publico detectado: " << ipv6 << "\n";

    const bool mudou = ip_publico_mudou(estado, ipv4, ipv6, tem_ipv4, tem_ipv6);

    EstadoExecucao estado_novo;
    const bool acionar = decidir_acionar(estado, mudou, false, estado_novo);
    // Atualiza a familia somente quando obtida nesta execucao; familias
    // temporariamente indisponiveis preservam o ultimo IP conhecido.
    if (tem_ipv4)
        estado_novo.ipv4 = ipv4;
    if (tem_ipv6)
        estado_novo.ipv6 = ipv6;

    if (!acionar)
    {
        // Regra 4.1: sem alteracao de IP e sem erro -> nao aciona o Worker.
        salvar_estado(ARQUIVO_ESTADO, estado_novo);
        std::cout << "[INFO] IP publico inalterado; Worker nao acionado "
                     "(regra 4.1).\n";
        return EXIT_SUCCESS;
    }

    // Migracoes retrocompatíveis: o cofre v1.2.0 armazenava o dominio como
    // string (auth_key pura); converte para {auth_key, types:[A,AAAA]} e
    // reescreve o cofre de forma idempotente quando detectado.
    json::Value dominios = json::Value::objeto();
    if (cofre.tem("domains") && cofre.get("domains").is_objeto())
        dominios = cofre.get("domains");
    bool cofre_migrado = false;
    for (json::Value::iterator it = dominios.begin(); it != dominios.end(); ++it)
    {
        if (!it->second.is_objeto())
        {
            ConfigDominio cfg;
            if (ler_config_dominio(it->second, cfg))
            {
                dominios.set(it->first, montar_valor_dominio(cfg));
                cofre_migrado = true;
            }
        }
    }
    if (cofre_migrado)
    {
        cofre.set("domains", dominios);
        if (salvar_cofre(cofre, senha, caminho))
            std::cout << "[INFO] Cofre migrado do formato legado para o novo "
                         "formato (auth_key + types).\n";
        else
            std::cerr << "[AVISO] Nao foi possivel persistir a migracao do "
                         "formato do cofre.\n";
    }

    // Agrupa os dominios por auth_key: o Worker valida a mesma auth_key para
    // todo o lote, entao dominios com chaves distintas exigem requisicoes
    // separadas (mapa auth_key -> dominios).
    std::map<std::string, std::vector<DadosDominio>> lotes;
    // Dominio -> DadosDominio efetivamente enviado (para mensagem de sucesso
    // exibir somente os IPs dos tipos configurados).
    std::map<std::string, DadosDominio> enviados;
    const json::Value& dominios_final = dominios;
    for (json::Value::iterator it = dominios_final.begin(); it != dominios_final.end(); ++it)
    {
        ConfigDominio cfg;
        if (!ler_config_dominio(it->second, cfg))
        {
            std::cerr << "[ERRO] Dominio '" << it->first
                      << "' sem configuracao valida no cofre. Ignorado.\n";
            continue;
        }
        DadosDominio d;
        d.dominio = it->first;
        // Propaga o filtro estrito de tipos para o payload (somente os IPs
        // dos tipos declarados no cofre serao enviados).
        d.types = cfg.types;
        d.ipv4 = "";
        d.ipv6 = "";
        for (const auto& t : cfg.types)
        {
            if (t == TIPO_A && tem_ipv4)
                d.ipv4 = ipv4;
            else if (t == TIPO_AAAA && tem_ipv6)
                d.ipv6 = ipv6;
        }
        lotes[cfg.auth_key].push_back(d);
        enviados[d.dominio] = d;
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
        if (!notificar_worker(api_url, par.first, par.second, resultados, erro, iface))
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
                const auto it_envio = enviados.find(r.dominio);
                if (it_envio != enviados.end())
                {
                    if (!it_envio->second.ipv4.empty())
                        std::cout << " (A: " << it_envio->second.ipv4 << ")";
                    if (!it_envio->second.ipv6.empty())
                        std::cout << " (AAAA: " << it_envio->second.ipv6 << ")";
                }
                std::cout << "\n";
            }
            else
            {
                std::cerr << "[ERRO] Dominio '" << r.dominio << "': " << r.erro << "\n";
                falhas = true;
            }
        }
    }

    if (falhas)
    {
        // Erro nesta execucao -> registra a janela pos-evento (4.2/4.2.1),
        // fazendo as proximas execucoes re-verificarem o Worker.
        (void)decidir_acionar(estado_novo, false, true, estado_novo);
    }
    salvar_estado(ARQUIVO_ESTADO, estado_novo);
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
        {
            std::string tipos;
            std::string iface;
            for (int i = 2; i < argc; ++i)
            {
                const std::string arg = argv[i];
                if (arg == "--types" && i + 1 < argc)
                {
                    tipos = argv[++i];
                }
                else if (arg == "--iface" && i + 1 < argc)
                {
                    iface = argv[++i];
                }
                else
                {
                    std::cerr << "[ERRO] Opcao desconhecida: " << arg << "\n";
                    return EXIT_FAILURE;
                }
            }
            return cmd_adicionar(ARQUIVO_VAULT, tipos, iface);
        }
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

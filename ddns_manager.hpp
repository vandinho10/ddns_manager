#pragma once

#include <string>
#include <vector>

#include "json_min.hpp"

#ifndef DDNS_VERSION
#define DDNS_VERSION "0.0.0"
#endif

// ddns_manager: cliente C++ de atualizacao dinamica de DNS (DDNS) via Worker do
// Cloudflare, com cofre de credenciais criptografado (AES-256-CBC + PBKDF2).
//
// Nomenclatura tecnica em ingles; comentarios em portugues.
// Multiplataforma: POSIX (OpenSSL EVP + libcurl) e Windows (WinHTTP + CNG
// nativos, sem dependencia de terceiros). Formato do cofre identico entre
// plataformas.
namespace ddns {

constexpr const char* ARQUIVO_VAULT = "ddns_vault.enc";
constexpr const char* ARQUIVO_ESTADO = "ddns_state.json";
constexpr long TIMEOUT_HTTP = 10; // segundos por requisicao

// Regras de acionamento do Worker (estado persistido entre execucoes):
// 4.1  Sem alteracao de IP e sem erro -> NAO acionar worker.
// 4.2  Alteracao de IP ou erro -> acionar worker.
// 4.2.1 As 4 proximas execucoes apos uma alteracao/erro -> acionar worker.
// 4.3  5 execucoes sem alteracao e sem erro -> acionar worker (sync periodico).
constexpr int JANELA_POS_EVENTO = 4;      // 4.2.1: janela de re-verificacao
constexpr int QUIET_TRIGGER_THRESHOLD = 5; // 4.3: execucoes quietas p/ periodicidade

// Numero de iteracoes PBKDF2 (derivacao da chave mestre).
constexpr unsigned int PBKDF2_ITERACOES = 120000;

// --- Cofre (vault.cpp) ---

// Deriva chave (32 bytes) e IV (16 bytes) a partir da senha mestra e do salt.
bool derivar_chave_iv(const std::string& senha, const unsigned char* salt,
                      unsigned char* chave, unsigned char* iv,
                      unsigned int iteracoes);

// Criptografa o texto para o arquivo com AES-256-CBC + PBKDF2 (formato:
// 8 bytes de salt + ciphertext). Escrita com permissao 0600.
bool criptografar_arquivo(const std::string& texto, const std::string& senha,
                          const std::string& caminho);

// Descriptografa o arquivo de volta para texto puro. Retorna false se o
// arquivo nao existir, estiver corrompido ou a senha estiver incorreta.
bool descriptografar_arquivo(const std::string& senha,
                             const std::string& caminho, std::string& saida);

// Carrega e valida o cofre (descriptografa + parse JSON). True apenas quando
// a senha esta correta e o JSON e um objeto valido.
bool carregar_cofre(const std::string& senha, const std::string& caminho,
                    json::Value& cofre);

// Serializa e criptografa o cofre para o arquivo.
bool salvar_cofre(const json::Value& cofre, const std::string& senha,
                  const std::string& caminho);

// Verifica se o arquivo existe no filesystem.
bool arquivo_existe(const std::string& caminho);

// Le uma linha do terminal com echo desabilitado (termios POSIX / CNG Win),
// ou do stdin quando nao-interativo. Nunca exibe o valor.
std::string ler_linha_sem_eco();

// Le a Senha Mestra: variavel de ambiente DDNS_MASTER_PASSWORD (automacao) ou
// ler_linha_sem_eco() (interativo). Nunca exibe o valor.
std::string obter_senha_mestra();

// --- Tipos de registro DNS por dominio (cofre) ---

// Tipos de registro DNS suportados por dominio: "A" (IPv4) e "AAAA" (IPv6).
// Um dominio pode atualizar apenas um deles ou ambos (retrocompativel).
constexpr const char* TIPO_A = "A";
constexpr const char* TIPO_AAAA = "AAAA";

// Configuracao de um dominio no cofre: auth_key + tipos de registro a
// atualizar. O formato antigo (string = auth_key pura) equivale aos
// tipos padrao A+AAAA (retrocompatibilidade).
struct ConfigDominio
{
    std::string auth_key;
    std::vector<std::string> types; // ex.: {"A","AAAA"} ou {"AAAA"}
};

// Verifica se um tipo isolado e valido ("A" ou "AAAA", aceita minusculas).
bool tipo_valido(const std::string& tipo);

// Normaliza a entrada de tipos ("A", "AAAA", "A,AAAA", "ambos"; aceita
// minusculas e espacos). Deduplica e mantem a ordem canonica A,AAAA.
// Retorna false para entrada vazia ou com tipos desconhecidos.
bool parsear_tipos(const std::string& entrada, std::vector<std::string>& types);

// Serializa os tipos para exibicao ("A", "AAAA" ou "A,AAAA").
std::string tipos_para_texto(const std::vector<std::string>& types);

// Le a configuracao de um dominio do cofre. Retrocompativel: uma string e
// interpretada como auth_key com tipos padrao A+AAAA. Retorna false para
// valores invalidos/desconhecidos.
bool ler_config_dominio(const json::Value& valor, ConfigDominio& cfg);

// Monta o valor JSON de um dominio no cofre: {auth_key, types:[...]}.
json::Value montar_valor_dominio(const ConfigDominio& cfg);

// --- Estado de execução e acionamento do Worker (estado.cpp) ---

// Estado persistido entre execuções (ddns_state.json), utilizado pelas regras
// de acionamento do Worker (4.1/4.2/4.2.1/4.3).
struct EstadoExecucao
{
    std::string ipv4;               // último IPv4 conhecido (vazio = nunca)
    std::string ipv6;               // último IPv6 conhecido (vazio = nunca)
    bool janela_pos_evento = false; // dentro das 4 execuções pós-evento (4.2.1)
    int execpos = 0;                // execuções restantes da janela pós-evento
    int quiet = 0;                  // execuções quietas consecutivas (4.1/4.3)
};

// Carrega o estado do arquivo JSON. Ausência/corrupção -> estado padrão.
void carregar_estado(const std::string& caminho, EstadoExecucao& estado);

// Persiste o estado em JSON (permissão 0600 no POSIX).
bool salvar_estado(const std::string& caminho, const EstadoExecucao& estado);

// Detecta alteração de IP entre o estado persistido e os IPs atuais.
bool ip_publico_mudou(const EstadoExecucao& estado, const std::string& ipv4,
                      const std::string& ipv6, bool tem_ipv4, bool tem_ipv6);

// Decide se o Worker deve ser acionado NESTA execução e atualiza o estado:
// 4.1  mudou=false && erro=false fora da janela e quiet<5 -> false
// 4.2  mudou=true  || erro=true   -> true (abre a janela pós-evento, 4 exec)
// 4.2.1 dentro da janela pós-evento -> true (re-verificação)
// 4.3  quiet >= 5 -> true (sync periódico, reinicia o contador)
bool decidir_acionar(const EstadoExecucao& estado_ant, bool mudou, bool erro,
                     EstadoExecucao& estado_novo);

// --- Transporte HTTP (http.cpp) ---

// Um dominio e os IPs associados a ele (vazio = ausente, omitido no payload).
struct DadosDominio
{
    std::string dominio;
    std::string ipv4;
    std::string ipv6;

    // Tipos de registro DNS deste dominio (ex.: {"A"} ou {"AAAA"} ou ambos).
    // Vazio = retrocompativel (A+AAAA). Usado pelo montar_payload_worker para
    // incluir apenas os campos (ipv4/ipv6) correspondentes aos tipos ativos.
    std::vector<std::string> types;
};

// Resultado (por dominio) da resposta do Worker.
struct ResultadoDominio
{
    std::string dominio;
    bool sucesso = false;
    std::string erro; // detalhe quando a atualizacao falha
};

// Requisicao GET simples com timeout. Retorna string vazia em caso de erro.
std::string http_get(const std::string& url, long timeout_s);

// Requisicao POST JSON. True quando o HTTP responde com 2xx.
bool http_post_json(const std::string& url, const std::string& corpo,
                    long timeout_s, long& codigo_http, std::string& resposta);

// Obtem o IP publico atual via https://api.ipify.org (valida IPv4).
bool obter_ip_publico(std::string& ip);

// Obtem o IP publico IPv6 atual via https://api6.ipify.org (valida IPv6).
bool obter_ipv6_publico(std::string& ip);

// Monta o corpo JSON do payload do Worker:
// {"auth_key":..., "domains":{<dominio>:{ipv4?, ipv6?}}} (IPs vazios omitidos).
std::string montar_payload_worker(const std::string& auth_key,
                                  const std::vector<DadosDominio>& dominios);

// Interpreta a resposta JSON do Worker, preenchendo um ResultadoDominio por
// dominio (mesma ordem de `dominios`). Retorna false se o corpo nao for um
// JSON com a lista "results". Nao realiza transporte HTTP.
bool interpretar_resposta_worker(const std::string& resposta,
                                 const std::vector<DadosDominio>& dominios,
                                 std::vector<ResultadoDominio>& resultados);

// Notifica o Worker do Cloudflare com um lote de dominios que compartilham a
// mesma auth_key. Envia {"auth_key":..., "domains":{<dominio>:{ipv4?, ipv6?}}}
// e preenche `resultados` (um por dominio, na mesma ordem). Retorna false
// apenas para falhas de transporte/parse; o estado individual de cada dominio
// fica em `resultados[].sucesso`.
bool notificar_worker(const std::string& api_url, const std::string& auth_key,
                      const std::vector<DadosDominio>& dominios,
                      std::vector<ResultadoDominio>& resultados,
                      std::string& erro);

// --- Comandos CLI (main.cpp) ---

// --add / --update: insere ou atualiza um dominio no cofre (interativo).
// tipos_flag vazio = pergunta os tipos no terminal (ou usa A+AAAA).
int cmd_adicionar(const std::string& caminho, const std::string& tipos_flag);

// --list: lista API URL e dominios cadastrados.
int cmd_listar(const std::string& caminho);

// --remove <dominio>: remove um dominio do cofre.
int cmd_remover(const std::string& dominio, const std::string& caminho);

// Modo padrao (sem argumentos): obtem IP publico e atualiza todos os dominios.
int cmd_atualizar(const std::string& caminho);

// Verifica se o texto e um IPv4 valido (pontos separando 1-3 digitos).
bool eh_ipv4(const std::string& texto);

// Verifica se o texto e um IPv6 valido (apenas hex e ':', com ao menos um ':').
bool eh_ipv6(const std::string& texto);

// Remove espacos em branco e quebras de linha das extremidades.
std::string trim(const std::string& texto);

void imprimir_ajuda(const char* prog);
void imprimir_versao(const char* prog);

} // namespace ddns
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
constexpr long TIMEOUT_HTTP = 10; // segundos por requisicao

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

// Le a Senha Mestra: variavel de ambiente DDNS_MASTER_PASSWORD (automacao) ou
// terminal com echo desabilitado (interativo). Nunca exibe o valor.
std::string obter_senha_mestra();

// --- Transporte HTTP (http.cpp) ---

// Um dominio e os IPs associados a ele (vazio = ausente, omitido no payload).
struct DadosDominio
{
    std::string dominio;
    std::string ipv4;
    std::string ipv6;
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
int cmd_adicionar(const std::string& caminho);

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
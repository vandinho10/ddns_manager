#ifndef SELFUPDATE_HPP
#define SELFUPDATE_HPP

// Autoatualização via GitHub Releases, compartilhada entre os compilados
// (getip, ddns_manager, invpush). Derivada do `codectx update`.
// Este arquivo é idêntico em todos os repositórios: altere em um, copie
// para os demais.

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace selfupdate
{

// Código de saída de `update check` quando há versão nova (0 = atualizado, 1 = erro).
constexpr int EXIT_UPDATE_DISPONIVEL = 2;

// GET HTTPS com verificação de certificado; corpo vazio + erro preenchido em falha.
using HttpGet = std::function<std::string(const std::string &url, std::string &erro)>;

struct Contexto
{
    std::string app;         // nome do binário e prefixo dos assets ("getip")
    std::string versao;      // versão compilada ("1.3.0")
    std::string repo_padrao; // "vandinho10/getip"
    std::string env_repo;    // variável que sobrescreve o repo ("GETIP_UPDATE_REPO")
    HttpGet http_get;
};

// `<app> update [check] [--yes] [--quiet]`; argv[primeiro] é o primeiro argumento após "update".
int comando_update(const Contexto &ctx, int argc, char *argv[], int primeiro);

// ---- funções puras, expostas para testes ----

struct SemVer
{
    int major = 0;
    int minor = 0;
    int patch = 0;
    bool ok = false;
};

SemVer parse_semver(std::string s);
int cmp_semver(const SemVer &a, const SemVer &b);
std::string nome_artefato(const std::string &app);
std::vector<std::pair<std::string, std::string>> json_assets(const std::string &json);
std::string json_string_field(const std::string &json, const std::string &key);
std::string hash_em_sumas(const std::string &sumas, const std::string &nome);
std::string sha256_hex(const std::string &dados);

} // namespace selfupdate

#endif // SELFUPDATE_HPP

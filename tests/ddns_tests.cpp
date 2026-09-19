// Testes baseados em tabela do ddns_manager: parser JSON, criptografia do
// cofre (AES-256-CBC + PBKDF2) e validacao de IPv4.
#include "ddns_manager.hpp"
#include "test_framework.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using ddns::json::Value;

namespace
{

// ===========================================================================
// Modulo JSON minimo
// ===========================================================================

TEST("json_objeto_aninhado_roundtrip")
{
    const std::string texto = R"({"api_url":"https://w.example.workers.dev","domains":{"a.com":"k1","b.com.br":"k2"}})";
    Value v = Value::parse(texto);
    CHECK(v.is_objeto());
    CHECK(v.tem("api_url"));
    CHECK(v.as_string("api_url", "") == "https://w.example.workers.dev");
    CHECK(v.tem("domains"));
    CHECK(v.get("domains").is_objeto());
    CHECK(v.get("domains").get("a.com").como_string() == "k1");
    CHECK(v.get("domains").get("b.com.br").como_string() == "k2");
    CHECK(v.dump() == texto);
}

TEST("json_array_e_literais")
{
    const std::string texto = R"({"lista":[1,2.5,-3e2,true,false,null],"txt":"a\"b\\c"})";
    Value v = Value::parse(texto);
    CHECK(v.is_objeto());
    CHECK(v.get("lista").is_array());
    CHECK(v.get("lista").size() == 6);
    CHECK(v.get("lista").type() == Value::Tipo::Array);
    CHECK(v.as_string("txt", "") == "a\"b\\c");
    // Dump preserva os literais
    const Value& arr = v.get("lista");
    CHECK(arr.size() == 6);
}

TEST("json_escapes_e_unicode")
{
    const std::string texto = R"({"e":"linha1\nlinha2\ttab\u00e9","caf":"\u2705"})";
    Value v = Value::parse(texto);
    const std::string e = v.as_string("e", "");
    CHECK(e == "linha1\nlinha2\ttab\xC3\xA9");
    CHECK(v.as_string("caf", "") == "\xE2\x9C\x85"); // U+2705 -> UTF-8
    // Roundtrip do dump reconstitui os escapes
    Value v2 = Value::parse(v.dump());
    CHECK(v2.as_string("e", "") == e);
}

TEST("json_espacos_sao_ignorados")
{
    const std::string texto = "  { \n \"a\" : \"x\" , \"b\" : [ 1 ] }\t";
    Value v = Value::parse(texto);
    CHECK(v.as_string("a", "") == "x");
    CHECK(v.get("b").is_array());
    CHECK(v.get("b").size() == 1);
}

TEST("json_construcao_manual_dump")
{
    Value v = Value::objeto();
    v.set("domain", Value::de_string("alfa.example.com"));
    v.set("ipv4", Value::de_string("203.0.113.9"));
    Value kids = Value::objeto();
    kids.set("one", Value::de_string("first"));
    v.set("nested", kids);
    const std::string d = v.dump();
    Value v2 = Value::parse(d);
    CHECK(v2.as_string("domain", "") == "alfa.example.com");
    CHECK(v2.get("nested").is_objeto());
}

TEST("json_erros_de_sintaxe")
{
    struct Caso
    {
        const char* texto;
        const char* esperado_fragmento;
    };
    const Caso casos[] = {
        {"", "valor ausente"},
        {"{", "esperado chave"},
        {"}", "JSON invalido"},
        {"{\"a\"}", "esperado ':'"},
        {"{\"a\":}", "JSON invalido"},
        {"{\"a\":1,}", "esperado chave"},
        {"[1,2,]", "JSON invalido"},
        {"\"abc", "terminada"},
        {"{\"a\":\"\\q\"}", "escape"},
        {"true extra", "extra"},
        {"nul", "literal"},
    };
    for (const auto& c : casos)
    {
        bool lancou = false;
        std::string msg;
        try
        {
            Value::parse(c.texto);
        }
        catch (const ddns::json::Erro& e)
        {
            lancou = true;
            msg = e.what();
        }
        CHECK(lancou);
        CHECK(msg.find(c.esperado_fragmento) != std::string::npos);
    }
}

// ===========================================================================
// Criptografia do cofre (AES-256-CBC + PBKDF2)
// ===========================================================================

TEST("crypto_roundtrip_arquivo")
{
    const std::string arquivo = "ddns_test_tmp_roundtrip.enc";
    const std::string senha = "SenhaMestra+MuitoForte#2026";
    const std::string texto = R"({"api_url":"https://w.example.com","domains":{"a.com":"k"}})";

    CHECK(ddns::criptografar_arquivo(texto, senha, arquivo));

    std::string saida;
    CHECK(ddns::descriptografar_arquivo(senha, arquivo, saida));
    CHECK(saida == texto);

    std::remove(arquivo.c_str());
}

TEST("crypto_roundtrip_blocos_multiplos")
{
    const std::string arquivo = "ddns_test_tmp_multibloco.enc";
    const std::string senha = "s3nh4";
    // 1, 15, 16, 17 e 64 bytes: cobre padding PKCS#7 em todas as fronteiras.
    const std::vector<std::string> textos = {
        "a",
        "abcdefghijklmno",      // 15
        "abcdefghijklmnop",     // 16
        "abcdefghijklmnopq",    // 17
        std::string(64, 'x'),   // multiplo exato
    };
    for (const auto& t : textos)
    {
        CHECK(ddns::criptografar_arquivo(t, senha, arquivo));
        std::string saida;
        CHECK(ddns::descriptografar_arquivo(senha, arquivo, saida));
        CHECK(saida == t);
    }
    std::remove(arquivo.c_str());
}

TEST("crypto_senha_incorreta_falha")
{
    const std::string arquivo = "ddns_test_tmp_senhaerrada.enc";
    CHECK(ddns::criptografar_arquivo("dados sigilosos", "correta-chave", arquivo));

    std::string saida;
    CHECK(!ddns::descriptografar_arquivo("chave-errada", arquivo, saida));
    CHECK(saida.empty());
    std::remove(arquivo.c_str());
}

TEST("crypto_arquivo_inexistente_falha")
{
    std::string saida;
    CHECK(!ddns::descriptografar_arquivo("x", "ddns_test_tmp_naoexiste.enc", saida));
}

TEST("crypto_salt_aleatorio_gera_ciphertext_distinto")
{
    const std::string a1 = "ddns_test_tmp_salt_a.enc";
    const std::string a2 = "ddns_test_tmp_salt_b.enc";
    CHECK(ddns::criptografar_arquivo("mesmo-conteudo", "senha", a1));
    CHECK(ddns::criptografar_arquivo("mesmo-conteudo", "senha", a2));

    std::ifstream f1(a1, std::ios::binary);
    std::ifstream f2(a2, std::ios::binary);
    std::string b1((std::istreambuf_iterator<char>(f1)), std::istreambuf_iterator<char>());
    std::string b2((std::istreambuf_iterator<char>(f2)), std::istreambuf_iterator<char>());
    CHECK(b1.size() > 8);
    CHECK(b2.size() > 8);
    CHECK(b1 != b2);

    std::remove(a1.c_str());
    std::remove(a2.c_str());
}

TEST("crypto_derivacao_chave_iv_estavel_com_salt_fixo")
{
    unsigned char chave1[32];
    unsigned char iv1[16];
    unsigned char chave2[32];
    unsigned char iv2[16];
    unsigned char salt[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    CHECK(ddns::derivar_chave_iv("senha", salt, chave1, iv1, 1000));
    CHECK(ddns::derivar_chave_iv("senha", salt, chave2, iv2, 1000));
    CHECK(std::memcmp(chave1, chave2, 32) == 0);
    CHECK(std::memcmp(iv1, iv2, 16) == 0);

    // Senhas diferentes com o mesmo salt geram material distinto
    CHECK(ddns::derivar_chave_iv("outra", salt, chave2, iv2, 1000));
    CHECK(std::memcmp(chave1, chave2, 32) != 0);
}

// ===========================================================================
// Cofre (salvar/carregar)
// ===========================================================================

TEST("cofre_roundtrip_multi_dominios")
{
    const std::string caminho = "ddns_test_tmp_vault.enc";
    const std::string senha = "cofre-mestre";

    Value cofre = Value::objeto();
    cofre.set("api_url", Value::de_string("https://w.e.com/update"));
    Value dominios = Value::objeto();
    dominios.set("alfa.e.com", Value::de_string("chave-alfa"));
    dominios.set("beta.e.com.br", Value::de_string("chave-beta"));
    cofre.set("domains", dominios);

    CHECK(ddns::salvar_cofre(cofre, senha, caminho));

    Value carregado;
    CHECK(ddns::carregar_cofre(senha, caminho, carregado));
    CHECK(carregado.as_string("api_url", "") == "https://w.e.com/update");
    CHECK(carregado.get("domains").get("alfa.e.com").como_string() == "chave-alfa");
    CHECK(carregado.get("domains").get("beta.e.com.br").como_string() == "chave-beta");
    CHECK(carregado.get("domains").size() == 2);

    // Senha incorreta: carregamento falha
    Value vazio;
    CHECK(!ddns::carregar_cofre("errada", caminho, vazio));
    // Arquivo inexistente: falha
    CHECK(!ddns::carregar_cofre(senha, "ddns_test_tmp_vault_inexistente.enc", vazio));
    // Cofre corrompido: falha ao carregar
    {
        std::ofstream arq(caminho, std::ios::binary);
        arq << "lixo";
    }
    CHECK(!ddns::carregar_cofre(senha, caminho, vazio));

    std::remove(caminho.c_str());
}

TEST("cofre_alteracao_nao_perde_dominios")
{
    const std::string caminho = "ddns_test_tmp_vault2.enc";
    const std::string senha = "mestre";

    Value cofre = Value::objeto();
    cofre.set("api_url", Value::de_string("https://w.e.com/update"));
    Value dominios = Value::objeto();
    dominios.set("a.com", Value::de_string("ka"));
    dominios.set("b.com", Value::de_string("kb"));
    cofre.set("domains", dominios);
    CHECK(ddns::salvar_cofre(cofre, senha, caminho));

    // Reabre, adiciona "c.com" e salva novamente
    Value c2;
    CHECK(ddns::carregar_cofre(senha, caminho, c2));
    Value dom2 = c2.is_objeto() && c2.tem("domains") ? c2.get("domains") : Value::objeto();
    dom2.set("c.com", Value::de_string("kc"));
    c2.set("domains", dom2);
    CHECK(ddns::salvar_cofre(c2, senha, caminho));

    Value c3;
    CHECK(ddns::carregar_cofre(senha, caminho, c3));
    CHECK(c3.get("domains").size() == 3);
    CHECK(c3.get("domains").get("a.com").como_string() == "ka");
    CHECK(c3.get("domains").get("c.com").como_string() == "kc");

    std::remove(caminho.c_str());
}

// ===========================================================================
// Validacoes utilitarias
// ===========================================================================

TEST("ipv4_valido")
{
    const std::vector<std::string> validos = {
        "0.0.0.0",
        "127.0.0.1",
        "192.168.1.1",
        "255.255.255.255",
        "10.0.0.100",
    };
    for (const auto& ip : validos)
    {
        if (!ddns::eh_ipv4(ip))
        {
            CHECK(false); // ip valido rejeitado
            std::cerr << "    rejeitado: " << ip << "\n";
        }
    }
    CHECK(true);
}

TEST("ipv4_invalido")
{
    const std::vector<std::string> invalidos = {
        "",
        " ",
        "256.1.1.1",
        "1.2.3",
        "1.2.3.4.5",
        "1.2.3.a",
        "999.999.999.999",
        "1.2.3.4 ",
        "-1.2.3.4",
    };
    for (const auto& ip : invalidos)
    {
        if (ddns::eh_ipv4(ip))
        {
            CHECK(false); // ip invalido aceito
            std::cerr << "    aceito: '" << ip << "'\n";
        }
    }
    CHECK(true);
}

TEST("trim_remove_espacos")
{
    struct Caso
    {
        const char* entrada;
        const char* esperado;
    };
    const Caso casos[] = {
        {"", ""},
        {"   ", ""},
        {"203.0.113.1", "203.0.113.1"},
        {"  203.0.113.1  ", "203.0.113.1"},
        {"\t196.0.0.1\r\n", "196.0.0.1"},
        {"a b c", "a b c"},
    };
    for (const auto& c : casos)
    {
        CHECK(ddns::trim(c.entrada) == c.esperado);
    }
}

// ===========================================================================
// Payload do Worker (formato do receptor Cloudflare)
// ===========================================================================

TEST("worker_payload_ipv4_e_ipv6")
{
    std::vector<ddns::DadosDominio> dominios;
    ddns::DadosDominio d;
    d.dominio = "alfa.example.com";
    d.ipv4 = "203.0.113.9";
    d.ipv6 = "2001:db8::1";
    dominios.push_back(d);

    ddns::json::Value v = ddns::json::Value::parse(ddns::montar_payload_worker("segredo", dominios));
    CHECK(v.as_string("auth_key", "") == "segredo");
    CHECK(v.get("domains").tem("alfa.example.com"));
    const ddns::json::Value& entry = v.get("domains").get("alfa.example.com");
    CHECK(entry.as_string("ipv4", "") == "203.0.113.9");
    CHECK(entry.as_string("ipv6", "") == "2001:db8::1");
}

TEST("worker_payload_sem_ipv6")
{
    std::vector<ddns::DadosDominio> dominios;
    ddns::DadosDominio d;
    d.dominio = "alfa.example.com";
    d.ipv4 = "203.0.113.9";
    dominios.push_back(d);

    ddns::json::Value v = ddns::json::Value::parse(ddns::montar_payload_worker("k", dominios));
    const ddns::json::Value& entry = v.get("domains").get("alfa.example.com");
    CHECK(entry.as_string("ipv4", "") == "203.0.113.9");
    CHECK(entry.as_string("ipv6", "ausente") == "ausente");
}

TEST("worker_payload_ipv6_only")
{
    std::vector<ddns::DadosDominio> dominios;
    ddns::DadosDominio d;
    d.dominio = "beta.example.com";
    d.ipv6 = "2001:db8::5678";
    dominios.push_back(d);

    ddns::json::Value v = ddns::json::Value::parse(ddns::montar_payload_worker("k", dominios));
    const ddns::json::Value& entry = v.get("domains").get("beta.example.com");
    CHECK(entry.as_string("ipv4", "ausente") == "ausente");
    CHECK(entry.as_string("ipv6", "") == "2001:db8::5678");
}

TEST("work_payload_multi_dominio")
{
    std::vector<ddns::DadosDominio> dominios;
    ddns::DadosDominio a;
    a.dominio = "zeta.example.com";
    a.ipv4 = "10.0.0.1";
    ddns::DadosDominio b;
    b.dominio = "alfa.example.com";
    b.ipv4 = "10.0.0.1";
    dominios.push_back(a);
    dominios.push_back(b);

    ddns::json::Value v = ddns::json::Value::parse(ddns::montar_payload_worker("k", dominios));
    CHECK(v.get("domains").size() == 2);
    CHECK(v.get("domains").tem("zeta.example.com"));
    CHECK(v.get("domains").tem("alfa.example.com"));
}

TEST("ipv6_valido")
{
    const std::vector<std::string> validos = {
        "::1",
        "2001:db8::1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "::",
        "fe80::1",
    };
    for (const auto& ip : validos)
    {
        if (!ddns::eh_ipv6(ip))
        {
            CHECK(false);
            std::cerr << "    rejeitado: " << ip << "\n";
        }
    }
    CHECK(true);
}

TEST("ipv6_invalido")
{
    const std::vector<std::string> invalidos = {
        "",
        " ",
        "127.0.0.1",
        "gggg::",
        "2001:::db8",
        "abc",
        "1.2.3.4",
    };
    for (const auto& ip : invalidos)
    {
        if (ddns::eh_ipv6(ip))
        {
            CHECK(false);
            std::cerr << "    aceito: '" << ip << "'\n";
        }
    }
    CHECK(true);
}

TEST("json_array_item_acesso")
{
    const std::string texto = R"({"results":[{"domain":"a.com","success":true},{"domain":"b.com","success":false}]})";
    ddns::json::Value v = ddns::json::Value::parse(texto);
    CHECK(v.get("results").is_array());
    CHECK(v.get("results").size() == 2);
    CHECK(v.get("results").item(0).as_string("domain", "") == "a.com");
    CHECK(v.get("results").item(0).get("success").raw() == "true");
    CHECK(v.get("results").item(1).get("success").raw() == "false");

    bool lancou = false;
    try
    {
        v.get("results").item(5);
    }
    catch (const ddns::json::Erro&)
    {
        lancou = true;
    }
    CHECK(lancou);
}

// ===========================================================================
// Interpretacao da resposta do Worker (receptor Cloudflare)
// ===========================================================================

TEST("worker_resposta_sucesso_todos_dominios")
{
    const std::string corpo = R"({"success":true,"results":[
        {"domain":"alfa.example.com","updates":[
            {"type":"A","content":"203.0.113.9","success":true},
            {"type":"AAAA","content":"2001:db8::1","success":true}]},
        {"domain":"beta.example.com.br","updates":[
            {"type":"A","content":"203.0.113.9","success":true}]}
    ]})";

    std::vector<ddns::DadosDominio> dominios;
    ddns::DadosDominio a;
    a.dominio = "alfa.example.com";
    a.ipv4 = "203.0.113.9";
    a.ipv6 = "2001:db8::1";
    ddns::DadosDominio b;
    b.dominio = "beta.example.com.br";
    b.ipv4 = "203.0.113.9";
    dominios.push_back(a);
    dominios.push_back(b);

    std::vector<ddns::ResultadoDominio> resultados;
    CHECK(ddns::interpretar_resposta_worker(corpo, dominios, resultados));
    CHECK(resultados.size() == 2);
    CHECK(resultados[0].sucesso);
    CHECK(resultados[1].sucesso);
}

TEST("worker_resposta_dominio_nao_listado")
{
    const std::string corpo = R"({"success":true,"results":[
        {"domain":"naolista.example.com","success":false,
         "error":"Domínio não listado, não autorizado ou chave incorreta"}
    ]})";

    std::vector<ddns::DadosDominio> dominios;
    ddns::DadosDominio a;
    a.dominio = "naolista.example.com";
    a.ipv4 = "203.0.113.9";
    dominios.push_back(a);

    std::vector<ddns::ResultadoDominio> resultados;
    CHECK(ddns::interpretar_resposta_worker(corpo, dominios, resultados));
    CHECK(resultados.size() == 1);
    CHECK(!resultados[0].sucesso);
    CHECK(!resultados[0].erro.empty());
}

TEST("worker_resposta_update_falhou_erro_cf")
{
    const std::string corpo = R"({"success":true,"results":[
        {"domain":"alfa.example.com","updates":[
            {"type":"A","content":"203.0.113.9","success":false,
             "errors":[{"code":9003,"message":"Record could not be found"}]}]}
    ]})";

    std::vector<ddns::DadosDominio> dominios;
    ddns::DadosDominio a;
    a.dominio = "alfa.example.com";
    a.ipv4 = "203.0.113.9";
    dominios.push_back(a);

    std::vector<ddns::ResultadoDominio> resultados;
    CHECK(ddns::interpretar_resposta_worker(corpo, dominios, resultados));
    CHECK(resultados.size() == 1);
    CHECK(resultados[0].sucesso == false);
    CHECK(resultados[0].erro.find("Record could not be found") != std::string::npos);
}

TEST("worker_resposta_sem_results")
{
    const std::string corpo = R"({"success":true})";

    std::vector<ddns::DadosDominio> dominios;
    ddns::DadosDominio a;
    a.dominio = "alfa.example.com";
    a.ipv4 = "203.0.113.9";
    dominios.push_back(a);

    std::vector<ddns::ResultadoDominio> resultados;
    CHECK(!ddns::interpretar_resposta_worker(corpo, dominios, resultados));
}

} // namespace

int main()
{
    return tests::run_all();
}
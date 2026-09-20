#pragma once

#include <cstdlib>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace tests
{

struct TestCase
{
    std::string nome;
    std::function<void()> fn;
};

inline std::vector<TestCase> &registry()
{
    static std::vector<TestCase> r;
    return r;
}

struct Registrar
{
    Registrar(const std::string &nome, std::function<void()> fn)
    {
        registry().push_back({nome, std::move(fn)});
    }
};

struct Resumo
{
    int pass = 0;
    int fail = 0;
};

inline Resumo &resumo()
{
    static Resumo r;
    return r;
}

inline void check(bool cond, const std::string &expr, const char *arquivo, int linha)
{
    if (cond)
    {
        ++resumo().pass;
    }
    else
    {
        ++resumo().fail;
        std::cerr << "  FALHA " << arquivo << ":" << linha << " -> " << expr << "\n";
    }
}

inline int run_all()
{
    for (auto &t : registry())
    {
        std::cerr << "[TEST] " << t.nome << "\n";
        t.fn();
    }
    std::cerr << "\nRESUMO: " << resumo().pass << " ok, " << resumo().fail << " falhas\n";
    return resumo().fail == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

} // namespace tests

#define TESTS_CONCAT_IMPL(a, b) a##b
#define TESTS_CONCAT(a, b) TESTS_CONCAT_IMPL(a, b)

#define CHECK(expr) ::tests::check((expr), #expr, __FILE__, __LINE__)

#define TEST(nome)\
    static void TESTS_CONCAT(test_fn_, __LINE__)(void);\
    static ::tests::Registrar TESTS_CONCAT(test_reg_, __LINE__)(nome, TESTS_CONCAT(test_fn_, __LINE__));\
    static void TESTS_CONCAT(test_fn_, __LINE__)(void)

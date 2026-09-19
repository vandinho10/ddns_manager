#pragma once

#include <map>
#include <stdexcept>
#include <string>
#include <vector>

// Parser e serializador JSON minimo embutido (zero dependencias externas).
// Suporta objetos, arrays, strings, numeros, true/false e null. E o suficiente
// para o cofre de credenciais do ddns_manager e para o payload do Worker.
namespace ddns {
namespace json {

class Erro : public std::runtime_error {
public:
    explicit Erro(const std::string& msg) : std::runtime_error(msg) {}
};

class Value {
public:
    enum class Tipo { String, Objeto, Array, Outro };

    // Construtores de conveniencia

    // Valor "null" padrao (utilizado pelo mapa interno de um objeto).
    Value() : tipo_(Tipo::Outro), str_("null") {}

    static Value de_string(const std::string& s)
    {
        Value v(Tipo::String);
        v.str_ = s;
        return v;
    }

    static Value de_literal(const std::string& literal)
    {
        Value v(Tipo::Outro);
        v.str_ = literal;
        return v;
    }

    static Value objeto()
    {
        return Value(Tipo::Objeto);
    }

    static Value array()
    {
        return Value(Tipo::Array);
    }

    // Predicados de tipo
    Tipo type() const { return tipo_; }
    bool is_string() const { return tipo_ == Tipo::String; }
    bool is_objeto() const { return tipo_ == Tipo::Objeto; }
    bool is_array() const { return tipo_ == Tipo::Array; }
    bool is_outro() const { return tipo_ == Tipo::Outro; }

    // Manipulacao de objeto
    bool tem(const std::string& chave) const
    {
        if (tipo_ != Tipo::Objeto)
            throw Erro("tem() em valor nao-objeto");
        return obj_.find(chave) != obj_.end();
    }

    const Value& get(const std::string& chave) const
    {
        if (!tem(chave))
            throw Erro("chave '" + chave + "' inexistente");
        return obj_.at(chave);
    }

    std::string as_string(const std::string& chave, const std::string& padrao) const
    {
        if (!tem(chave))
            return padrao;
        const Value& v = obj_.at(chave);
        return (v.is_string() || v.is_outro()) ? v.str_ : padrao;
    }

    std::string como_string() const
    {
        if (tipo_ != Tipo::String && tipo_ != Tipo::Outro)
            throw Erro("como_string() em valor nao-escalar");
        return str_;
    }

    void set(const std::string& chave, const Value& v)
    {
        if (tipo_ != Tipo::Objeto)
            throw Erro("set() em valor nao-objeto");
        obj_[chave] = v;
    }

    bool remover(const std::string& chave)
    {
        if (tipo_ != Tipo::Objeto)
            throw Erro("remover() em valor nao-objeto");
        return obj_.erase(chave) > 0;
    }

    // Manipulacao de array
    void empurra(const Value& v)
    {
        if (tipo_ != Tipo::Array)
            throw Erro("empurra() em valor nao-array");
        arr_.push_back(v);
    }

    // Acesso a elemento de array por indice.
    const Value& item(size_t i) const
    {
        if (tipo_ != Tipo::Array)
            throw Erro("item() em valor nao-array");
        if (i >= arr_.size())
            throw Erro("indice de array fora dos limites");
        return arr_[i];
    }

    // Iteracao sobre objeto (chave -> valor)
    typedef std::map<std::string, Value>::const_iterator iterator;
    iterator begin() const
    {
        if (tipo_ != Tipo::Objeto)
            throw Erro("begin() em valor nao-objeto");
        return obj_.begin();
    }
    iterator end() const
    {
        if (tipo_ != Tipo::Objeto)
            throw Erro("end() em valor nao-objeto");
        return obj_.end();
    }

    size_t size() const
    {
        if (tipo_ == Tipo::Objeto)
            return obj_.size();
        if (tipo_ == Tipo::Array)
            return arr_.size();
        return 0;
    }

    const std::string& raw() const { return str_; }

    // Parsing e serializacao
    static Value parse(const std::string& texto);
    std::string dump() const;

private:
    explicit Value(Tipo t) : tipo_(t) {}

    Tipo tipo_;
    std::string str_;
    std::map<std::string, Value> obj_;
    std::vector<Value> arr_;
};

std::string escapar(const std::string& s);

} // namespace json
} // namespace ddns
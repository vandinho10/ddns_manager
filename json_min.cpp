#include "json_min.hpp"

#include <cctype>
#include <cstdio>

namespace ddns {
namespace json {

namespace {

struct Parser {
    const std::string& s;
    size_t i = 0;

    explicit Parser(const std::string& texto) : s(texto) {}

    void espacos()
    {
        while (i < s.size() &&
               (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r'))
            ++i;
    }

    [[noreturn]] void erro(const std::string& msg) const
    {
        throw Erro(msg + " (posicao " + std::to_string(i) + ")");
    }

    bool consumir(char c)
    {
        if (i < s.size() && s[i] == c)
        {
            ++i;
            return true;
        }
        return false;
    }

    static unsigned hex(char c)
    {
        if (c >= '0' && c <= '9')
            return static_cast<unsigned>(c - '0');
        if (c >= 'a' && c <= 'f')
            return static_cast<unsigned>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F')
            return static_cast<unsigned>(c - 'A' + 10);
        throw Erro(std::string("hex invalido: '") + c + "'");
    }

    static void utf8(unsigned cp, std::string& out)
    {
        if (cp < 0x80)
        {
            out.push_back(static_cast<char>(cp));
        }
        else if (cp < 0x800)
        {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
        else if (cp < 0x10000)
        {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
        else
        {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    Value valor()
    {
        espacos();
        if (i >= s.size())
            erro("valor ausente");
        char c = s[i];
        if (c == '{')
            return objeto();
        if (c == '[')
            return array();
        if (c == '"')
            return Value::de_string(string_literal());
        if (c == 't' || c == 'f' || c == 'n')
            return literal_palavra();
        return numero();
    }

    Value objeto()
    {
        if (!consumir('{'))
            erro("esperado '{'");
        Value v = Value::objeto();
        espacos();
        if (consumir('}'))
            return v;
        while (true)
        {
            espacos();
            if (i >= s.size() || s[i] != '"')
                erro("esperado chave de objeto (string)");
            std::string chave = string_literal();
            espacos();
            if (!consumir(':'))
                erro("esperado ':' apos chave");
            v.set(chave, valor());
            espacos();
            if (consumir('}'))
                return v;
            if (!consumir(','))
                erro("esperado ',' ou '}' em objeto");
        }
    }

    Value array()
    {
        if (!consumir('['))
            erro("esperado '['");
        Value v = Value::array();
        espacos();
        if (consumir(']'))
            return v;
        while (true)
        {
            v.empurra(valor());
            espacos();
            if (consumir(']'))
                return v;
            if (!consumir(','))
                erro("esperado ',' ou ']' em array");
        }
    }

    std::string string_literal()
    {
        if (!consumir('"'))
            erro("esperado '\"'");
        std::string out;
        while (true)
        {
            if (i >= s.size())
                erro("string nao terminada");
            char c = s[i];
            if (c == '"')
            {
                ++i;
                return out;
            }
            if (c == '\\')
            {
                ++i;
                if (i >= s.size())
                    erro("escape incompleto");
                char e = s[i++];
                switch (e)
                {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u':
                {
                    if (i + 4 > s.size())
                        erro("escape unicode incompleto");
                    unsigned cp = 0;
                    for (int k = 0; k < 4; ++k)
                        cp = (cp << 4) | hex(s[i++]);
                    // Par de surrogates (emoji / caracteres fora do BMP)
                    if (cp >= 0xD800 && cp <= 0xDBFF)
                    {
                        if (s.size() - i >= 6 && s[i] == '\\' && s[i + 1] == 'u')
                        {
                            unsigned lo = 0;
                            i += 2;
                            for (int k = 0; k < 4; ++k)
                                lo = (lo << 4) | hex(s[i++]);
                            if (lo >= 0xDC00 && lo <= 0xDFFF)
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        }
                    }
                    utf8(cp, out);
                    break;
                }
                default: erro("escape invalido");
                }
            }
            else
            {
                out.push_back(c);
                ++i;
            }
        }
    }

    Value literal_palavra()
    {
        if (s.compare(i, 4, "true") == 0)
        {
            i += 4;
            return Value::de_literal("true");
        }
        if (s.compare(i, 5, "false") == 0)
        {
            i += 5;
            return Value::de_literal("false");
        }
        if (s.compare(i, 4, "null") == 0)
        {
            i += 4;
            return Value::de_literal("null");
        }
        erro("literal invalido");
    }

    Value numero()
    {
        if (i >= s.size())
            erro("valor ausente");
        if (s[i] != '-' && !std::isdigit(static_cast<unsigned char>(s[i])))
            erro("valor JSON invalido");
        size_t inicio = i;
        if (consumir('-'))
        {
            if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i])))
                erro("numero invalido");
        }
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i])))
            ++i;
        if (consumir('.'))
        {
            if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i])))
                erro("numero invalido");
            while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i])))
                ++i;
        }
        if (i < s.size() && (s[i] == 'e' || s[i] == 'E'))
        {
            ++i;
            if (i < s.size() && (s[i] == '+' || s[i] == '-'))
                ++i;
            if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i])))
                erro("expoente invalido");
            while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i])))
                ++i;
        }
        return Value::de_literal(s.substr(inicio, i - inicio));
    }
};

} // namespace

Value Value::parse(const std::string& texto)
{
    Parser p(texto);
    Value v = p.valor();
    p.espacos();
    if (p.i < p.s.size())
        throw Erro("conteudo extra apos o valor JSON");
    return v;
}

std::string escapar(const std::string& s)
{
    std::string out;
    char buf[8];
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20)
            {
                std::snprintf(buf, sizeof buf, "\\u%04x", c);
                out += buf;
            }
            else
            {
                out.push_back(static_cast<char>(c));
            }
        }
    }
    return out;
}

std::string Value::dump() const
{
    switch (tipo_)
    {
    case Tipo::String:
        return "\"" + escapar(str_) + "\"";
    case Tipo::Outro:
        return str_.empty() ? "null" : str_;
    case Tipo::Objeto:
    {
        std::string out = "{";
        bool primeiro = true;
        for (const auto& par : obj_)
        {
            if (!primeiro)
                out += ",";
            primeiro = false;
            out += "\"" + escapar(par.first) + "\":" + par.second.dump();
        }
        return out + "}";
    }
    case Tipo::Array:
    {
        std::string out = "[";
        bool primeiro = true;
        for (const auto& v : arr_)
        {
            if (!primeiro)
                out += ",";
            primeiro = false;
            out += v.dump();
        }
        return out + "]";
    }
    }
    return "null";
}

} // namespace json
} // namespace ddns
CXX      := g++
STD      := -std=c++17
WARN     := -Wall -Wextra -Wpedantic
OPTFLAGS := -O2
DBGFLAGS := -O0 -g

VERSION  := 1.5.0
TARGET   := ddns_manager
TESTBIN  := tests/test_runner
TESTBIN_SAN := tests/test_runner_san

# Alvo do sistema: alvo nativo por padrao; passe TARGET_OS=Windows_NT ao
# compilar com mingw-w64 (x86_64-w64-mingw32-g++ / i686-w64-mingw32-g++).
TARGET_OS ?= $(shell uname -s)

# Windows (MinGW): binario 100% estatico com transporte WinHTTP nativo e
# criptografia CNG (bcrypt.dll). ws2_32: inet_pton/sockaddr no vinculo de
# interface. iphlpapi: GetAdaptersAddresses (listagem de placas). POSIX:
# libcurl dinamico + OpenSSL EVP.
ifeq ($(TARGET_OS),Windows_NT)
  LIBS := -static -static-libgcc -static-libstdc++ -lwinhttp -lbcrypt -lws2_32 -liphlpapi -Wl,--no-insert-timestamp
else
  LIBS := -lcurl -lssl -lcrypto
endif

# Sobrescrevem -I/-L para cross-ambiente (ex.: sysroot sem sudo).
INC_DIRS :=
LIB_DIRS :=

CXXFLAGS := $(STD) $(WARN) -I. $(INC_DIRS)

.PHONY: all check test sanitize version install clean

all: $(TARGET)

$(TARGET): main.cpp vault.cpp http.cpp estado.cpp iface.cpp json_min.cpp selfupdate.cpp ddns_manager.hpp json_min.hpp selfupdate.hpp
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) -DDDNS_VERSION=\"$(VERSION)\" -o $@ main.cpp vault.cpp http.cpp estado.cpp iface.cpp json_min.cpp selfupdate.cpp $(LIB_DIRS) $(LIBS)

# Verificacao estatica: warnings tratados como erro
check:
	$(CXX) $(CXXFLAGS) -Werror -fsyntax-only -DDDNS_VERSION=\"$(VERSION)\" main.cpp vault.cpp http.cpp estado.cpp iface.cpp json_min.cpp selfupdate.cpp
	@echo "verificacao ok (zero warnings)"

$(TESTBIN): tests/ddns_tests.cpp vault.cpp http.cpp estado.cpp iface.cpp json_min.cpp selfupdate.cpp ddns_manager.hpp json_min.hpp selfupdate.hpp tests/test_framework.hpp
	$(CXX) $(CXXFLAGS) $(DBGFLAGS) -DDDNS_VERSION=\"$(VERSION)\" -o $@ tests/ddns_tests.cpp vault.cpp http.cpp estado.cpp iface.cpp json_min.cpp selfupdate.cpp $(LIB_DIRS) $(LIBS)

test: $(TESTBIN)
	./$(TESTBIN)

# Build com sanitizers (AddressSanitizer + UndefinedBehaviorSanitizer)
$(TESTBIN_SAN): tests/ddns_tests.cpp vault.cpp http.cpp estado.cpp iface.cpp json_min.cpp selfupdate.cpp ddns_manager.hpp json_min.hpp selfupdate.hpp tests/test_framework.hpp
	$(CXX) $(CXXFLAGS) $(DBGFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer -DDDNS_VERSION=\"$(VERSION)\" -o $@ tests/ddns_tests.cpp vault.cpp http.cpp estado.cpp iface.cpp json_min.cpp selfupdate.cpp $(LIB_DIRS) $(LIBS)

sanitize: $(TESTBIN_SAN)
	./$(TESTBIN_SAN)

version:
	@echo "$(TARGET) v$(VERSION)"

# Padrão na pasta do usuário (sem sudo), para o `ddns_manager update`
# conseguir se substituir. Outro destino: sudo make install BINDIR=/usr/local/bin
BINDIR ?= $(HOME)/.local/bin

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET) $(TARGET).exe $(TESTBIN) $(TESTBIN_SAN)
	rm -rf ddns_test_tmp_*
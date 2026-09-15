# Makefile — build for the ITB Lua binding (Lua 5.4 C module).
#
# Targets:
#   all (default):  lua/libitb3_lua.so — the C module, loadable via require "itb3".
#   libitb3.so:      rebuilds the underlying Go shared library into ITB_DIST.
#   test:           builds + runs tests/test_itb.lua.
#   bench:          builds + runs bench/bench.lua.
#   clean:          removes every generated artefact.
#
# Variables (override on the command line):
#   CC        C compiler                   (default: cc)
#   LUA       Lua 5.4 interpreter          (default: lua5.4)
#   LUA_INC   Lua 5.4 header directory     (default: /usr/include/lua5.4)
#   ITB_DIST  path to libitb3.so + .h dir   (default: ../../dist/linux-amd64)
#
# The module is deliberately not linked against liblua: the hosting
# interpreter provides the Lua API symbols at load time (the standard
# Lua C-module convention, avoiding a second Lua state in-process).

CC       ?= cc
LUA      ?= lua5.4
LUA_INC  ?= /usr/include/lua5.4
ITB_DIST ?= ../../dist/linux-amd64

WARN   = -Wall -Wextra -Wshadow -Wformat=2 -Wnull-dereference \
         -Wmissing-prototypes -Wstrict-prototypes -Werror
CFLAGS = -std=c11 -O2 -g $(WARN) -fstack-protector-strong -fPIC \
         -I$(LUA_INC) -isystem $(ITB_DIST)
RPATH   = $(abspath $(ITB_DIST))
LDFLAGS = -L$(ITB_DIST) -Wl,-rpath,$(RPATH)

LUA_ENV = LUA_PATH="$(CURDIR)/lua/?.lua;;" LUA_CPATH="$(CURDIR)/lua/?.so;;"

all: lua/libitb3_lua.so

lua/libitb3_lua.so: c_src/itb3_lua.c
	$(CC) $(CFLAGS) -shared -o $@ $< $(LDFLAGS) -litb3

# ---- Underlying Go shared library -----------------------------------
libitb3.so:
	cd ../.. && go build -trimpath -buildmode=c-shared \
	    -o dist/linux-amd64/libitb3.so ./cmd/cshared

# ---- Tests -----------------------------------------------------------
test: all
	$(LUA_ENV) $(LUA) tests/test_itb.lua

# ---- Benchmarks -------------------------------------------------------
bench: all
	$(LUA_ENV) $(LUA) bench/bench.lua

clean:
	rm -f lua/libitb3_lua.so

.PHONY: all libitb3.so test bench clean

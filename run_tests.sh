#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Lua binding. Builds the
# C module via build.sh, then runs the assert-based test suite under
# the Lua 5.4 interpreter.
#
# Usage:
#   ./run_tests.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

LUA="${LUA:-lua5.4}"
if ! command -v "$LUA" >/dev/null 2>&1; then
    LUA=lua
fi

export LUA_PATH="$PWD/lua/?.lua;;"
export LUA_CPATH="$PWD/lua/?.so;;"

exec "$LUA" tests/test_itb.lua

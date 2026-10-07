#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Lua binding:
# runs the utility with every argument passed through. The utility is
# pure Lua over the binding's C module, so there is nothing to compile
# here; build.sh owns libitb3.so, lua/libitb3_lua.so and the syntax
# check over the sources.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

exec lua5.4 loop/main.lua "$@"

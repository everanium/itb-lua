#!/usr/bin/env bash
#
# One-step build for the Lua binding: (re)builds libitb3.so if absent (or
# when ITB_REBUILD_LIBITB3=1), then compiles the Lua 5.4 C module
# lua/libitb3_lua.so. Prerequisites (Go, gcc, make, Lua 5.4 headers) must be
# installed separately; see README.md "Prerequisites".
#
# Every artefact this binding owns is removed before the build, so
# nothing in the tree predates the invocation. lua/libitb3_lua.so is
# also what eitb/eitb loads, so eitb is rebuilt by the same step.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's SIMD asm kernels
#                          # (use on hosts without AVX-512+VL)
#
# Environment:
#   ITB_SKIP_CLEAN=1       # keep existing artefacts (fast iteration)
#   ITB_KEEP_DOWNLOADS=1   # keep fetched dependency trees

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

# ---- artefact wipe ---------------------------------------------------
# The build starts from nothing: every artefact this binding owns is
# removed before anything is rebuilt, so no output can predate this
# invocation. ITB_SKIP_CLEAN=1 skips the wipe for fast iteration.
#
# Fetched dependency trees and registry-resolved lock files need network
# to restore, so ITB_KEEP_DOWNLOADS=1 preserves them. That is the weaker
# guarantee: a stale dependency can still mask breakage, and only the
# artefacts this binding compiles itself are then known to be fresh.
#
# Deletion safety: clean_target takes a path relative to this binding's
# own directory. An empty path, an absolute path, or one containing ".."
# is refused outright, and the resolved target is re-checked to lie
# inside the binding directory before removal -- so the wipe cannot
# reach the shared dist/linux-amd64/libitb3.so, another binding, or
# anything else outside this directory. Every removal is logged first.
BINDING_DIR="$(pwd -P)"

# Subtrees, relative to this binding, that a pattern sweep must not
# descend into. A dependency tree preserved by ITB_KEEP_DOWNLOADS sits
# inside this directory, so without this the sweep would reach into the
# very tree the flag is there to protect.
CLEAN_PRUNE=()

clean_target() {
    local rel="$1" abs res
    case "$rel" in
        ""|/*|*..*)
            echo "[clean] refusing unsafe target: '$rel'" >&2
            exit 1
            ;;
    esac
    abs="$BINDING_DIR/$rel"
    [ -e "$abs" ] || [ -L "$abs" ] || return 0
    res="$(readlink -f "$abs")"
    case "$res" in
        "$BINDING_DIR"/*) ;;
        *)
            echo "[clean] refusing target outside $BINDING_DIR: $res" >&2
            exit 1
            ;;
    esac
    echo "[clean] rm -rf $abs"
    rm -rf "$abs"
}

# Remove every entry matching a name pattern anywhere below this
# binding's directory, skipping the CLEAN_PRUNE subtrees. Matches are
# collected before the first removal so the walk is not racing the
# deletions.
clean_tree() {
    local pattern="$1" hit prune
    local -a args=("$BINDING_DIR") hits=()
    for prune in ${CLEAN_PRUNE+"${CLEAN_PRUNE[@]}"}; do
        args+=(-path "$BINDING_DIR/$prune" -prune -o)
    done
    args+=(-name "$pattern" -print0)
    while IFS= read -r -d '' hit; do
        hits+=("$hit")
    done < <(find "${args[@]}")
    for hit in "${hits[@]}"; do
        clean_target "${hit#"$BINDING_DIR"/}"
    done
}

if [[ "${ITB_SKIP_CLEAN:-0}" == "1" ]]; then
    echo "==> ITB_SKIP_CLEAN=1: keeping the existing artefacts"
else
    echo "==> removing the artefacts owned by this binding"
    # The compiled C module is hunted by pattern rather than by its one
    # expected path, so a module left behind under any earlier name goes
    # too and cannot be picked up by LUA_CPATH.
    clean_tree '*.so'
    clean_tree '*.o'
    clean_target 'build'
    clean_target 'bench/build'
    # The binding declares no fetched dependency tree, so there is
    # nothing for ITB_KEEP_DOWNLOADS to preserve; the wipe above is
    # already the full guarantee.
fi

if [[ ! -f "$DIST_DIR/libitb3.so" || "${ITB_REBUILD_LIBITB3:-0}" == "1" || ${#TAGS[@]} -gt 0 ]]; then
    echo "==> building libitb3.so${TAGS:+ (with ${TAGS[*]})}"
    (cd "$REPO_ROOT" && go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
        -o dist/linux-amd64/libitb3.so ./cmd/cshared)
else
    echo "==> libitb3.so present; skipping Go rebuild (set ITB_REBUILD_LIBITB3=1 to force)"
fi

echo "==> compiling the Lua C module lua/libitb3_lua.so (also the module eitb loads)"
make -s all

if [[ ! -f lua/libitb3_lua.so ]]; then
    echo "build.sh: lua/libitb3_lua.so was not produced" >&2
    exit 1
fi

echo "==> syntax-checking the Lua sources, the tests, the bench, eitb and loop"
LUAC="${LUAC:-luac5.4}"
if ! command -v "$LUAC" >/dev/null 2>&1; then
    LUAC=luac
fi
# The loop utility and the other Lua sources compile to nothing on
# disk, so the build's part in owning them is proving they parse: -p
# checks a chunk and writes no output. A stale artefact is impossible
# where there is no artefact, which is why the wipe above needs no
# entry for them.
"$LUAC" -p lua/*.lua tests/*.lua bench/*.lua eitb/*.lua loop/*.lua

echo "==> ready: ./run_tests.sh"

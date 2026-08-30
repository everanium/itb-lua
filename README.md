# ITB Lua Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`), packaged as a plain Lua 5.4 C module (`lua_State`
API; no LuaJIT, no FFI library). The compiled `itb.so` module links
`libitb.so` directly, and every hash-name / MAC-name / cipher-name /
profile-name is an opaque string passed through to Go for validation —
the binding carries no ITB construction logic. The public surface is a
`Pipeline` userdata (create / open / rekey / close, Single Message
encrypt / decrypt, whole-buffer and incremental stream sessions), an opts
query-string builder, `register_profile`, and the Go runtime knobs.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc make lua54
```

`lua54` provides the Lua 5.4 interpreter (`lua5.4`) and the headers at
`/usr/include/lua5.4`. Generic Linux: any Lua 5.4 installation works —
override `LUA` (interpreter) and `LUA_INC` (header directory) on the
`make` command line.

## Build

The convenience driver builds `libitb.so` (only when absent — set
`ITB_REBUILD_LIBITB=1` to force a Go rebuild) and compiles the C
module in one step:

```bash
./bindings/lua/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/lua && make all      # produces lua/itb.so
```

The module embeds an rpath to the repository's `dist/linux-amd64`
directory, so `libitb.so` resolves without `LD_LIBRARY_PATH`; pass
`ITB_DIST=<dir>` to `make` to link against a differently-located
build. The module is deliberately not linked against liblua — the
hosting interpreter provides the Lua API symbols at load time (the
standard Lua C-module convention).

## Module resolution

`require "itb"` resolves through the standard Lua search:

- With `LUA_PATH` pointing at `bindings/lua/lua/?.lua`, the sugar
  module `lua/itb.lua` loads first; it locates the compiled `itb.so`
  next to itself via `package.loadlib` and re-exports the C surface
  plus the pure-Lua helpers (`opts`, `tohex` / `fromhex`, `pump`).
- With only `LUA_CPATH` pointing at `bindings/lua/lua/?.so`, the C
  core loads directly; its surface is complete on its own (the sugar
  helpers are then unavailable).

The run scripts set both paths.

## Usage example

```lua
local itb = require "itb"

local sender = itb.create("singlemsg-triple-mac-v1")
local receiver = itb.open("singlemsg-triple-mac-v1", sender:blob())

local wire = sender:encrypt_message("any text or binary data")
local plain = receiver:decrypt_message(wire)
assert(plain == "any text or binary data")

sender:free()
receiver:free()
```

`itb.opts` overrides the profile default per call (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette); the
table is rendered into the URL-query string libitb consumes:

```lua
local opts = itb.opts({ chunk_size = 65536, with_wrapper = false })
local sender = itb.create("singlemsg-triple-mac-v1", opts)
local receiver = itb.open("singlemsg-triple-mac-v1", sender:blob(), opts)
```

`pipe:rekey(perm, wrap)` rotates the parallax + wrapper masters
mid-session (the eight ITB seeds and MAC key are fixed for the
session lifetime by design); the receiver picks up the new masters
through a fresh `sender:blob()` handshake:

```lua
sender:rekey(string.rep("\x11", 32), string.rep("\x22", 32))
local receiver = itb.open("singlemsg-triple-mac-v1", sender:blob())
```

`Pipeline` and stream-session userdata are to-be-closed values, so a
`local pipe <close> = itb.create(...)` declaration frees the Go-side
handle deterministically at scope exit (garbage collection via `__gc`
covers the plain-local path). Lua strings are the byte-buffer type
throughout: inputs and outputs are ordinary (possibly
embedded-zero-carrying) Lua strings.

Incremental streaming:

```lua
local pipe <close> = itb.create("streaming-noaead-triple-v1")
local sess <close> = pipe:encrypt_stream()
sess:write(part1)
sess:write(part2)
local wire = sess:drain_all()      -- finish + drain in one call
```

The explicit loop form is `write` / `finish` / `read` (`finish` is the
end-of-input signal — named so because `end` is a Lua keyword);
`read([max])` returns `chunk, finished` and never blocks before
`finish`. The `itb.pump(sess, read_fn, write_fn)` helper moves bytes
through a session with bounded memory. A stream session holds a
reference to its parent `Pipeline` in its uservalue, so the Lua GC
cannot collect the Pipeline while the session is live.

Errors are raised as objects — tables `{status=<int>, label=<string>,
message=<string>}` with a `__tostring` metamethod — so `pcall` callers
branch on `err.status` against the `itb.status` constant table:

```lua
local ok, err = pcall(function() return itb.create("no-such-profile") end)
assert(err.status == itb.status.BAD_INPUT)
```

Options are URL-query strings built with `itb.opts{...}` (snake_case
keys map onto the Go opts grammar; unknown keys pass through verbatim
for the register-profile grammar):

```lua
local opts = itb.opts({ nonce_bits = 512, key_bits = 1024, chunk_size = 65536 })
local pipe = itb.create("streaming-aead-triple-mac-v1", opts)
```

Go runtime knobs: `itb.set_memory_limit(bytes)` and
`itb.set_gc_percent(pct)` (negative values query without changing).
`itb.hashes()` returns the shipped hash primitive roster in canonical
registry order; `itb.profiles()` returns the built-in Triple profile
names.

## Testing

```bash
./bindings/lua/run_tests.sh
```

Assert-based suite (no external test framework): version and roster
checks, Single Message and incremental Streaming round trips, the pump
helper, a > 1 MiB payload, error mapping (unknown profile, unknown
opts key, tampered wire, closed Pipeline, duplicate profile
registration), rekey blob refresh, the GC parent-pin, and the opts /
hex helpers.

## Benchmarking

```bash
./bindings/lua/run_bench.sh                       # canonical 5 s per case
ITB_BENCH_MIN_SEC=1 ./bindings/lua/run_bench.sh   # quick smoke
```

Single Message encrypt and incremental Streaming encrypt (No MAC
profiles) at 1 MiB / 16 MiB / 64 MiB, configured through the fleet's
canonical env vars (`ITB_INNER_HASH`, `ITB_KEY_BITS`,
`ITB_NONCE_BITS`, `ITB_WITH_PARALLAX`, `ITB_WITH_WRAPPER`,
`ITB_PROFILE`, `ITB_BENCH_MIN_SEC`); the harness caps the Go runtime
via `itb.set_memory_limit(512 * 1024 * 1024)` and
`itb.set_gc_percent(20)`. See `bindings/BENCH.md` for the fleet-wide
configuration authority and comparison tables.

## eitb CLI

```bash
./bindings/lua/eitb/eitb version
./bindings/lua/eitb/eitb hashes
./bindings/lua/eitb/eitb profiles
./bindings/lua/eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.itb  2> blob.hex
./bindings/lua/eitb/eitb decrypt singlemsg-triple-mac-v1 "$(cat blob.hex)" out.itb back.bin
```

`encrypt` prints the session blob to stderr as hex; feed that hex back
to `decrypt` on the receiving side.

## Limitations

- **Plain Lua 5.4, no LuaJIT.** Every binding call crosses one C-Lua
  trampoline; with Lua's immutable strings each buffer also crosses by
  copy in both directions. Single Message throughput at large payloads
  sits close to the rest of the binding fleet; the multi-call
  Streaming shape pays proportionally more per-call overhead.
- **Strings as buffers.** There is no zero-copy path; extremely
  allocation-sensitive callers should size `read(max)` to their chunk
  cadence and reuse Lua-side accumulation patterns (`table.concat`).
- **`finish`, not `end`.** The stream end-of-input method is named
  `finish` because `end` is a reserved word in Lua.
- **`itb.profiles()` is a mirror.** The C ABI exposes no profile
  enumeration; the returned list mirrors the built-in profile registry
  and does not include profiles added at runtime via
  `register_profile`.
- **Streaming decrypt caveat.** Chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The binding exposes the Triple Pipeline surface only; the Low-Level
  Go-native configuration surface is not exported.

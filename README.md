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
`Pipeline` userdata (create / load / load_f / save / save_f / rekey /
max_workers / close, Single Message encrypt / decrypt, whole-buffer
and incremental stream sessions), an opts query-string builder for
`create`, the profile-catalogue functions (`inspect` / `register` /
`lookup` / `profiles`), and the Go runtime knobs.

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
local receiver = itb.load(sender:save())

local wire = sender:encrypt_message("any text or binary data")
local plain = receiver:decrypt_message(wire)
assert(plain == "any text or binary data")

sender:free()
receiver:free()

-- File-backed equivalent (persist across processes):
-- local sender = itb.create("singlemsg-triple-mac-v1")
-- sender:save_f("session.blob")
-- local receiver = itb.load_f("session.blob")
```

`itb.opts` overrides the profile default at `create` (chunk size,
outer cipher, parallax on/off, wrapper on/off, MAC name, palette,
worker cap); the table is rendered into the URL-query string libitb
consumes. The resolved shape is written into the blob, so the
receiver loads it with no opts of its own:

```lua
local opts = itb.opts({ chunk_size = 65536, with_wrapper = false })
local sender = itb.create("singlemsg-triple-mac-v1", opts)
local receiver = itb.load(sender:save())
```

`pipe:rekey(perm, wrap)` rotates the parallax + wrapper masters
mid-session (the eight ITB seeds and MAC key are fixed for the
session lifetime by design) and returns the refreshed blob; the
receiver picks up the new masters through a fresh `load`:

```lua
local rotated = sender:rekey(string.rep("\x11", 32), string.rep("\x22", 32))
local receiver = itb.load(rotated)
```

## Persisting sessions

The blob is self-describing: it carries the profile record (mode,
width, primitives, key bits, MAC, layer switches) alongside the key
material, so a session reopens from the blob alone.

```lua
local blob = sender:save()                  -- current blob (Lua string)
sender:save_f("session.blob")               -- written by libitb, mode 0600
local receiver = itb.load(blob)             -- reopen from bytes
local receiver = itb.load_f("session.blob") -- reopen from file
local receiver = itb.load(blob, perm, wrap) -- override the masters
local record = itb.inspect(blob)            -- profile record, no Pipeline
```

`itb.inspect` returns the profile record as the JSON text libitb
emits (keys `name`, `mode`, `width`, `hash`, `hashes`, `keybits`,
`mac`, `tagstub`, `chunk`, `wrapper`, `outer`, `parallax`, `palette`,
`segment`; absent keys are optional fields at their zero value) —
Lua ships no JSON codec, so the text is handed over verbatim for the
caller's own decoder.

The shipped `itb3` command-line utility (see `cmd/itb3`) generates
session blobs on disk (JSON files) that this binding reopens through
`itb.load_f`, and also encrypts / decrypts files or stdio streams from
the shell. It is the openssl-style entry point for ITB; the binding is
the programmatic entry point.

Load works for blobs generated with shipped primitives (every entry
in the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to `load` such a blob through
this binding raises an error object with
`err.status == itb.status.RECIPE_PRIMITIVE_UNKNOWN`.

## Profile registry

```lua
itb.profiles()                              -- sorted array of names
itb.lookup("singlemsg-triple-mac-v1")       -- record JSON; unknown -> UNKNOWN_PROFILE
itb.register("my-profile", [[{
  "mode": "singlemsg-nomac",
  "width": 256,
  "hashes": ["blake3", "blake2s", "areion256", "blake2b256",
             "chacha20", "blake3", "blake2s", "areion256"],
  "keybits": 1024,
  "parallax": false,
  "wrapper": false
}]])
local sender = itb.create("my-profile")
```

`itb.register` takes the same JSON record shape `itb.inspect` /
`itb.lookup` return; a `name` key inside it, if present, must be
empty or equal to the name argument. Every rule — name pattern,
reserved prefixes, field constraints, primitive names — is enforced
by libitb; a duplicate name raises `itb.status.PROFILE_EXISTS`.

## Runtime tuning

`pipe:max_workers(n)` sets the worker cap on a live Pipeline
(`n <= 0` selects auto, values above 256 are clamped). The cap is
per-machine tuning and is never written to the blob, so the receiver
may pick its own worker cap after `load`. The `max_workers` opts key
sets the same cap at `create`.

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
assert(err.status == itb.status.UNKNOWN_PROFILE)
```

Options are URL-query strings built with `itb.opts{...}` (snake_case
keys map onto the Go opts grammar; unknown keys pass through
verbatim):

```lua
local opts = itb.opts({ nonce_bits = 512, key_bits = 1024, chunk_size = 65536 })
local pipe = itb.create("streaming-aead-triple-mac-v1", opts)
```

`itb.profiles()` returns every registered Triple profile name (shipped
catalogue plus `itb.register` additions), sorted.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass a negative value to
query without changing. Long-running or allocation-heavy workloads
(benchmarks, bulk encryption) should set both — without a soft cap +
aggressive GC the Go scratch heap grows unboundedly under allocation
churn:

```lua
itb.set_memory_limit(512 * 1024 * 1024) -- 512 MiB soft cap
itb.set_gc_percent(20)                  -- aggressive GC
```

## Testing

```bash
./bindings/lua/run_tests.sh
```

Assert-based suite (no external test framework): version check, Single
Message and incremental Streaming round trips, the pump helper, a
> 1 MiB payload, error mapping (unknown profile, unknown opts key,
tampered wire, closed Pipeline, duplicate profile registration), rekey
blob refresh, save / load persistence (in memory and through a file),
inspect / lookup / profiles, the worker cap, the GC parent-pin, and
the opts / hex helpers.

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

## eitb utility

```bash
./bindings/lua/eitb/eitb version
./bindings/lua/eitb/eitb profiles
./bindings/lua/eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.itb  2> blob.hex
./bindings/lua/eitb/eitb inspect "$(cat blob.hex)"
./bindings/lua/eitb/eitb decrypt singlemsg-triple-mac-v1 "$(cat blob.hex)" out.itb back.bin
```

`encrypt` prints the session blob (`pipe:save()`) to stderr as hex;
feed that hex back to `decrypt` on the receiving side, which reopens
the session with `itb.load` (the profile argument only routes Single
Message versus streaming).

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
- **Profile records are JSON text.** `itb.inspect` / `itb.lookup`
  return, and `itb.register` accepts, the record as the JSON string
  libitb exchanges; Lua ships no JSON codec, so decoding into a table
  is left to the caller's library of choice.
- **Streaming decrypt caveat.** Chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The binding exposes the Triple Pipeline surface only; the Low-Level
  Go-native configuration surface is not exported.

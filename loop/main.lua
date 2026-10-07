--- Long-run stress harness. The loop utility holds one Pipeline handle
--- per exercised cipher surface for minutes, hammers it with
--- encrypt -> decrypt -> compare round-trips, rotates the outer masters
--- and reopens the handle from its session blob on a schedule, and
--- reports whether the process survived with every byte intact. It is
--- the Lua binding's counterpart of the Go harness under tools/loop:
--- the same flags, the same round structure, the same summary in both
--- renderings.
---
--- The default shape is full production: the Streaming AEAD profile
--- with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner
--- hash, 1024-bit keys, and the compile-in 512-bit nonce width, driven
--- through a stream session for five minutes on 16 MiB plaintexts. The
--- worker's plaintext is CSPRNG-generated and held for the whole run,
--- so any cross-call state leakage inside the Pipeline surfaces as a
--- data mismatch rather than cancelling out.
---
--- A failure is one of two things. A cipher, rekey or load call that
--- returns a non-OK status is a worker error: the run stops, the
--- summary lists it, the verdict is FAIL and the exit code 1. A
--- round-trip that returns without error but with different bytes is a
--- data mismatch: the process terminates on the spot with exit code 3,
--- printing the worker, the iteration and the first differing offset,
--- and no summary — the state that produced the wrong bytes is the
--- evidence. A crash inside the shared library or the host runtime has
--- no exit code of its own here; surfacing it is what the utility is
--- for.
---
--- Usage:
---
---   lua5.4 loop/main.lua --duration 5m --goroutines 1 --shape stream \
---       --hash areion512 --mac hmac-blake3 --payload-size 16MB \
---       --memlimit auto --parallax on --wrapper on

-- Lua-specific. Running a script does not put its own directory on the
-- module search path, and the binding's Lua sources sit one level up,
-- so both are placed there explicitly rather than through an
-- environment variable the launcher would have to set — everything the
-- launcher contributes has to be part of what a reader runs by hand.
do
    local src = debug.getinfo(1, "S").source
    local path = src:match("^@(.*)$") or src
    local dir = path:match("^(.*)[/\\][^/\\]*$") or "."
    package.path = dir .. "/?.lua;" .. dir .. "/../lua/?.lua;" .. package.path
end

local itb = require "itb3"

local ops = require "ops"
local payload = require "payload"
local size = require "size"
local state = require "state"
local summary = require "summary"
local worker = require "worker"

local _ = ops  -- unit wiring: the worker unit drives maintenance

-- Profiles the shape-based pair is built against when --profile is
-- empty.
local DEFAULT_STREAM_PROFILE = "streaming-aead-triple-mac-v1"
local DEFAULT_MESSAGE_PROFILE = "singlemsg-triple-mac-v1"

-- The primitive supplied for the parallax palette and the outer cipher
-- when a profile leaves them unnamed. AES-CMAC is PRF-grade, so it is
-- sound outside the Interlocked Barrier, and it is the closest relative
-- of the AES-based inner primitive whose profiles need this fill.
local KEYSTREAM_FILL_CIPHER = "aescmac"

-- ------------------------------------------------------------------ --
-- Flags                                                               --
-- ------------------------------------------------------------------ --

local INT, INT64, UINT64, STRING, BOOL = 0, 1, 2, 3, 4

-- One command-line flag: its name, the type label the usage prints,
-- its kind, its default, and its help text. Values are validated after
-- the whole line is parsed. The table is in alphabetical order, which
-- is the order the usage prints.
local FLAGS = {
    { "barrier-fill", "int", INT, 0,
        "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)" },
    { "blob-cycle-every", "int", INT64, 0,
        "reopen each pipeline from its session blob every N iterations per worker; 0 = never" },
    { "blob-mode", "int", INT, 1,
        "container floor sizing mode: 1 (per-region, default) | 2 (per-container)" },
    { "chunk-size", "string", STRING, "0",
        "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape" },
    { "drbg", "string", STRING, "",
        "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)" },
    { "duration", "duration", STRING, "5m",
        "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0" },
    { "gogc", "int", INT, 0,
        "GC trigger percentage; 0 = leave the runtime default" },
    { "gomaxprocs", "int", INT, 0,
        "Go runtime GOMAXPROCS override; 0 = inherit from the environment" },
    { "goroutines", "int", INT, 3,
        "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1" },
    { "hash", "string", STRING, "areion512",
        "inner ITB hash primitive name" },
    { "iterations", "int", INT64, 0,
        "fixed per-worker iteration count; 0 = duration-based" },
    { "json-output", "", BOOL, false,
        "print the final summary as one compact JSON object instead of log lines" },
    { "key-bits", "int", INT, 0,
        "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)" },
    { "mac", "string", STRING, "hmac-blake3",
        "MAC primitive name" },
    { "memlimit", "string", STRING, "auto",
        "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the "
        .. "runtime has no limit) or a size (e.g. 512MB)" },
    { "memprofile", "string", STRING, "",
        "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none" },
    { "nonce-bits", "int", INT, 0,
        "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)" },
    { "parallax", "string", STRING, "on",
        "parallax layer: on | off" },
    { "payload-mode", "string", STRING, "fixed",
        "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii" },
    { "payload-size", "string", STRING, "16MB",
        "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)" },
    { "profile", "string", STRING, "",
        "exercise this single registered triple profile (overrides --shape with the profile's "
        .. "surface); empty = shape-based profile pair" },
    { "rekey-every", "int", INT64, 0,
        "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never" },
    { "seed", "uint", UINT64, 0,
        "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline "
        .. "keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts" },
    { "shape", "string", STRING, "stream",
        "cipher surface to exercise: stream | message | stream_one_shot | both" },
    { "wrapper", "string", STRING, "on",
        "wrapper layer: on | off" },
}

local INT32_MAX = 2147483647
local UINT64_MAX_DEC = "18446744073709551615"

-- Renders a 64-bit pattern as its unsigned decimal. Lua-specific: Lua
-- integers are signed, so a seed above 2^63 - 1 is held as a negative
-- pattern and %d would print it as such; the unsigned division below
-- recovers the decimal the operator typed.
local function u64_dec(x)
    if x >= 0 then
        return string.format("%d", x)
    end
    local q = (x >> 1) // 5
    local r = x - q * 10
    return string.format("%d%d", q, r)
end

local function err(text)
    state.err_line(text)
end

local function usage()
    local out = { "Usage of loop:\n" }
    for _, f in ipairs(FLAGS) do
        local name, label, kind, default, help = f[1], f[2], f[3], f[4], f[5]
        out[#out + 1] = "  -" .. name .. (label ~= "" and " " .. label or "") .. "\n"
        local line = "    \t" .. help
        -- The default-value suffix follows the shape a Go flag set
        -- prints: an integer default only when it is non-zero, a string
        -- default only when it is non-empty.
        if kind == INT and default ~= 0 then
            line = line .. string.format(" (default %d)", default)
        elseif kind == STRING and default ~= "" then
            line = line .. string.format(' (default "%s")', default)
        end
        out[#out + 1] = line .. "\n"
    end
    io.stderr:write(table.concat(out))
    io.stderr:flush()
end

-- Parses an unsigned 64-bit decimal into the matching integer bit
-- pattern; nil when the digits do not form one.
local function parse_u64(s)
    if s == "" or s:find("[^0-9]") then
        return nil
    end
    local trimmed = s:gsub("^0+", "")
    if trimmed == "" then
        return 0
    end
    if #trimmed > 20 or (#trimmed == 20 and trimmed > UINT64_MAX_DEC) then
        return nil
    end
    local n = 0
    for i = 1, #trimmed do
        n = n * 10 + (trimmed:byte(i) - 0x30)
    end
    return n
end

-- Parses one value into its flag slot; nil on a malformed value.
local function assign(kind, value)
    if kind == INT or kind == INT64 then
        local sign, body = value:match("^([+-]?)(.*)$")
        if body == "" or body:find("[^0-9]") then
            return nil
        end
        local n = math.tointeger(tonumber(body, 10))
        if n == nil then
            return nil
        end
        if sign == "-" then
            n = -n
        end
        if kind == INT and (n > INT32_MAX or n < -INT32_MAX) then
            return nil
        end
        return n
    end
    if kind == UINT64 then
        local body = value:sub(1, 1) == "+" and value:sub(2) or value
        return parse_u64(body)
    end
    if kind == STRING then
        return value
    end
    if value == "true" then
        return true
    end
    if value == "false" then
        return false
    end
    return nil
end

-- Parses argv into the raw flag values. Accepts -name value,
-- --name value, -name=value and --name=value; a boolean flag takes no
-- value unless given as -name=true / -name=false. Returns (0, values),
-- (1, nil) for -h / --help (usage printed), or (-1, nil) after printing
-- the error.
local function parse_argv(argv)
    local raw = {}
    local by_name = {}
    for _, f in ipairs(FLAGS) do
        raw[f[1]] = f[4]
        by_name[f[1]] = f[3]
    end
    local i = 1
    while i <= #argv do
        local arg = argv[i]
        if arg:sub(1, 1) ~= "-" or arg == "-" then
            err("unexpected positional arguments: [" .. arg .. "]")
            return -1, nil
        end
        local name = arg:sub(1, 2) == "--" and arg:sub(3) or arg:sub(2)
        if name == "h" or name == "help" then
            usage()
            return 1, nil
        end
        local value = nil
        local eq = name:find("=", 1, true)
        if eq ~= nil then
            value = name:sub(eq + 1)
            name = name:sub(1, eq - 1)
        end
        local kind = by_name[name]
        if kind == nil then
            err("flag provided but not defined: -" .. name)
            usage()
            return -1, nil
        end
        if value == nil then
            if kind == BOOL then
                value = "true"
            elseif i < #argv then
                i = i + 1
                value = argv[i]
            else
                err("flag needs an argument: -" .. name)
                return -1, nil
            end
        end
        local parsed = assign(kind, value)
        if parsed == nil then
            err(string.format('invalid value "%s" for flag -%s', value, name))
            return -1, nil
        end
        raw[name] = parsed
        i = i + 1
    end
    return 0, raw
end

local function parse_on_off(v)
    if v == "on" then
        return true
    end
    if v == "off" then
        return false
    end
    return nil
end

-- Whether name is in the shipped hash registry the binding enumerates.
local function hash_registered(name)
    local ok, names = pcall(itb.hash_names)
    if not ok then
        return false
    end
    for _, got in ipairs(names) do
        if got == name then
            return true
        end
    end
    return false
end

-- ------------------------------------------------------------------ --
-- Profile records                                                     --
-- ------------------------------------------------------------------ --

-- The binding hands a profile record back as its JSON text, and record
-- strings are restricted to [a-z0-9-], so a quoted run is one complete
-- value and a key probe is a substring search — the same reading the C
-- reference does.
local function record_has(json, key)
    return json:find('"' .. key .. '":', 1, true) ~= nil
end

local function record_int(json, key)
    local v = json:match('"' .. key .. '":(-?%d+)')
    return math.tointeger(tonumber(v or "0")) or 0
end

local function record_str(json, key)
    local v = json:match('"' .. key .. '":"([^"]*)"')
    if v == nil or v == "" then
        return "-"
    end
    return v
end

local function record_bool(json, key)
    return json:find('"' .. key .. '":true', 1, true) ~= nil
end

-- Resolves a registered profile to the shape family its record's mode
-- exposes by reading the record through the binding's lookup: a mode
-- beginning with "streaming" exposes the stream surfaces, one beginning
-- with "singlemsg" the message surface, "blob-only" none. Prints the
-- validation message and returns nil on rejection.
local function profile_surface(name)
    local ok, json = pcall(itb.lookup, name)
    if not ok then
        err(string.format('--profile "%s" is not a registered triple profile', name))
        return nil
    end
    local mode = record_str(json, "mode")
    if mode:sub(1, 9) == "streaming" then
        return state.SHAPE_STREAM
    end
    if mode:sub(1, 9) == "singlemsg" then
        return state.SHAPE_MESSAGE
    end
    err(string.format('--profile "%s" carries no cipher surface (blob-only mode)', name))
    return nil
end

-- Applies a --profile's surface to the requested shape: a
-- message-surface profile forces message; a stream-surface profile
-- keeps stream or stream_one_shot as requested and turns message or
-- both into stream.
local function narrow_shape(requested, surface)
    if surface == state.SHAPE_MESSAGE then
        return state.SHAPE_MESSAGE
    end
    if requested == state.SHAPE_STREAM_ONE_SHOT then
        return state.SHAPE_STREAM_ONE_SHOT
    end
    return state.SHAPE_STREAM
end

-- ------------------------------------------------------------------ --
-- Validation                                                          --
-- ------------------------------------------------------------------ --

-- Builds the resolved config from argv. Returns (0, cfg), (1, cfg) for
-- help, or (-1, cfg) after printing "loop: <message>" for the first
-- failing rule.
local function parse_flags(argv)
    local cfg = state.new_config()
    local rc, raw = parse_argv(argv)
    if rc ~= 0 then
        return rc, cfg
    end

    local duration_ns = size.parse_duration(raw["duration"])
    if duration_ns == nil or duration_ns <= 0 then
        err(string.format("--duration must be positive, got %s", raw["duration"]))
        return -1, cfg
    end
    cfg.duration_ns = duration_ns
    cfg.iterations = raw["iterations"]
    if cfg.iterations < 0 then
        err(string.format("--iterations must be >= 0, got %d", cfg.iterations))
        return -1, cfg
    end
    local goroutines = raw["goroutines"]
    if goroutines < 1 or goroutines > state.MAX_WORKERS then
        err(string.format("--goroutines must be in 1..%d, got %d",
            state.MAX_WORKERS, goroutines))
        return -1, cfg
    end
    -- Concurrency mode. This binding runs single, so the requested
    -- count is recorded and the effective one clamped to 1; the summary
    -- reports both so a fleet report cannot read a clamped run as a
    -- concurrent one.
    cfg.workers_requested = goroutines
    cfg.workers = 1
    local shape = state.parse_shape(raw["shape"])
    if shape == nil then
        err(string.format(
            '--shape must be stream | message | stream_one_shot | both, got "%s"',
            raw["shape"]))
        return -1, cfg
    end
    cfg.shape = shape
    if not hash_registered(raw["hash"]) then
        err(string.format('--hash "%s" is not a registered hash primitive', raw["hash"]))
        return -1, cfg
    end
    cfg.hash = raw["hash"]
    -- Validated by Init: the C ABI enumerates no MAC names.
    cfg.mac = raw["mac"]
    local payload_bytes = size.parse_size(raw["payload-size"])
    if payload_bytes == nil then
        err(string.format('--payload-size: invalid size "%s"', raw["payload-size"]))
        return -1, cfg
    end
    cfg.payload = payload_bytes
    if cfg.payload < 1 then
        err("--payload-size must be at least 1 byte")
        return -1, cfg
    end
    if raw["memlimit"] == "auto" then
        cfg.memlimit_auto = true
        cfg.memlimit = cfg.workers <= 3 and (1 << 30) or (256 << 20)
    else
        local memlimit = size.parse_size(raw["memlimit"])
        if memlimit == nil then
            err(string.format('--memlimit: invalid size "%s"', raw["memlimit"]))
            return -1, cfg
        end
        cfg.memlimit = memlimit
    end
    cfg.gogc = raw["gogc"]
    if cfg.gogc < 0 then
        err(string.format("--gogc must be >= 0, got %d", cfg.gogc))
        return -1, cfg
    end
    local parallax = parse_on_off(raw["parallax"])
    if parallax == nil then
        err(string.format('--parallax must be on | off, got "%s"', raw["parallax"]))
        return -1, cfg
    end
    cfg.parallax = parallax
    local wrapper = parse_on_off(raw["wrapper"])
    if wrapper == nil then
        err(string.format('--wrapper must be on | off, got "%s"', raw["wrapper"]))
        return -1, cfg
    end
    cfg.wrapper = wrapper
    cfg.profile = raw["profile"]
    if cfg.profile ~= "" then
        local surface = profile_surface(cfg.profile)
        if surface == nil then
            return -1, cfg
        end
        cfg.shape = narrow_shape(cfg.shape, surface)
    end
    cfg.key_bits = raw["key-bits"]
    if cfg.key_bits ~= 0 and cfg.key_bits ~= 512 and cfg.key_bits ~= 1024
        and cfg.key_bits ~= 2048 then
        err(string.format(
            "--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got %d",
            cfg.key_bits))
        return -1, cfg
    end
    cfg.nonce_bits = raw["nonce-bits"]
    if cfg.nonce_bits ~= 0 and cfg.nonce_bits ~= 128 and cfg.nonce_bits ~= 256
        and cfg.nonce_bits ~= 512 then
        err(string.format(
            "--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got %d",
            cfg.nonce_bits))
        return -1, cfg
    end
    cfg.blob_mode = raw["blob-mode"]
    if cfg.blob_mode ~= 1 and cfg.blob_mode ~= 2 then
        err(string.format(
            "--blob-mode must be 1 (per-region) | 2 (per-container), got %d",
            cfg.blob_mode))
        return -1, cfg
    end
    cfg.barrier_fill = raw["barrier-fill"]
    local fill_ok = { [0] = true, [1] = true, [2] = true, [4] = true,
        [8] = true, [16] = true, [32] = true }
    if not fill_ok[cfg.barrier_fill] then
        err(string.format(
            "--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got %d",
            cfg.barrier_fill))
        return -1, cfg
    end
    -- Validated by Init: the C ABI enumerates no DRBG names.
    cfg.drbg = raw["drbg"]
    local chunk_size = size.parse_size(raw["chunk-size"])
    if chunk_size == nil then
        err(string.format('--chunk-size: invalid size "%s"', raw["chunk-size"]))
        return -1, cfg
    end
    cfg.chunk_size = chunk_size
    cfg.gomaxprocs = raw["gomaxprocs"]
    if cfg.gomaxprocs < 0 then
        err(string.format("--gomaxprocs must be > 0 when specified, got %d",
            cfg.gomaxprocs))
        return -1, cfg
    end
    cfg.rekey_every = raw["rekey-every"]
    if cfg.rekey_every < 0 then
        err(string.format("--rekey-every must be >= 0, got %d", cfg.rekey_every))
        return -1, cfg
    end
    cfg.blob_cycle_every = raw["blob-cycle-every"]
    if cfg.blob_cycle_every < 0 then
        err(string.format("--blob-cycle-every must be >= 0, got %d",
            cfg.blob_cycle_every))
        return -1, cfg
    end
    local payload_mode = payload.parse_mode(raw["payload-mode"])
    if payload_mode == nil then
        err(string.format(
            '--payload-mode must be %s, got "%s"',
            table.concat(payload.NAMES, " | "), raw["payload-mode"]))
        return -1, cfg
    end
    cfg.payload_mode = payload_mode
    cfg.seed = raw["seed"]
    cfg.json_output = raw["json-output"]
    cfg.memprofile = raw["memprofile"]
    return 0, cfg
end

-- ------------------------------------------------------------------ --
-- Pipelines                                                           --
-- ------------------------------------------------------------------ --

-- Prints the construction line with the recipe read back from the blob
-- the Pipeline handed out, not echoed from the flags: every
-- construction override is proven to have reached the library by the
-- value the receiver would see. Record values that are empty (a No MAC
-- profile's MAC, a mixed profile's single hash) print as "-".
local function log_pipeline_initialised(profile, blob)
    local ok, json = pcall(itb.inspect, blob)
    if not ok then
        state.log_line(string.format(
            "pipeline initialised: profile=%s blob=%d bytes (inspect: %s)",
            profile, #blob, state.status_message(json)))
        return
    end
    local line = string.format(
        "pipeline initialised: profile=%s blob=%d bytes hash=%s key-bits=%d "
        .. "nonce-bits=%d barrier-fill=%d chunk-size=%d mac=%s parallax=%s wrapper=%s",
        profile, #blob, record_str(json, "hash"), record_int(json, "keybits"),
        record_int(json, "nonce_bits"), record_int(json, "barrier_fill"),
        record_int(json, "chunk"), record_str(json, "mac"),
        state.on_off(record_bool(json, "parallax")),
        state.on_off(record_bool(json, "wrapper")))
    local container_mode = record_int(json, "container_mode")
    if container_mode == 2 then
        line = line .. string.format(" container-mode=%d", container_mode)
    end
    local drbg = record_str(json, "drbg")
    if drbg ~= "-" then
        line = line .. " drbg=" .. drbg
    end
    state.log_line(line)
end

-- Returns a copy of a wrap-layer session blob whose inner blob's "mode"
-- field is set to target_mode (1 = per-region, 2 = per-container), or
-- nil when the inner blob or its mode field is not found. The wrap
-- layer's profile record carries its own "mode" (a string), so the
-- search starts at the inner blob ("ib"); both shipped modes are one
-- digit wide, so the blob length does not change and nothing before the
-- inner blob is touched.
local function edit_inner_blob_mode(blob, target_mode)
    local _, ib_end = blob:find('"ib":{', 1, true)
    if ib_end == nil then
        return nil
    end
    local _, mode_end = blob:find('"mode":', ib_end + 1, true)
    if mode_end == nil then
        return nil
    end
    local at = mode_end + 1
    if not blob:sub(at, at):match("^[12]$") or blob:sub(at + 1, at + 1):match("^%d$") then
        return nil
    end
    return blob:sub(1, at - 1) .. string.format("%d", target_mode) .. blob:sub(at + 1)
end

-- Folds a keystream primitive into opts for any layer the named profile
-- leaves unfilled but the operator asked for.
--
-- A profile built around a primitive that is safe only inside the
-- Interlocked Barrier ships with no parallax palette and no outer
-- cipher: both layers run outside the barrier, where that primitive
-- would stand bare, so the recipe leaves them unnamed rather than
-- naming a primitive that must not key them. Engaging either layer
-- therefore needs a keystream-capable primitive supplied from outside
-- the recipe; without it construction fails on a palette below its
-- minimum or an unnamed outer cipher, and the primitive that most
-- deserves stressing becomes the one that cannot be stressed with those
-- layers engaged.
--
-- Overrides fold into the resolved record the blob carries, so the
-- receiver rebuilds the same shape from the blob alone.
--
-- Returns 1 when a layer was filled, 0 when none needed it, -1 on a
-- lookup failure (message already printed).
local function fill_keystream_layers(name, opts, want_parallax, want_wrapper)
    local ok, json = pcall(itb.lookup, name)
    if not ok then
        err(string.format('--profile "%s" is not a registered triple profile', name))
        return -1
    end
    local filled = 0
    if want_parallax and not record_has(json, "palette") then
        opts.parallax_palette = { KEYSTREAM_FILL_CIPHER, KEYSTREAM_FILL_CIPHER,
            KEYSTREAM_FILL_CIPHER }
        if not record_has(json, "segment") then
            -- A recipe that never carried a palette never carried a
            -- segment size either, and the schedule rejects zero.
            opts.parallax_segment_size = 4093
        end
        filled = 1
    end
    if want_wrapper and not record_has(json, "outer") then
        opts.outer_cipher = KEYSTREAM_FILL_CIPHER
        filled = 1
    end
    return filled
end

-- Constructs one Pipeline against profile with every flag-carried
-- override in the opts string (zero values included — the shared
-- library treats zero as "profile default"), then obtains the Init blob
-- once through save: the binding's create entry does not hand the blob
-- back, and the bytes are the ones Init produced. Later blob reopens
-- use the retained blob; save is never called again.
local function build_pipeline(cfg, profile)
    local opts = {
        inner_hash = cfg.hash,
        mac_name = cfg.mac,
        with_parallax = cfg.parallax,
        with_wrapper = cfg.wrapper,
        key_bits = cfg.key_bits,
        nonce_bits = cfg.nonce_bits,
        barrier_fill = cfg.barrier_fill,
        drbg = cfg.drbg,
        chunk_size = cfg.chunk_size,
    }
    if cfg.profile ~= "" then
        local filled = fill_keystream_layers(cfg.profile, opts, cfg.parallax,
            cfg.wrapper)
        if filled < 0 then
            return nil
        end
        if filled > 0 then
            err(string.format(
                "%s leaves the requested keystream layers unnamed; %s supplied for them",
                cfg.profile, KEYSTREAM_FILL_CIPHER))
        end
    end
    local ok, pipe = pcall(itb.create, profile, itb.opts(opts))
    if not ok then
        err(string.format("Init(%s): %s", profile, state.status_detail(pipe)))
        return nil
    end
    local saved, blob = pcall(pipe.save, pipe)
    if not saved then
        err(string.format("Save(%s): %s", profile, state.status_detail(blob)))
        pipe:free()
        return nil
    end
    if cfg.blob_mode == 2 then
        -- The sizing mode is not an Opts knob: the Init blob is edited
        -- and the pipeline reopened from it, so the retained blob (the
        -- one blob-cycle reopens from) carries the edited mode.
        local edited = edit_inner_blob_mode(blob, 2)
        if edited == nil then
            err("rewrite blob mode: inner blob mode field not found")
            pipe:free()
            return nil
        end
        pipe:free()
        local loaded, fresh = pcall(itb.load, edited)
        if not loaded then
            err("reload Mode 2 blob: " .. state.status_detail(fresh))
            return nil
        end
        pipe, blob = fresh, edited
    end
    log_pipeline_initialised(profile, blob)
    return pipe, blob
end

-- ------------------------------------------------------------------ --
-- Run                                                                 --
-- ------------------------------------------------------------------ --

local function run(argv)
    local rc, cfg = parse_flags(argv)
    if rc == 1 then
        return 0
    end
    if rc ~= 0 then
        return 2
    end

    local r = state.new_run(cfg)

    -- Runtime shaping. A long run under allocation churn grows the Go
    -- heap inside the shared library without bound unless a soft limit
    -- paces the collector, so a limit is always in force: an explicit
    -- --memlimit is set as given, and auto caps the heap only when the
    -- runtime reports no limit at all (a limit already installed from
    -- the environment is left standing). The GC percentage and
    -- GOMAXPROCS are set only when their flag is non-zero — a zero flag
    -- skips the setter rather than calling it with zero, because zero
    -- is a real value to the GC-percent setter, and a call would clobber
    -- whatever the environment installed. All of it lands before any
    -- Pipeline exists so the baselines are taken under the shaped
    -- runtime, in the order heap limit, GC percent, GOMAXPROCS.
    if cfg.memlimit_auto then
        if itb.set_memory_limit(-1) == math.maxinteger then
            itb.set_memory_limit(cfg.memlimit)
        end
    else
        itb.set_memory_limit(cfg.memlimit)
    end
    cfg.memlimit = math.tointeger(itb.set_memory_limit(-1)) or cfg.memlimit
    if cfg.gogc > 0 then
        itb.set_gc_percent(cfg.gogc)
    end
    if cfg.gomaxprocs > 0 then
        itb.set_gomaxprocs(cfg.gomaxprocs)
    end

    state.log_line(string.format(
        "start: duration=%s iterations=%d goroutines=%d workers=%d "
        .. "concurrency=%s shape=%s hash=%s mac=%s payload=%s memlimit=%s "
        .. "parallax=%s wrapper=%s",
        size.human_duration(cfg.duration_ns), cfg.iterations,
        cfg.workers_requested, cfg.workers, state.CONCURRENCY,
        state.shape_name(cfg.shape), cfg.hash, cfg.mac,
        size.human_bytes(cfg.payload), size.human_bytes(cfg.memlimit),
        state.on_off(cfg.parallax), state.on_off(cfg.wrapper)))
    state.log_line(string.format(
        'overrides: profile="%s" key-bits=%d nonce-bits=%d chunk-size=%s '
        .. "barrier-fill=%d gomaxprocs=%d rekey-every=%d blob-cycle-every=%d "
        .. "payload-mode=%s seed=%s json-output=%s%s%s",
        cfg.profile, cfg.key_bits, cfg.nonce_bits,
        size.human_bytes(cfg.chunk_size), cfg.barrier_fill, cfg.gomaxprocs,
        cfg.rekey_every, cfg.blob_cycle_every,
        payload.mode_name(cfg.payload_mode), u64_dec(cfg.seed),
        cfg.json_output and "true" or "false",
        cfg.blob_mode ~= 1 and string.format(" blob-mode=%d", cfg.blob_mode) or "",
        cfg.drbg ~= "" and " drbg=" .. cfg.drbg or ""))
    state.log_line(string.format(
        "policy: microbatch-tiers=%s hashpool-starters=%s",
        state.policy_label(os.getenv("ITB_MICROBATCH_TIERS")),
        state.policy_label(os.getenv("ITB_HASHPOOL_STARTERS"))))

    -- Pipeline construction — one handle per exercised shape. stream
    -- and stream_one_shot share the streaming handle.
    r.stream_profile = cfg.profile ~= "" and cfg.profile or DEFAULT_STREAM_PROFILE
    r.msg_profile = cfg.profile ~= "" and cfg.profile or DEFAULT_MESSAGE_PROFILE
    if cfg.shape == state.SHAPE_STREAM or cfg.shape == state.SHAPE_STREAM_ONE_SHOT
        or cfg.shape == state.SHAPE_BOTH then
        local pipe, blob = build_pipeline(cfg, r.stream_profile)
        if pipe == nil then
            return 1
        end
        r.stream_pipe, r.stream_blob = pipe, blob
    end
    if cfg.shape == state.SHAPE_MESSAGE or cfg.shape == state.SHAPE_BOTH then
        local pipe, blob = build_pipeline(cfg, r.msg_profile)
        if pipe == nil then
            return 1
        end
        r.msg_pipe, r.msg_blob = pipe, blob
    end

    -- Allocation posture. The per-worker plaintext is built once and
    -- held for the whole run (rotating mode replaces it per iteration);
    -- the wire and round-trip buffers are the strings the binding
    -- returns per call and the collector reclaims them when the
    -- iteration drops them, and the pump loop accumulates its slices
    -- into one joined buffer per direction. Under the default fixed
    -- CSPRNG mode every worker's buffer is distinct, so cross-worker
    -- data crossover is detectable; pattern modes trade that property
    -- for content edge-case coverage.
    for i = 0, cfg.workers - 1 do
        local w = state.new_worker(i, r)
        w.payload_mode = cfg.payload_mode
        w.seeded = cfg.seed ~= 0
        w.rng = payload.seed_worker(cfg.seed, i)
        local ok, buf, rng = pcall(payload.fill, cfg.payload_mode, w.seeded,
            w.rng, cfg.payload)
        if not ok then
            err("payload alloc: " .. tostring(buf))
            return 1
        end
        w.plaintext, w.rng = buf, rng
        r.workers[#r.workers + 1] = w
    end

    r.pool_warmup = summary.pool_snapshot()
    r.pool_steady = r.pool_warmup
    if #r.pool_warmup == 0 then
        err("pool snapshot alloc failed")
        return 1
    end

    -- Graceful stop. SIGINT and SIGTERM would set a flag the run polls
    -- before every iteration, so a signal interrupts nothing mid-call:
    -- the in-flight encrypt / decrypt / compare completes and the
    -- partial summary prints. This binding installs no handler: Lua
    -- 5.4's standard library exposes no signal entry at all, so an
    -- interrupt keeps the interpreter's default disposition and the
    -- process dies where it stands, without a summary. The deviation is
    -- the library's, not the harness's — there is nothing in the
    -- language to hook.

    -- Warmup barrier. The worker runs one iteration before the clock
    -- starts, so the first-call costs (pool warm-up, lazy kernel
    -- dispatch, page faults on the payload buffer) fall outside the
    -- measured window, and the RSS and pool baselines taken here
    -- describe a process that has already run the whole cipher path
    -- once. With one worker the barrier is that worker's own first
    -- iteration; the rendezvous the shared-handle bindings need has no
    -- second party to wait for.
    local warmup_start = size.now_ns()
    local warmup_ok = worker.warmup(r.workers[1])
    r.rss_warmup, r.rss_peak = summary.read_rss()
    r.pool_warmup = summary.pool_snapshot()
    local warmup_ns = size.now_ns() - warmup_start
    state.log_line(string.format(
        "warmup: %d workers x 1 iter completed in %s (baseline rss=%s)",
        cfg.workers, size.human_duration(
            (warmup_ns + 50000000) // 100000000 * 100000000),
        size.human_bytes(r.rss_warmup)))

    r.start_ns = size.now_ns()
    r.finish_ns = r.start_ns
    if warmup_ok then
        worker.run_worker(r.workers[1])
    end
    r.finish_ns = size.now_ns()

    local elapsed_ns = r.finish_ns - r.start_ns
    local peak
    r.rss_final, peak = summary.read_rss()
    if peak > r.rss_peak then
        r.rss_peak = peak
    end
    r.pool_steady = summary.pool_snapshot()

    if cfg.memprofile ~= "" then
        local ok, res = pcall(itb.write_heap_profile, cfg.memprofile)
        if ok then
            state.log_line("memprofile: heap profile written to " .. cfg.memprofile)
        else
            err("memprofile: " .. state.status_message(res))
        end
    end

    local code = summary.final_summary(r, elapsed_ns)

    if r.stream_pipe ~= nil then
        r.stream_pipe:free()
    end
    if r.msg_pipe ~= nil then
        r.msg_pipe:free()
    end
    return code
end

-- A consumer that stops reading ends the run. The process dies from
-- SIGPIPE with status 141 and prints nothing — the reference behaviour,
-- and what anyone piping into head or less expects. Most managed
-- runtimes install a handler or ignore the signal at startup and have
-- to restore the default explicitly; a stock Lua 5.4 interpreter
-- installs nothing, so the default disposition is already in force when
-- the first line is written, and the language exposes no signal entry
-- with which to restore it in any case.

os.exit(run(arg), false)

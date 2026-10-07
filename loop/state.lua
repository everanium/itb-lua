--- Shared declarations of the loop stress harness: the cipher-surface
--- selectors, the concurrency mode this binding runs, the resolved
--- configuration and per-worker state constructors, and the output
--- helpers every unit logs through.
---
--- Lua-specific. `require` evaluates a module the first time it is
--- named, so two units that name each other cannot both be loaded: the
--- worker unit drives maintenance and the ops unit reads the run
--- state, which is exactly that shape. A declarations unit holding
--- what both sides need is the same answer the C reference reaches
--- with its header.

local M = {}

-- Cipher surfaces the --shape flag selects.
M.SHAPE_STREAM = 0           -- session pump: begin / write / read / end
M.SHAPE_MESSAGE = 1          -- Single Message: one whole-buffer call
M.SHAPE_STREAM_ONE_SHOT = 2  -- stream surface, one whole-buffer call
M.SHAPE_BOTH = 3             -- all three, rotating by iteration number

M.SHAPE_NAMES = { "stream", "message", "stream_one_shot", "both" }

-- --goroutines ceiling; the harness targets modest hosts and each
-- worker pins payload-sized buffers for the whole run.
M.MAX_WORKERS = 10

-- Concurrency mode. This binding runs single: a stock Lua 5.4
-- interpreter is one thread with one lua_State and its standard
-- library offers no thread primitive, only coroutines, which are
-- cooperative and would serialise on the same interpreter anyway. So
-- the single-threaded core is the whole of it and --goroutines above 1
-- is clamped to 1 rather than silently pretending to concurrency.
M.CONCURRENCY = "single"

-- Largest slice fed to a stream session per write; the drain after
-- every write uses the same bound.
M.PUMP_SLICE = 1 << 20

function M.shape_name(shape)
    return M.SHAPE_NAMES[shape + 1]
end

function M.parse_shape(s)
    for i, name in ipairs(M.SHAPE_NAMES) do
        if name == s then
            return i - 1
        end
    end
    return nil
end

--- A fresh resolved command line, every field at its zero default.
function M.new_config()
    return {
        duration_ns = 0,        -- run duration; ignored when iterations > 0
        iterations = 0,         -- per-worker count incl. warmup; 0 = duration-based
        workers_requested = 0,  -- the --goroutines value as given
        workers = 0,            -- the effective worker count
        shape = M.SHAPE_STREAM,
        hash = "",
        mac = "",
        payload = 0,            -- bytes per iteration
        memlimit = 0,           -- resolved bytes; the effective limit once shaped
        memlimit_auto = false,  -- --memlimit auto: cap only when the runtime has none
        gogc = 0,               -- 0 = leave the runtime default
        parallax = true,
        wrapper = true,

        profile = "",           -- empty = shape-based profile pair
        key_bits = 0,           -- 0 = profile default
        nonce_bits = 0,         -- 0 = profile default
        blob_mode = 1,          -- container floor sizing mode: 1 (per-region, default) | 2 (per-container)
        chunk_size = 0,         -- 0 = profile default
        barrier_fill = 0,       -- 0 = profile default
        drbg = "",              -- DRBG fill primitive; "" = profile default (auto tier)
        gomaxprocs = 0,         -- 0 = inherit from the environment
        rekey_every = 0,        -- per-worker iterations between rotations; 0 = never
        blob_cycle_every = 0,   -- per-worker iterations between reopens; 0 = never
        payload_mode = 0,
        seed = 0,               -- 0 = OS CSPRNG plaintexts
        json_output = false,
        memprofile = "",        -- empty = none
    }
end

--- One worker's private state: its plaintext, its generator, its
--- counters, and the error it stopped on.
function M.new_worker(id, run)
    return {
        id = id,
        run = run,

        plaintext = "",
        payload_mode = 0,
        seeded = false,
        rng = 0,  -- splitmix64 state when seeded

        -- Counters read by the summary after the worker has returned.
        iters = 0,
        bytes_enc = 0,
        bytes_dec = 0,
        nanos_enc = 0,
        nanos_dec = 0,

        failed = false,
        error = "",
    }
end

--- The state the run shares: the Pipeline handles, the retained blobs,
--- the stop request, and the baselines the summary reads.
function M.new_run(cfg)
    return {
        cfg = cfg,

        stream_pipe = nil,  -- nil unless the shape uses it
        msg_pipe = nil,     -- nil unless the shape uses it
        stream_profile = "",
        msg_profile = "",

        -- Handle mutation. The blob Init handed out, replaced by every
        -- rekey; the input of the next blob reopen.
        stream_blob = "",
        msg_blob = "",

        rekeys = 0,
        blob_cycles = 0,

        workers = {},

        -- Set by the duration deadline or by a failing worker; checked
        -- before every iteration.
        stop = false,

        start_ns = 0,
        finish_ns = 0,

        -- Baselines taken after the warmup barrier and at shutdown.
        rss_warmup = 0,
        rss_peak = 0,
        rss_final = 0,
        pool_warmup = {},
        pool_steady = {},
    }
end

--- Prints one prefixed status line to stdout.
---
--- The line is assembled with its newline and handed over in a single
--- write, so nothing another part of the run prints can land between a
--- text and the newline that terminates it.
function M.log_line(text)
    io.stdout:write("[loop] " .. text .. "\n")
    io.stdout:flush()
end

--- Prints one prefixed error line to stderr.
function M.err_line(text)
    io.stderr:write("loop: " .. text .. "\n")
    io.stderr:flush()
end

function M.on_off(b)
    return b and "on" or "off"
end

--- Renders an encoder policy env value for the summary: the raw string
--- when set, "default" when the shipped ladder applies.
function M.policy_label(env)
    if env == nil then
        return "default"
    end
    env = env:gsub("^[ \t]+", "")
    return env ~= "" and env or "default"
end

--- The failure detail a log line carries: the numeric status the
--- binding's own surface exposes and the finished sentence the library
--- left behind. Nothing is composed here — the wording arrives whole
--- from the failing call.
function M.status_detail(err)
    if type(err) == "table" and err.status ~= nil then
        return string.format("status %d: %s", err.status,
            tostring(err.message or ""))
    end
    return tostring(err)
end

--- The bare diagnostic sentence, without the numeric status: what the
--- lines that name no code carry.
function M.status_message(err)
    if type(err) == "table" and err.message ~= nil then
        return tostring(err.message)
    end
    return tostring(err)
end

--- Records the worker's error text (first error wins) and requests a
--- stop of the whole run.
function M.worker_fail(w, text)
    if not w.failed then
        w.error = text
        w.failed = true
    end
    w.run.stop = true
end

return M

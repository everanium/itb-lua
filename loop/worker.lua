--- The worker: its body (one warmup iteration, the warmup barrier,
--- the main loop), one iteration, the session pump loop the stream
--- shape drives, and the round-trip comparison that decides between a
--- worker error and a data mismatch.

local ops = require "ops"
local payload = require "payload"
local size = require "size"
local state = require "state"

local M = {}

-- Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
-- and ITB drives the chunk loop internally; the C ABI has no reader /
-- writer entry, so the caller drives it: open a session, feed slices of
-- at most 1 MiB, drain whatever the session has produced after every
-- write (a read before end never blocks), end, then drain until the
-- session reports finished (after end, a read on an empty spool blocks
-- until the terminal bytes arrive). The loop is written here rather
-- than delegated to the binding's pump convenience so it stands in the
-- utility, at the same place, in every language.
local function pump(pipe, encrypt, src)
    local session = encrypt and pipe:encrypt_stream() or pipe:decrypt_stream()
    local ok, res = pcall(function()
        local parts = {}
        local off = 1
        local total = #src
        while off <= total do
            local last = math.min(off + state.PUMP_SLICE - 1, total)
            session:write(src:sub(off, last))
            off = last + 1
            while true do
                local chunk = session:read(state.PUMP_SLICE)
                if #chunk == 0 then
                    break
                end
                parts[#parts + 1] = chunk
            end
        end
        session:finish()
        while true do
            local chunk, finished = session:read(state.PUMP_SLICE)
            if #chunk > 0 then
                parts[#parts + 1] = chunk
            end
            if finished then
                break
            end
        end
        return table.concat(parts)
    end)
    session:free()
    if not ok then
        error(res, 0)
    end
    return res
end

-- First offset at which a and b differ; the shorter length when one is
-- a prefix of the other.
local function first_difference(a, b)
    local n = math.min(#a, #b)
    for i = 1, n do
        if a:byte(i) ~= b:byte(i) then
            return i - 1
        end
    end
    return n
end

-- Up to 16 bytes of buf from off (zero-based) as lowercase hex, or "-"
-- when buf has no bytes there.
local function hex_window(buf, off)
    if off >= #buf then
        return "-"
    end
    local out = {}
    for i = off + 1, math.min(off + 16, #buf) do
        out[#out + 1] = string.format("%02x", buf:byte(i))
    end
    return table.concat(out)
end

-- Records a worker error for a failed cipher call.
local function cipher_fail(w, it, shape, direction, err)
    state.worker_fail(w, string.format("g%d iter %d shape=%s: %s: %s",
        w.id, it, state.shape_name(shape), direction, state.status_detail(err)))
end

--- One iteration. In order: refill the plaintext under rotating mode;
--- take the read lock; pick the surface; encrypt (timed); decrypt
--- (timed); compare the round-trip with the plaintext; bump the
--- counters; release the lock. The whole round-trip is kept clear of
--- handle-mutating maintenance (rekey, blob reopen), which runs after
--- this returns, from the worker loop, so nothing lands between an
--- encrypt and its matching decrypt. On this binding that separation
--- needs no lock: the run is one thread, so the ordering is the only
--- mechanism there is. Returns false after recording the worker error.
function M.iterate(w, it)
    local r = w.run

    if w.payload_mode == payload.ROTATING then
        w.plaintext, w.rng =
            payload.fill(payload.ROTATING, w.seeded, w.rng, #w.plaintext)
    end

    -- Shape dispatch. message is one whole-buffer call on the Single
    -- Message Pipeline; stream_one_shot is one whole-buffer call on the
    -- streaming Pipeline (the C ABI's ITB_Triple_EncryptStream, which
    -- routes to the same one-shot stream entry the Go harness calls
    -- by name); stream opens a session on the same streaming Pipeline
    -- and drives the chunk loop from here. Under both the three rotate
    -- by iteration number so the session path and the whole-buffer path
    -- alternate on one handle inside every worker — the cross-path
    -- state-reuse hazard this harness exists to catch.
    local shape = r.cfg.shape
    if shape == state.SHAPE_BOTH then
        shape = ({ state.SHAPE_STREAM, state.SHAPE_MESSAGE,
            state.SHAPE_STREAM_ONE_SHOT })[it % 3 + 1]
    end

    local want = w.plaintext
    local wire, got
    if shape == state.SHAPE_STREAM then
        local t0 = size.now_ns()
        local ok, res = pcall(pump, r.stream_pipe, true, want)
        if not ok then
            cipher_fail(w, it, shape, "encrypt", res)
            return false
        end
        wire = res
        w.nanos_enc = w.nanos_enc + (size.now_ns() - t0)
        t0 = size.now_ns()
        ok, res = pcall(pump, r.stream_pipe, false, wire)
        if not ok then
            cipher_fail(w, it, shape, "decrypt", res)
            return false
        end
        got = res
        w.nanos_dec = w.nanos_dec + (size.now_ns() - t0)
    else
        local pipe, enc, dec
        if shape == state.SHAPE_MESSAGE then
            pipe = r.msg_pipe
            enc, dec = pipe.encrypt_message, pipe.decrypt_message
        else
            pipe = r.stream_pipe
            enc, dec = pipe.encrypt_stream_one_shot, pipe.decrypt_stream_one_shot
        end
        local t0 = size.now_ns()
        local ok, res = pcall(enc, pipe, want)
        if not ok then
            cipher_fail(w, it, shape, "encrypt", res)
            return false
        end
        wire = res
        w.nanos_enc = w.nanos_enc + (size.now_ns() - t0)
        t0 = size.now_ns()
        ok, res = pcall(dec, pipe, wire)
        if not ok then
            cipher_fail(w, it, shape, "decrypt", res)
            return false
        end
        got = res
        w.nanos_dec = w.nanos_dec + (size.now_ns() - t0)
    end

    -- Failure model. A cipher call that returns a non-OK status is a
    -- worker error: it is recorded, the run is asked to stop, and the
    -- error is listed in the summary with the FAIL verdict. A
    -- round-trip that returns OK with different bytes is a data
    -- mismatch: the process terminates here, without summary or
    -- cleanup, because the Pipeline state that produced the wrong bytes
    -- is the evidence and nothing that runs afterwards may touch it.
    if got ~= want then
        local off = first_difference(want, got)
        io.stderr:write(string.format(
            "loop: DATA MISMATCH g%d iter %d shape=%s: want %d bytes, "
            .. "got %d bytes, first difference at offset %d: want %s got %s\n",
            w.id, it, state.shape_name(shape), #want, #got, off,
            hex_window(want, off), hex_window(got, off)))
        io.stderr:flush()
        -- Lua-specific. os.exit's second argument asks the interpreter
        -- to close the state on the way out, which would run every
        -- __gc metamethod, including the ones that free the Pipeline
        -- handles. Leaving it out is what "no summary, no cleanup"
        -- asks for.
        os.exit(3)
    end

    w.iters = w.iters + 1
    w.bytes_enc = w.bytes_enc + #want
    w.bytes_dec = w.bytes_dec + #got
    return true
end

--- The worker body: one warmup iteration, then the main loop until a
--- stop is requested, the duration deadline passes, or the fixed
--- per-worker iteration budget (warmup included) is spent.
---
--- Concurrency mode. This binding runs single: a stock Lua 5.4
--- interpreter has one thread and one lua_State, and its standard
--- library offers no thread primitive — coroutines are cooperative, so
--- they would run on the same interpreter one at a time and could not
--- put two calls into the library at once. --goroutines is therefore
--- accepted, clamped to 1, and reported next to the requested value,
--- so a fleet reading the summary sees the mode rather than inferring
--- it. The warmup barrier below degenerates to the single worker's own
--- first iteration.
function M.warmup(w)
    local ok, res = pcall(M.iterate, w, 0)
    if not ok then
        state.worker_fail(w, string.format("g%d iter 0: %s", w.id, tostring(res)))
        return false
    end
    return res
end

--- The main loop, entered after the warmup barrier has been passed and
--- the baselines taken.
function M.run_worker(w)
    local r = w.run
    local cfg = r.cfg
    local it = 1
    while true do
        if cfg.iterations > 0 and it >= cfg.iterations then
            break
        end
        if r.stop then
            break
        end
        if cfg.iterations == 0
            and size.now_ns() - r.start_ns >= cfg.duration_ns then
            break
        end
        local ok, res = pcall(M.iterate, w, it)
        if not ok then
            state.worker_fail(w, string.format("g%d iter %d: %s",
                w.id, it, tostring(res)))
            break
        end
        if not res then
            break
        end
        ok, res = pcall(ops.worker_maintenance, w, it)
        if not ok then
            state.worker_fail(w, string.format("g%d iter %d: %s",
                w.id, it, tostring(res)))
            break
        end
        if not res then
            break
        end
        it = it + 1
    end
end

return M

--- The final summary in both renderings, and the two measurements it
--- folds in that are not per-worker counters: the process resident set
--- and the shared library's pool counters.

local itb = require "itb3"

local payload = require "payload"
local size = require "size"
local state = require "state"

local M = {}

-- ------------------------------------------------------------------ --
-- Resident set                                                        --
-- ------------------------------------------------------------------ --

-- Parses one "Vm...:   1234 kB" line of /proc/self/status into bytes;
-- zero on any parse failure.
local function status_kb(line)
    local digits = line:match(":%s*(%d+)%s")
    if digits == nil then
        return 0
    end
    return (math.tointeger(tonumber(digits)) or 0) * 1024
end

--- The process's current resident set and its high-water mark in
--- bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
--- Both are zero on a platform without that file; the figures are
--- informational and never enter the verdict.
function M.read_rss()
    local f = io.open("/proc/self/status", "r")
    if f == nil then
        return 0, 0
    end
    local current, peak = 0, 0
    for line in f:lines() do
        if line:sub(1, 6) == "VmRSS:" then
            current = status_kb(line)
        elseif line:sub(1, 6) == "VmHWM:" then
            peak = status_kb(line)
        end
    end
    f:close()
    return current, peak
end

-- ------------------------------------------------------------------ --
-- Pool counters                                                       --
-- ------------------------------------------------------------------ --

--- Pool counters. The shared library keeps process-wide monotonic
--- totals at every pool checkout of its cipher core: per hash-array
--- tier the starter width, checkouts, constructor misses, regrow
--- replacements and bytes allocated; for the scratch byte pool and the
--- parallax chunk pool the checkouts, constructor misses, regrows and
--- regrow bytes. Two snapshots bracketing the main loop are differenced
--- into per-run hit / miss figures that tell whether a pool keeps its
--- items warm between calls or evicts them across GC cycles. The slot
--- layout is read from the library: slot 0 carries the tier count T,
--- tier i occupies the five slots at 1 + 5*i, and the two byte pools
--- occupy the eight slots at 1 + 5*T; the vector is sized from the
--- binding's length query, never from a constant.
function M.pool_snapshot()
    local ok, res = pcall(itb.pool_stats)
    if not ok then
        return {}
    end
    return res
end

-- The differenced pool figures of one run. Lua arrays are one-based,
-- so the library's slot n is read at index n + 1.
local function pool_delta(warmup, steady)
    local d = {
        tiers = 0,
        starter = {}, get = {}, new = {}, regrow = {}, new_bytes = {},
        buf = { 0, 0, 0, 0 },
        chunk = { 0, 0, 0, 0 },
    }
    if #warmup == 0 or #steady < 9 or #warmup ~= #steady then
        return d
    end
    local tiers = steady[1]
    if tiers < 0 or 1 + 5 * tiers + 8 > #steady then
        return d
    end
    d.tiers = tiers
    for i = 0, tiers - 1 do
        local base = 1 + 5 * i + 1
        d.starter[i + 1] = steady[base]
        d.get[i + 1] = steady[base + 1] - warmup[base + 1]
        d.new[i + 1] = steady[base + 2] - warmup[base + 2]
        d.regrow[i + 1] = steady[base + 3] - warmup[base + 3]
        d.new_bytes[i + 1] = steady[base + 4] - warmup[base + 4]
    end
    local tail = 1 + 5 * tiers + 1
    for i = 0, 3 do
        d.buf[i + 1] = steady[tail + i] - warmup[tail + i]
        d.chunk[i + 1] = steady[tail + 4 + i] - warmup[tail + 4 + i]
    end
    return d
end

-- Misses over checkouts as a percentage; zero when nothing was checked
-- out.
local function miss_percent(miss, get)
    if get <= 0 then
        return 0.0
    end
    return 100.0 * miss / get
end

-- The effective GC percentage as the runtime reports it: the query form
-- of the setter (a set-and-restore round trip inside the library) so
-- the field is the same whether the value came from the flag, the
-- environment, or the runtime default.
local function effective_gogc(flag)
    if flag > 0 then
        return flag
    end
    return math.tointeger(itb.set_gc_percent(-1)) or 0
end

-- Renders s as a JSON string literal with the escapes JSON requires.
local function js(s)
    local out = s:gsub('[%c"\\]', function(c)
        if c == '"' then return '\\"' end
        if c == "\\" then return "\\\\" end
        if c == "\n" then return "\\n" end
        if c == "\r" then return "\\r" end
        if c == "\t" then return "\\t" end
        if c == "\b" then return "\\b" end
        if c == "\f" then return "\\f" end
        return string.format("\\u%04x", c:byte())
    end)
    return '"' .. out .. '"'
end

-- One compact object on one line, keys in the contract's order, floats
-- with the contract's decimal counts and never in exponent form.
local function emit_json(r, elapsed_ns, totals, pd, rss_growth, gomaxprocs,
                         stream_profile, msg_profile)
    local cfg = r.cfg
    local tiers = {}
    for i = 1, pd.tiers do
        if pd.starter[i] ~= 0 then
            tiers[#tiers + 1] = string.format(
                '{"tier":%d,"starter":%d,"get":%d,"new":%d,"regrow":%d,'
                .. '"new_bytes":%d,"miss_percent":%.2f}',
                i - 1, pd.starter[i], pd.get[i], pd.new[i], pd.regrow[i],
                pd.new_bytes[i], miss_percent(pd.new[i] + pd.regrow[i], pd.get[i]))
        end
    end
    local per_worker = {}
    local errors = {}
    for _, w in ipairs(r.workers) do
        per_worker[#per_worker + 1] = string.format("%d", w.iters)
        if w.failed then
            errors[#errors + 1] = js(w.error)
        end
    end
    local out = table.concat({
        string.format('{"duration_seconds":%.3f', elapsed_ns / 1e9),
        string.format(',"iterations":%d', totals.iters),
        ',"per_worker_iterations":[' .. table.concat(per_worker, ",") .. "]",
        string.format(',"bytes_encrypted":%d', totals.bytes_enc),
        string.format(',"bytes_decrypted":%d', totals.bytes_dec),
        string.format(',"encrypt_mb_per_sec":%.1f',
            size.mb_per_sec(totals.bytes_enc, totals.avg_enc)),
        string.format(',"decrypt_mb_per_sec":%.1f',
            size.mb_per_sec(totals.bytes_dec, totals.avg_dec)),
        string.format(',"combined_mb_per_sec":%.1f',
            size.mb_per_sec(totals.bytes_enc + totals.bytes_dec, elapsed_ns)),
        string.format(',"rekeys":%d', r.rekeys),
        string.format(',"blob_cycles":%d', r.blob_cycles),
        ',"worker_errors":[' .. table.concat(errors, ",") .. "]",
        string.format(',"verdict":"%s"', #errors == 0 and "PASS" or "FAIL"),
        string.format(',"shape":"%s"', state.shape_name(cfg.shape)),
        ',"stream_profile":' .. js(stream_profile),
        ',"message_profile":' .. js(msg_profile),
        ',"hash":' .. js(cfg.hash),
        ',"mac":' .. js(cfg.mac),
        string.format(',"payload_bytes":%d', cfg.payload),
        string.format(',"payload_mode":"%s"', payload.mode_name(cfg.payload_mode)),
        string.format(',"seed":%d', cfg.seed),
        string.format(',"key_bits":%d', cfg.key_bits),
        string.format(',"nonce_bits":%d', cfg.nonce_bits),
        string.format(',"blob_mode":%d', cfg.blob_mode),
        ',"drbg":' .. js(cfg.drbg),
        ',"drbg_auto_tier":' .. js(itb.drbg_auto_tier()),
        string.format(',"chunk_size_bytes":%d', cfg.chunk_size),
        string.format(',"barrier_fill":%d', cfg.barrier_fill),
        string.format(',"parallax":"%s"', state.on_off(cfg.parallax)),
        string.format(',"wrapper":"%s"', state.on_off(cfg.wrapper)),
        string.format(',"goroutines_requested":%d', cfg.workers_requested),
        string.format(',"goroutines":%d', cfg.workers),
        string.format(',"concurrency":"%s"', state.CONCURRENCY),
        string.format(',"gogc":"%d"', effective_gogc(cfg.gogc)),
        string.format(',"memlimit_bytes":%d', cfg.memlimit),
        string.format(',"gomaxprocs":%d', gomaxprocs),
        ',"microbatch_tiers":'
        .. js(state.policy_label(os.getenv("ITB_MICROBATCH_TIERS"))),
        ',"hashpool_starters":'
        .. js(state.policy_label(os.getenv("ITB_HASHPOOL_STARTERS"))),
        string.format(',"rss_warmup_bytes":%d', r.rss_warmup),
        string.format(',"rss_peak_bytes":%d', r.rss_peak),
        string.format(',"rss_final_bytes":%d', r.rss_final),
        string.format(',"rss_growth_percent":%.2f', rss_growth),
        ',"hash_pool_tiers":[' .. table.concat(tiers, ",") .. "]",
        string.format(
            ',"buf_pool":{"get":%d,"new":%d,"regrow":%d,"regrow_bytes":%d,'
            .. '"miss_percent":%.2f}',
            pd.buf[1], pd.buf[2], pd.buf[3], pd.buf[4],
            miss_percent(pd.buf[3], pd.buf[1])),
        string.format(
            ',"parallax_chunk_pool":{"get":%d,"new":%d,"regrow":%d,'
            .. '"regrow_bytes":%d,"miss_percent":%.2f}',
            pd.chunk[1], pd.chunk[2], pd.chunk[3], pd.chunk[4],
            miss_percent(pd.chunk[3], pd.chunk[1])),
        "}\n",
    })
    io.stdout:write(out)
    io.stdout:flush()
end

--- Output contract. Both renderings are shared with the Go harness and
--- every other binding's loop utility field for field: the same lines
--- in the same order, the same keys in the same order, floats with a
--- fixed number of decimals so the JSON is byte-identical across
--- implementations. The Go harness alone adds its runtime-internal
--- lines after rss: and its runtime-internal keys after
--- parallax_chunk_pool; nothing here reproduces them because nothing
--- they read is reachable through the C ABI.
function M.final_summary(r, elapsed_ns)
    local cfg = r.cfg
    local totals = {
        iters = 0, bytes_enc = 0, bytes_dec = 0, nanos_enc = 0, nanos_dec = 0,
    }
    local errors = {}
    for _, w in ipairs(r.workers) do
        totals.iters = totals.iters + w.iters
        totals.bytes_enc = totals.bytes_enc + w.bytes_enc
        totals.bytes_dec = totals.bytes_dec + w.bytes_dec
        totals.nanos_enc = totals.nanos_enc + w.nanos_enc
        totals.nanos_dec = totals.nanos_dec + w.nanos_dec
        if w.failed then
            errors[#errors + 1] = w.error
        end
    end

    -- Throughput. Per-direction throughput divides the sum of every
    -- worker's wall time in that direction by the worker count — the
    -- equivalent single-stream wall time under N-way concurrency — so
    -- each direction reports the aggregate rate it sustained rather
    -- than collapsing to combined/2 (every iteration moves equal
    -- encrypt and decrypt bytes, so a total-elapsed denominator would
    -- give both directions the same figure). The combined rate keeps
    -- total elapsed as the one-glance overall figure.
    totals.avg_enc = totals.nanos_enc > 0 and totals.nanos_enc // cfg.workers or 0
    totals.avg_dec = totals.nanos_dec > 0 and totals.nanos_dec // cfg.workers or 0

    local rss_delta = r.rss_final - r.rss_warmup
    local rss_growth = r.rss_warmup > 0 and (100.0 * rss_delta / r.rss_warmup) or 0.0

    local pd = pool_delta(r.pool_warmup, r.pool_steady)
    local passed = #errors == 0
    local gomaxprocs = math.tointeger(itb.set_gomaxprocs(0)) or 0
    local stream_profile = r.stream_pipe ~= nil and r.stream_profile or ""
    local msg_profile = r.msg_pipe ~= nil and r.msg_profile or ""

    if cfg.json_output then
        emit_json(r, elapsed_ns, totals, pd, rss_growth, gomaxprocs,
            stream_profile, msg_profile)
        return passed and 0 or 1
    end

    state.log_line("=== FINAL ===")
    state.log_line("  duration: " .. size.human_duration(
        (elapsed_ns + 500000) // 1000000 * 1000000))
    local parts = {}
    for _, w in ipairs(r.workers) do
        parts[#parts + 1] = string.format("%d", w.iters)
    end
    state.log_line(string.format("  iterations: %s = %d total",
        table.concat(parts, " + "), totals.iters))
    state.log_line(string.format(
        "  throughput: encrypt %s, decrypt %s, combined %s",
        size.human_rate(totals.bytes_enc, totals.avg_enc),
        size.human_rate(totals.bytes_dec, totals.avg_dec),
        size.human_rate(totals.bytes_enc + totals.bytes_dec, elapsed_ns)))
    state.log_line(string.format("  bytes: %s encrypted, %s decrypted",
        size.human_bytes(totals.bytes_enc), size.human_bytes(totals.bytes_dec)))
    state.log_line(string.format("  data integrity: %d/%d PASS",
        totals.iters, totals.iters))
    state.log_line(string.format("  concurrency: %s, workers %d (requested %d)",
        state.CONCURRENCY, cfg.workers, cfg.workers_requested))
    state.log_line(string.format(
        "  rss: warmup %s, peak %s, final %s (delta %s, %.1f%% growth)",
        size.human_bytes(r.rss_warmup), size.human_bytes(r.rss_peak),
        size.human_bytes(r.rss_final), size.human_bytes_signed(rss_delta),
        rss_growth))
    for i = 1, pd.tiers do
        if pd.starter[i] ~= 0 then
            local miss = pd.new[i] + pd.regrow[i]
            state.log_line(string.format(
                "  hash pool tier %d (starter %d): get %d, miss %d "
                .. "(new %d + regrow %d), miss %.2f%%, %s allocated",
                i - 1, pd.starter[i], pd.get[i], miss, pd.new[i], pd.regrow[i],
                miss_percent(miss, pd.get[i]), size.human_bytes(pd.new_bytes[i])))
        end
    end
    state.log_line(string.format(
        "  buf pool: get %d, regrow %d (of which fresh %d), miss %.2f%%, "
        .. "%s regrown",
        pd.buf[1], pd.buf[3], pd.buf[2], miss_percent(pd.buf[3], pd.buf[1]),
        size.human_bytes(pd.buf[4])))
    state.log_line(string.format(
        "  parallax chunk pool: get %d, regrow %d (of which fresh %d), "
        .. "miss %.2f%%, %s regrown",
        pd.chunk[1], pd.chunk[3], pd.chunk[2],
        miss_percent(pd.chunk[3], pd.chunk[1]), size.human_bytes(pd.chunk[4])))
    if r.rekeys > 0 then
        state.log_line(string.format("  rekeys: %d", r.rekeys))
    end
    if r.blob_cycles > 0 then
        state.log_line(string.format("  blob cycles: %d", r.blob_cycles))
    end
    for _, text in ipairs(errors) do
        state.log_line("  ERROR: " .. text)
    end
    if passed then
        state.log_line("  verdict: PASS")
        return 0
    end
    state.log_line(string.format("  verdict: FAIL (errors=%d)", #errors))
    return 1
end

return M

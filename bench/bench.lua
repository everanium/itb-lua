--- bench.lua — micro-benchmarks for the ITB Lua binding.
--
-- Single Message encrypt and incremental Streaming encrypt throughput
-- at 1 MiB / 16 MiB / 64 MiB. Wall-clock via the module's monotonic
-- itb.now() (os.clock reports process CPU time, which over-counts the
-- Go runtime's worker threads); output is a fixed-width table:
--
--     bench             size     mb_per_sec
--     message           1 MiB    <n>
--     ...
--
-- Configuration is driven by environment variables so a side-by-side
-- comparison with the root Go bench harness is straightforward:
--
--     ITB_NONCE_BITS      512         shipped secure default
--     ITB_KEY_BITS        1024        matches root Go BENCH3.md
--     ITB_WITH_PARALLAX   false       root Go bench runs without parallax
--     ITB_WITH_WRAPPER    false       root Go bench runs without the wrapper
--     ITB_INNER_HASH      (profile)   opaque hash name
--     ITB_MSG_PROFILE     (fallback ITB_PROFILE, then singlemsg-triple-nomac-v1)
--     ITB_STREAM_PROFILE  (fallback ITB_PROFILE, then streaming-noaead-triple-v1)
--     ITB_BENCH_MIN_SEC   5           per-case wall-clock budget (seconds)

local itb = require "itb"

local SIZES = { 1 << 20, 16 << 20, 64 << 20 }
local BENCH_MIN_ITERS = 3
local PUMP_SLICE = 1 << 20

local function env(name, fallback)
    local v = os.getenv(name)
    if v == nil or v == "" then
        return fallback
    end
    return v
end

-- Reads the per-shape profile env var, falling back to ITB_PROFILE,
-- then to the shape's own default.
local function profile_env(shape_env, fallback)
    return env(shape_env, env("ITB_PROFILE", fallback))
end

local function bench_min_seconds()
    local v = tonumber(env("ITB_BENCH_MIN_SEC", "5"))
    if v == nil or v <= 0 then
        return 5.0
    end
    return v
end

-- Reads the bench-shape env vars and builds the opts string. Defaults
-- match the root Go BENCH3.md pin so numbers are directly comparable.
local function build_opts()
    local t = {
        nonce_bits = tonumber(env("ITB_NONCE_BITS", "512")),
        key_bits = tonumber(env("ITB_KEY_BITS", "1024")),
        with_parallax = env("ITB_WITH_PARALLAX", "false") == "true",
        with_wrapper = env("ITB_WITH_WRAPPER", "false") == "true",
    }
    local inner = env("ITB_INNER_HASH", "")
    if inner ~= "" then
        t.inner_hash = inner
    end
    local mac = env("ITB_MAC_NAME", "")
    if mac ~= "" then
        t.mac_name = mac
    end
    return itb.opts(t)
end

-- CSPRNG-fill so plaintext content matches the root Go bench
-- (crypto/rand). Not in the timing loop.
local function random_bytes(n)
    local f = assert(io.open("/dev/urandom", "rb"))
    local s = assert(f:read(n))
    f:close()
    assert(#s == n, "short /dev/urandom read")
    return s
end

local function size_label(size)
    if size >= (1 << 20) then
        return ("%d MiB"):format(size >> 20)
    end
    return ("%d KiB"):format(size >> 10)
end

-- Runs fn until the wall-clock budget is spent (with an iteration
-- floor + one untimed warm-up), then prints one table row.
local function bench_case(name, size, fn)
    fn() -- warm-up
    local budget = bench_min_seconds()
    local start = itb.now()
    local elapsed = 0.0
    local iters = 0
    while elapsed < budget or iters < BENCH_MIN_ITERS do
        fn()
        iters = iters + 1
        elapsed = itb.now() - start
    end
    local mb = size * iters / (1024.0 * 1024.0)
    print(("%-17s %-8s %.1f"):format(name, size_label(size), mb / elapsed))
end

-- One incremental encrypt-session pass: feed 1 MiB slices, drain
-- available wire as it appears, then finish + final drain.
local function stream_pass(pipe, plain)
    local sess = pipe:encrypt_stream()
    for off = 1, #plain, PUMP_SLICE do
        sess:write(plain:sub(off, off + PUMP_SLICE - 1))
        while true do
            local chunk = sess:read()
            if #chunk == 0 then break end
        end
    end
    sess:finish()
    while true do
        local _, finished = sess:read()
        if finished then break end
    end
    sess:free()
end

-- Decrypt counterpart.
local function stream_dec_pass(pipe, wire)
    local sess = pipe:decrypt_stream()
    for off = 1, #wire, PUMP_SLICE do
        sess:write(wire:sub(off, off + PUMP_SLICE - 1))
        while true do
            local chunk = sess:read()
            if #chunk == 0 then break end
        end
    end
    sess:finish()
    while true do
        local _, finished = sess:read()
        if finished then break end
    end
    sess:free()
end

-- Pre-encrypt one wire outside the decrypt timing loop.
local function stream_encrypt_all(pipe, plain)
    local parts = {}
    local sess = pipe:encrypt_stream()
    for off = 1, #plain, PUMP_SLICE do
        sess:write(plain:sub(off, off + PUMP_SLICE - 1))
        while true do
            local chunk = sess:read()
            if #chunk == 0 then break end
            parts[#parts + 1] = chunk
        end
    end
    sess:finish()
    while true do
        local chunk, finished = sess:read()
        if chunk and #chunk > 0 then parts[#parts + 1] = chunk end
        if finished then break end
    end
    sess:free()
    return table.concat(parts)
end

local function main()
    -- Bench-scale allocation churn leaks Go scratch heap unboundedly
    -- without a soft memory cap + aggressive GC; the return values
    -- report the previous settings, not an error.
    itb.set_memory_limit(512 * 1024 * 1024)
    itb.set_gc_percent(20)

    local opts = build_opts()
    print(("%-17s %-8s mb_per_sec"):format("bench", "size"))

    do
        local pipe <close> = itb.create(
            profile_env("ITB_MSG_PROFILE", "singlemsg-triple-nomac-v1"), opts)
        for _, size in ipairs(SIZES) do
            local plain = random_bytes(size)
            bench_case("message", size, function()
                pipe:encrypt_message(plain)
            end)
            local dec_wire = pipe:encrypt_message(plain)
            bench_case("message-dec", size, function()
                pipe:decrypt_message(dec_wire)
            end)
            plain = nil
            dec_wire = nil
            collectgarbage("collect")
        end
    end

    do
        local pipe <close> = itb.create(
            profile_env("ITB_STREAM_PROFILE", "streaming-noaead-triple-v1"), opts)
        for _, size in ipairs(SIZES) do
            local plain = random_bytes(size)
            bench_case("stream", size, function()
                stream_pass(pipe, plain)
            end)
            local dec_wire = stream_encrypt_all(pipe, plain)
            bench_case("stream-dec", size, function()
                stream_dec_pass(pipe, dec_wire)
            end)
            plain = nil
            dec_wire = nil
            collectgarbage("collect")
        end
    end

    do
        local pipe <close> = itb.create(
            profile_env("ITB_STREAM_PROFILE", "streaming-noaead-triple-v1"), opts)
        for _, size in ipairs(SIZES) do
            local plain = random_bytes(size)
            bench_case("stream_one_shot", size, function()
                pipe:encrypt_stream_one_shot(plain)
            end)
            local dec_wire = pipe:encrypt_stream_one_shot(plain)
            bench_case("stream_one_shot-dec", size, function()
                pipe:decrypt_stream_one_shot(dec_wire)
            end)
            plain = nil
            dec_wire = nil
            collectgarbage("collect")
        end
    end
end

main()

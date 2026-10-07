--- Plaintext content: the payload modes, the seeded per-worker
--- generator, and the buffer fill from the operating-system CSPRNG.

local M = {}

-- Payload mode selector values for the --payload-mode flag.
--
--   - fixed: one CSPRNG-generated buffer per worker, held unchanged
--     for the whole run (the default).
--   - rotating: the buffer is regenerated before every iteration, so
--     no two encrypt calls see the same plaintext.
--   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00 /
--     all 0xFF) probing minimum-entropy plaintext handling.
--   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
--     structured text.
M.FIXED = 0
M.ROTATING = 1
M.PATTERN_ZERO = 2
M.PATTERN_FF = 3
M.PATTERN_ASCII = 4

M.NAMES = {
    "fixed",
    "rotating",
    "pattern-zero",
    "pattern-ff",
    "pattern-ascii",
}

function M.mode_name(mode)
    return M.NAMES[mode + 1]
end

function M.parse_mode(s)
    for i, name in ipairs(M.NAMES) do
        if name == s then
            return i - 1
        end
    end
    return nil
end

--- Seeded plaintext. The seed makes plaintext content reproducible so
--- a failing iteration can be replayed with the same bytes; it governs
--- nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
--- so a seeded run is a reproduction aid and never a security test.
--- Each worker's stream is domain-separated by its id so seeded
--- workers still hold pairwise-distinct buffers under the fixed and
--- rotating modes. The generator is splitmix64: a few lines in any
--- language, which is why it is the one every binding uses.
function M.seed_worker(seed, worker_id)
    return seed + worker_id + 1
end

local GOLDEN = 0x9E3779B97F4A7C15
local MIX1 = 0xBF58476D1CE4E5B9
local MIX2 = 0x94D049BB133111EB

-- One splitmix64 draw; returns the advanced state and the output.
--
-- Lua-specific. Lua 5.4 integers are 64-bit two's complement and
-- arithmetic on them wraps, and >> is a logical shift, so the
-- generator is the reference one without any masking step. The values
-- are signed when printed, which never matters: only their bytes are
-- consumed.
local function splitmix64(state)
    state = state + GOLDEN
    local z = state
    z = (z ~ (z >> 30)) * MIX1
    z = (z ~ (z >> 27)) * MIX2
    return state, z ~ (z >> 31)
end

-- The operating-system CSPRNG, opened once and held for the run.
--
-- Lua-specific. Lua's standard library carries no cryptographic
-- generator, so the bytes come from the kernel device directly. math.random
-- is a userspace PRNG and is never used for this.
local urandom = nil

--- Draws n bytes from the operating-system CSPRNG.
function M.fill_random(n)
    if urandom == nil then
        local f, err = io.open("/dev/urandom", "rb")
        if f == nil then
            error("open /dev/urandom: " .. tostring(err), 0)
        end
        urandom = f
    end
    local parts = {}
    local got = 0
    while got < n do
        local piece = urandom:read(n - got)
        if piece == nil or #piece == 0 then
            error("short read from /dev/urandom", 0)
        end
        parts[#parts + 1] = piece
        got = got + #piece
    end
    if #parts == 1 then
        return parts[1]
    end
    return table.concat(parts)
end

-- n bytes from the seeded generator, eight at a time.
local function fill_seeded(rng, n)
    local parts = {}
    local full = n // 8
    for _ = 1, full do
        local value
        rng, value = splitmix64(rng)
        parts[#parts + 1] = string.pack("<i8", value)
    end
    local tail = n % 8
    if tail > 0 then
        local value
        rng, value = splitmix64(rng)
        parts[#parts + 1] = string.pack("<i8", value):sub(1, tail)
    end
    return table.concat(parts), rng
end

local ASCII_RAMP = nil

--- Builds one plaintext buffer according to the payload mode and
--- returns it with the advanced generator state. The fixed and
--- rotating modes draw from the seeded generator when the run is
--- seeded and from the OS CSPRNG otherwise; the pattern modes are
--- deterministic regardless of the seed.
function M.fill(mode, seeded, rng, n)
    if mode == M.FIXED or mode == M.ROTATING then
        if not seeded then
            return M.fill_random(n), rng
        end
        return fill_seeded(rng, n)
    end
    if mode == M.PATTERN_ZERO then
        return string.rep("\0", n), rng
    end
    if mode == M.PATTERN_FF then
        return string.rep("\255", n), rng
    end
    if ASCII_RAMP == nil then
        local out = {}
        for i = 0, 25 do
            out[i + 1] = string.char(0x41 + i)
        end
        ASCII_RAMP = table.concat(out)
    end
    return string.rep(ASCII_RAMP, n // 26 + 1):sub(1, n), rng
end

return M

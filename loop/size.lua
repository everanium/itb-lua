--- Size and duration parsing, the monotonic clock, and the human
--- renderings of sizes, rates and durations. Every rendering here is
--- part of the output contract shared with the Go harness and the
--- other bindings' loop utilities, so the formats are fixed to the
--- character, not to taste.

local itb = require "itb3"

local M = {}

-- Byte-size suffixes, longest first so "KIB" is matched before "K" and
-- "B" never swallows the tail of another suffix. Every multiple is
-- binary.
local SIZE_SUFFIXES = {
    { "KIB", 1 << 10 },
    { "KB", 1 << 10 },
    { "K", 1 << 10 },
    { "MIB", 1 << 20 },
    { "MB", 1 << 20 },
    { "M", 1 << 20 },
    { "GIB", 1 << 30 },
    { "GB", 1 << 30 },
    { "G", 1 << 30 },
    { "B", 1 },
}

-- Duration units in the order the grammar probes them, so "ms" is
-- taken before "m" and "s".
local DURATION_UNITS = {
    { "ns", 1.0 },
    { "us", 1e3 },
    { "ms", 1e6 },
    { "s", 1e9 },
    { "m", 60e9 },
    { "h", 3600e9 },
}

local INT64_MAX = math.maxinteger

--- Parses a human byte-size string ("16MB", "1MiB", "512K",
--- "1073741824") into a byte count. Every suffix is a binary multiple:
--- K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
--- bytes; matching is case-insensitive and surrounding whitespace is
--- trimmed. Returns nil on a malformed or negative value.
function M.parse_size(s)
    local upper = (s:gsub("^%s+", ""):gsub("%s+$", "")):upper()
    if upper == "" then
        return nil
    end
    local mult = 1
    local digits = upper
    for _, row in ipairs(SIZE_SUFFIXES) do
        local suffix, m = row[1], row[2]
        if #upper >= #suffix and upper:sub(- #suffix) == suffix then
            mult = m
            digits = upper:sub(1, #upper - #suffix)
            break
        end
    end
    digits = digits:gsub("%s+$", "")
    if digits == "" or digits:find("[^0-9]") then
        return nil
    end
    local n = math.tointeger(tonumber(digits, 10))
    if n == nil then
        return nil
    end
    if mult > 1 and n > INT64_MAX // mult then
        return nil
    end
    return n * mult
end

--- Parses the Go duration grammar — a sequence of decimal numbers each
--- followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
--- "1h30m", "1.5s" — into nanoseconds. Returns nil on a malformed
--- string.
function M.parse_duration(s)
    if s == nil or s == "" then
        return nil
    end
    local total = 0.0
    local pos = 1
    while pos <= #s do
        local digits = s:match("^[0-9.]+", pos)
        if digits == nil then
            return nil
        end
        local value = tonumber(digits)
        if value == nil or value < 0.0 then
            return nil
        end
        pos = pos + #digits
        local mult = 0.0
        for _, row in ipairs(DURATION_UNITS) do
            local unit, ns = row[1], row[2]
            if s:sub(pos, pos + #unit - 1) == unit
                and not s:sub(pos + #unit, pos + #unit):match("%a") then
                mult = ns
                pos = pos + #unit
                break
            end
        end
        if mult == 0.0 then
            return nil
        end
        total = total + value * mult
    end
    if total > 9.2e18 then
        return nil
    end
    return math.tointeger(math.floor(total)) or math.floor(total)
end

-- The monotonic clock's origin, taken once at load. Lua-specific.
-- itb.now() hands back CLOCK_MONOTONIC as a double of seconds, and
-- CLOCK_MONOTONIC counts from boot, so scaling it to nanoseconds
-- directly would spend the mantissa on the host's uptime. Every
-- reading is taken relative to this origin instead, which keeps the
-- whole of the double's precision on the run itself.
local ORIGIN = itb.now()

--- Monotonic wall clock in nanoseconds, counted from process start.
function M.now_ns()
    return math.floor((itb.now() - ORIGIN) * 1e9)
end

--- Renders a byte count with a binary-unit suffix: "1.0GiB",
--- "16.0MiB", "4.0KiB", "512B".
function M.human_bytes(n)
    if n >= (1 << 30) then
        return string.format("%.1fGiB", n / (1 << 30))
    end
    if n >= (1 << 20) then
        return string.format("%.1fMiB", n / (1 << 20))
    end
    if n >= (1 << 10) then
        return string.format("%.1fKiB", n / (1 << 10))
    end
    return string.format("%dB", n)
end

--- Renders a possibly-negative byte delta with an explicit sign.
function M.human_bytes_signed(n)
    if n < 0 then
        return "-" .. M.human_bytes(-n)
    end
    return "+" .. M.human_bytes(n)
end

--- Binary MiB per second over a nanosecond window; 0 when the window
--- is unmeasured.
function M.mb_per_sec(byte_count, ns)
    if ns <= 0 then
        return 0.0
    end
    return byte_count / (1 << 20) / (ns / 1e9)
end

--- Renders a throughput as "123.4MB/s" (binary MiB per second) or
--- "n/a" for an unmeasured window.
function M.human_rate(byte_count, ns)
    if ns <= 0 then
        return "n/a"
    end
    return string.format("%.1fMB/s", M.mb_per_sec(byte_count, ns))
end

-- The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
-- with trailing zeros removed; empty for zero.
local function fraction(frac_ns)
    if frac_ns == 0 then
        return ""
    end
    return "." .. (string.format("%09d", frac_ns):gsub("0+$", ""))
end

--- Renders a duration the way Go's time.Duration prints: below one
--- second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
--- where the hour part appears when non-zero, the minute part when the
--- hour part appears or the minutes are non-zero, and the seconds
--- carry their fraction with trailing zeros removed ("5s", "5.003s",
--- "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first.
function M.human_duration(ns)
    ns = ns < 0 and -ns or ns
    if ns == 0 then
        return "0s"
    end
    if ns < 1000000000 then
        -- Scale the sub-millisecond remainder to nine digits so the
        -- fraction renderer sees the same shape it does for seconds.
        return string.format("%d%sms", ns // 1000000,
            fraction((ns % 1000000) * 1000))
    end
    local hours = ns // 3600000000000
    local rem = ns % 3600000000000
    local minutes = rem // 60000000000
    rem = rem % 60000000000
    local seconds = rem // 1000000000
    local frac = rem % 1000000000
    local out = hours > 0 and string.format("%dh", hours) or ""
    if hours > 0 or minutes > 0 then
        out = out .. string.format("%dm", minutes)
    end
    return string.format("%s%d%ss", out, seconds, fraction(frac))
end

return M

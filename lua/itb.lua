--- itb.lua — Lua-side sugar over the itb C module (itb.so).
--
-- Loads the compiled C core located next to this file and re-exports
-- its surface plus pure-Lua conveniences:
--
--   itb.opts{...}          — URL-query opts builder (table -> string)
--   itb.tohex / itb.fromhex — hex codec for blob transport
--   itb.pump(sess, read_fn, write_fn) — bounded-memory stream pump
--
-- When only LUA_CPATH is configured, `require "itb"` resolves the C
-- core directly and this file is bypassed; the C surface is complete
-- on its own. With LUA_PATH pointing here, `require "itb"` returns
-- the merged table below.

local function core_path()
    local src = debug.getinfo(1, "S").source
    local path = src:match("^@(.*)$") or src
    local dir = path:match("^(.*)[/\\][^/\\]*$") or "."
    return dir .. "/itb.so"
end

local loader = assert(package.loadlib(core_path(), "luaopen_itb"))
local M = loader()

-- ---------------------------------------------------------------------
-- Opts builder.
--
-- Renders a Lua table into the URL-query opts string consumed by
-- itb.create / itb.open / itb.register_profile. No validation is
-- performed here — every key and value passes through to Go verbatim
-- (percent-encoded); libitb rejects unknown keys or bad values with a
-- diagnostic surfaced through the error object.
--
-- Snake_case keys map onto the Go opts grammar; any key not in the
-- map is passed through unchanged (the raw escape hatch covering the
-- register-profile grammar: mode, width, innerHashes, parallaxOn,
-- wrapperOn, ...). Values: booleans render as "true"/"false",
-- integers as decimals, tables as comma-joined lists, strings as-is.

local KEY_MAP = {
    nonce_bits = "nonceBits",
    key_bits = "keyBits",
    with_parallax = "withParallax",
    with_wrapper = "withWrapper",
    max_workers = "maxWorkers",
    barrier_fill = "barrierFill",
    chunk_size = "chunkSize",
    parallax_segment_size = "parallaxSegmentSize",
    mac_name = "macName",
    inner_hash = "innerHash",
    outer_cipher = "outerCipher",
    parallax_palette = "parallaxPalette",
    perm_master = "pm",
    wrap_master = "wm",
}

-- Percent-encodes everything outside the URL-safe subset plus ','.
local function enc(s)
    return (s:gsub("[^%w%-%.%_%~%,]", function(c)
        return string.format("%%%02X", string.byte(c))
    end))
end

local function render_value(v)
    local t = type(v)
    if t == "boolean" then
        return v and "true" or "false"
    elseif t == "number" then
        return string.format("%d", v)
    elseif t == "table" then
        return table.concat(v, ",")
    elseif t == "string" then
        return v
    end
    error("itb.opts: unsupported value type: " .. t, 3)
end

--- Builds the opts query string from a table. Keys are emitted in
--- sorted order so the rendered string is deterministic.
function M.opts(tbl)
    if tbl == nil then
        return ""
    end
    assert(type(tbl) == "table", "itb.opts: expected a table")
    local keys = {}
    for k in pairs(tbl) do
        assert(type(k) == "string", "itb.opts: keys must be strings")
        keys[#keys + 1] = k
    end
    table.sort(keys)
    local pairs_out = {}
    for _, k in ipairs(keys) do
        local go_key = KEY_MAP[k] or k
        pairs_out[#pairs_out + 1] =
            enc(go_key) .. "=" .. enc(render_value(tbl[k]))
    end
    return table.concat(pairs_out, "&")
end

-- ---------------------------------------------------------------------
-- Hex codec (blob transport through shells / config files).

function M.tohex(s)
    return (s:gsub(".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

function M.fromhex(h)
    assert(#h % 2 == 0, "itb.fromhex: odd-length hex string")
    assert(not h:find("[^0-9a-fA-F]"), "itb.fromhex: non-hex character")
    return (h:gsub("%x%x", function(cc)
        return string.char(tonumber(cc, 16))
    end))
end

-- ---------------------------------------------------------------------
-- Bounded-memory stream pump.
--
-- Moves bytes from read_fn through an open stream session into
-- write_fn: feed a slice, drain available output, repeat; finish +
-- final drain on source EOF. read_fn() returns a string (empty or
-- nil at EOF); write_fn(chunk) consumes produced bytes. The caller
-- owns the session (free it after the pump returns).

function M.pump(sess, read_fn, write_fn)
    while true do
        local piece = read_fn()
        if piece == nil or #piece == 0 then
            break
        end
        sess:write(piece)
        -- Drain whatever the chain has produced so far; a read
        -- before finish() never blocks.
        while true do
            local chunk = sess:read()
            if #chunk == 0 then
                break
            end
            write_fn(chunk)
        end
    end
    sess:finish()
    while true do
        local chunk, finished = sess:read()
        if #chunk > 0 then
            write_fn(chunk)
        end
        if finished then
            break
        end
    end
end

return M

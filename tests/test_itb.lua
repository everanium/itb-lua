--- Assert-based test suite for the ITB Lua binding.
--
-- Plain Lua 5.4 asserts (no external test framework dependency); each
-- case prints "ok - <name>" on success, and the process exits non-zero
-- on the first failure with a traceback.

local itb = require "itb3"

local failures = 0

local function run(name, fn)
    local ok, err = xpcall(fn, debug.traceback)
    if ok then
        print("ok - " .. name)
    else
        failures = failures + 1
        print("FAIL - " .. name)
        print(tostring(err))
    end
end

-- Deterministic non-trivial payload (xorshift fill).
local function payload(n, seed)
    local x = seed | 1
    local out = {}
    for i = 1, n do
        x = x ~ ((x << 13) & 0xFFFFFFFFFFFFFFFF)
        x = x ~ (x >> 7)
        x = x ~ ((x << 17) & 0xFFFFFFFFFFFFFFFF)
        out[i] = string.char(x & 0xFF)
    end
    return table.concat(out)
end

-- Runs fn under pcall and asserts it raised an itb error object with
-- one of the expected statuses.
local function assert_status(expected, fn)
    local ok, err = pcall(fn)
    assert(not ok, "expected an error, got success")
    assert(type(err) == "table" and err.status ~= nil,
        "expected an itb error object, got: " .. tostring(err))
    for _, want in ipairs(expected) do
        if err.status == want then
            assert(#tostring(err) > 0, "error object must stringify")
            return err
        end
    end
    error(("unexpected status %d: %s"):format(err.status, tostring(err)))
end

-- ---------------------------------------------------------------------

run("version", function()
    local v = itb.version()
    assert(type(v) == "string" and #v > 0, "empty version")
    assert(itb._VERSION == "0.5.5")
end)

run("drbg auto tier", function()
    local tier = itb.drbg_auto_tier()
    assert(tier == "aes-256-ctr" or tier == "chacha20", "drbg auto tier: " .. tostring(tier))
end)

run("profiles list", function()
    local got = itb.profiles()
    assert(#got > 0)
    local set = {}
    for _, name in ipairs(got) do
        set[name] = true
    end
    for _, want in ipairs({
        "singlemsg-triple-mac-v1",
        "singlemsg-triple-nomac-v1",
        "streaming-aead-triple-mac-v1",
        "streaming-noaead-triple-v1",
    }) do
        assert(set[want], "missing profile " .. want)
    end
end)

run("runtime knobs", function()
    -- Negative values query without changing.
    assert(type(itb.set_memory_limit(-1)) == "number")
    assert(type(itb.set_gc_percent(-1)) == "number")
end)

run("message round trip (singlemsg-triple-mac-v1)", function()
    local sender <close> = itb.create("singlemsg-triple-mac-v1")
    local receiver <close> = itb.load(sender:save())
    for _, size in ipairs({ 1, 4 * 1024, 256 * 1024 }) do
        local plain = payload(size, size)
        local wire = sender:encrypt_message(plain)
        assert(wire ~= plain and #wire > 0)
        assert(receiver:decrypt_message(wire) == plain,
            "round trip mismatch @" .. size)
    end
end)

run("stream round trip (streaming-noaead-triple-v1)", function()
    local sender <close> = itb.create("streaming-noaead-triple-v1")
    local receiver <close> = itb.load(sender:save())
    local plain = payload(96 * 1024, 7)

    -- Encrypt incrementally: 8 KiB writes, then finish + drain.
    local enc <close> = sender:encrypt_stream()
    for off = 1, #plain, 8192 do
        enc:write(plain:sub(off, off + 8191))
    end
    local wire = enc:drain_all()
    assert(#wire > 0)

    -- Decrypt with pathological batch sizes (17-byte feed,
    -- 23-byte drain) across chunk boundaries.
    local dec <close> = receiver:decrypt_stream()
    for off = 1, #wire, 17 do
        dec:write(wire:sub(off, off + 16))
    end
    dec:finish()
    local back = {}
    while true do
        local chunk, finished = dec:read(23)
        back[#back + 1] = chunk
        if finished then break end
    end
    assert(table.concat(back) == plain, "stream round trip mismatch")
end)

run("pump helper round trip", function()
    local sender <close> = itb.create("streaming-noaead-triple-v1")
    local receiver <close> = itb.load(sender:save())
    local plain = payload(64 * 1024 + 3, 11)

    local function reader_over(s)
        local off = 1
        return function()
            if off > #s then return nil end
            local piece = s:sub(off, off + 8191)
            off = off + 8192
            return piece
        end
    end
    local function collector(acc)
        return function(chunk) acc[#acc + 1] = chunk end
    end

    local wire_parts = {}
    do
        local sess <close> = sender:encrypt_stream()
        itb.pump(sess, reader_over(plain), collector(wire_parts))
    end
    local wire = table.concat(wire_parts)

    local back_parts = {}
    do
        local sess <close> = receiver:decrypt_stream()
        itb.pump(sess, reader_over(wire), collector(back_parts))
    end
    assert(table.concat(back_parts) == plain, "pump round trip mismatch")
end)

run("large plaintext round trip (> 1 MiB)", function()
    local sender <close> = itb.create("singlemsg-triple-nomac-v1")
    local receiver <close> = itb.load(sender:save())
    local plain = payload(2 * 1024 * 1024 + 17, 3)
    local wire = sender:encrypt_message(plain)
    assert(receiver:decrypt_message(wire) == plain)
end)

run("unknown profile maps to UNKNOWN_PROFILE", function()
    local err = assert_status({ itb.status.UNKNOWN_PROFILE }, function()
        itb.create("no-such-profile")
    end)
    assert(#err.message > 0, "error object must carry a diagnostic")
end)

run("unknown opts key maps to BAD_INPUT", function()
    -- Typoed key (lowercase s) — Go rejects unknown keys; the binding
    -- performs no validation of its own.
    assert_status({ itb.status.BAD_INPUT }, function()
        itb.create("singlemsg-triple-mac-v1", itb.opts({ chunksize = 4096 }))
    end)
end)

run("tampered wire fails authentication", function()
    local sender <close> = itb.create("singlemsg-triple-mac-v1")
    local receiver <close> = itb.load(sender:save())
    local wire = sender:encrypt_message(payload(4096, 21))
    local i = #wire // 2
    local tampered = wire:sub(1, i - 1)
        .. string.char(string.byte(wire, i) ~ 0xFF)
        .. wire:sub(i + 1)
    assert_status(
        { itb.status.MAC_FAILURE, itb.status.DECRYPT_FAILED },
        function() receiver:decrypt_message(tampered) end)
end)

run("closed pipeline maps to TRIPLE_CLOSED", function()
    local pipe <close> = itb.create("singlemsg-triple-mac-v1")
    pipe:close()
    pipe:close() -- idempotent
    assert_status({ itb.status.TRIPLE_CLOSED }, function()
        pipe:encrypt_message("payload")
    end)
end)

run("rekey refreshes the blob", function()
    local sender <close> = itb.create("singlemsg-triple-mac-v1")
    local blob_before = sender:save()
    local blob_after = sender:rekey(payload(32, 5), payload(32, 6))
    assert(blob_after ~= blob_before, "blob unchanged after rekey")
    assert(sender:save() == blob_after, "save does not observe the rekey")
    -- The refreshed blob reconstructs a working receiver.
    local receiver <close> = itb.load(blob_after)
    local wire = sender:encrypt_message("post-rekey payload")
    assert(receiver:decrypt_message(wire) == "post-rekey payload")
end)

run("register round trip and duplicate", function()
    local profile = [[{
        "mode": "singlemsg-nomac",
        "width": 256,
        "hashes": ["blake3", "blake2s", "areion256", "blake2b256",
                   "chacha20", "blake3", "blake2s", "areion256"],
        "keybits": 1024,
        "parallax": false,
        "wrapper": false
    }]]
    itb.register("lua-binding-test-mixed", profile)
    local seen = false
    for _, name in ipairs(itb.profiles()) do
        if name == "lua-binding-test-mixed" then seen = true end
    end
    assert(seen, "registered profile missing from itb.profiles()")
    assert(itb.lookup("lua-binding-test-mixed"):find('"hashes":["blake3"', 1, true),
        "lookup record lacks the hashes constellation")
    local sender <close> = itb.create("lua-binding-test-mixed")
    local receiver <close> = itb.load(sender:save())
    local wire = sender:encrypt_message("custom profile")
    assert(receiver:decrypt_message(wire) == "custom profile")
    assert_status({ itb.status.PROFILE_EXISTS }, function()
        itb.register("lua-binding-test-mixed", profile)
    end)
    -- Strict record decode on the Go side: an unknown key is
    -- rejected there, not by the binding.
    assert_status({ itb.status.BAD_INPUT }, function()
        itb.register("lua-binding-test-badkey", '{"mode":"singlemsg-nomac","bogus":1}')
    end)
end)

run("save / load round trip", function()
    local sender <close> = itb.create("singlemsg-triple-mac-v1")
    local blob = sender:save()
    assert(#blob > 0 and sender:save() == blob, "save is not stable")
    local receiver <close> = itb.load(blob)
    assert(receiver:save() == blob, "load did not retain the blob")
    local wire = sender:encrypt_message("in-memory persist")
    assert(receiver:decrypt_message(wire) == "in-memory persist")
end)

run("save_f / load_f round trip", function()
    local path = os.tmpname()
    os.remove(path)
    local sender <close> = itb.create("singlemsg-triple-mac-v1")
    sender:save_f(path)
    local f = assert(io.open(path, "rb"))
    local on_disk = f:read("a")
    f:close()
    assert(on_disk == sender:save(), "file content differs from save()")
    local receiver <close> = itb.load_f(path)
    assert(receiver:save() == sender:save())
    local wire = sender:encrypt_message("file persist")
    assert(receiver:decrypt_message(wire) == "file persist")
    os.remove(path)
    assert_status({ itb.status.BAD_INPUT }, function() itb.load_f(path) end)
end)

run("load with master override", function()
    local sender <close> = itb.create("singlemsg-triple-mac-v1")
    local rotated = sender:rekey(payload(32, 8), payload(32, 10))
    local receiver <close> = itb.load(sender:save(), payload(32, 8), payload(32, 10))
    assert(receiver:save() == rotated)
    local wire = sender:encrypt_message("master override")
    assert(receiver:decrypt_message(wire) == "master override")
end)

run("inspect / lookup / profiles", function()
    local pipe <close> = itb.create("singlemsg-triple-mac-v1")
    local record = itb.inspect(pipe:save())
    assert(record:find('"name":"singlemsg-triple-mac-v1"', 1, true), record)
    assert(record:find('"mode":"singlemsg-mac"', 1, true), record)
    -- inspect carries the registry recipe plus the blob-only
    -- nonce_bits / barrier_fill inspection fields; lookup returns
    -- just the recipe.
    local looked = itb.lookup("singlemsg-triple-mac-v1")
    assert(record:find('"nonce_bits":', 1, true), "inspect must carry nonce_bits")
    assert(record:find('"barrier_fill":', 1, true), "inspect must carry barrier_fill")
    assert(looked:find('"name":"singlemsg-triple-mac-v1"', 1, true), looked)
    assert(not looked:find('"nonce_bits":', 1, true), "lookup must not carry nonce_bits")
    assert(not looked:find('"barrier_fill":', 1, true), "lookup must not carry barrier_fill")
    assert_status({ itb.status.BAD_INPUT }, function() itb.inspect("not a blob") end)
    assert_status({ itb.status.UNKNOWN_PROFILE }, function() itb.lookup("no-such-profile") end)
    local names = itb.profiles()
    assert(#names > 0)
    for i = 2, #names do
        assert(names[i - 1] < names[i], "profiles() is not sorted")
    end
end)

run("max_workers", function()
    local pipe <close> = itb.create("singlemsg-triple-mac-v1")
    pipe:max_workers(2)
    pipe:max_workers(-1)     -- clamped to auto, never rejected
    pipe:max_workers(10000)  -- clamped to 256
    local wire = pipe:encrypt_message("after cap change")
    assert(pipe:decrypt_message(wire) == "after cap change")
    pipe:close()
    assert_status({ itb.status.TRIPLE_CLOSED }, function() pipe:max_workers(2) end)
    -- A negative init-time cap is clamped as well.
    local neg <close> = itb.create("singlemsg-triple-mac-v1", itb.opts({ max_workers = -1 }))
    assert(neg:decrypt_message(neg:encrypt_message("negative cap")) == "negative cap")
end)

run("stream session pins its parent pipeline against GC", function()
    local sess
    do
        local pipe = itb.create("streaming-noaead-triple-v1")
        sess = pipe:encrypt_stream()
        -- pipe goes out of scope here with no other Lua reference.
    end
    collectgarbage("collect")
    collectgarbage("collect")
    -- The session's uservalue keeps the Pipeline userdata (and its
    -- Go-side handle) alive, so the write still succeeds.
    sess:write("still alive after parent went out of scope")
    local wire = sess:drain_all()
    assert(#wire > 0, "empty wire after GC")
    sess:free()
    sess:free() -- idempotent
end)

run("opts builder rendering", function()
    assert(itb.opts(nil) == "")
    assert(itb.opts({}) == "")
    local q = itb.opts({
        nonce_bits = 512,
        key_bits = 1024,
        with_parallax = false,
        inner_hash = "areion512",
        parallax_palette = { "chacha20", "blake3" },
    })
    -- Keys are emitted in sorted (snake_case) order.
    assert(q == "innerHash=areion512&keyBits=1024&nonceBits=512"
        .. "&parallaxPalette=chacha20,blake3&withParallax=false", q)
    -- Percent-encoding of non-URL-safe bytes.
    assert(itb.opts({ x = "a b&c" }) == "x=a%20b%26c")
end)

run("hex codec", function()
    assert(itb.tohex("\0\255ab") == "00ff6162")
    assert(itb.fromhex("00ff6162") == "\0\255ab")
    assert(itb.fromhex(itb.tohex(payload(257, 9))) == payload(257, 9))
    assert(not pcall(itb.fromhex, "0g"))
    assert(not pcall(itb.fromhex, "012"))
end)

run("hash registry enumeration", function()
    local got = itb.hash_names()
    assert(#got > 0, "empty hash registry")
    local set = {}
    for _, name in ipairs(got) do
        assert(type(name) == "string" and #name > 0)
        set[name] = true
    end
    for _, want in ipairs({ "areion512", "blake3", "aesitb128" }) do
        assert(set[want], "missing hash primitive " .. want)
    end
    -- The enumeration is what a caller validates a name against, so a
    -- name that is not in it must be one libitb3 rejects.
    assert(not set["nosuchhash"])
    assert_status({ itb.status.BAD_HASH, itb.status.BAD_INPUT,
        itb.status.INTERNAL }, function()
        itb.create("singlemsg-triple-mac-v1",
            itb.opts({ inner_hash = "nosuchhash" }))
    end)
end)

run("gomaxprocs knob", function()
    -- n <= 0 queries without changing; a positive n sets and reports
    -- the previous value, so the pair round-trips.
    local before = itb.set_gomaxprocs(0)
    assert(type(before) == "number" and before > 0)
    local prev = itb.set_gomaxprocs(2)
    assert(prev == before, "set did not report the previous value")
    assert(itb.set_gomaxprocs(0) == 2, "set did not take effect")
    itb.set_gomaxprocs(before)
    assert(itb.set_gomaxprocs(0) == before, "restore failed")
end)

run("heap profile", function()
    local path = os.tmpname()
    itb.write_heap_profile(path)
    local f = assert(io.open(path, "rb"))
    local body = f:read("a")
    f:close()
    os.remove(path)
    assert(#body > 0, "empty heap profile")
    -- pprof output is a gzip stream.
    assert(body:byte(1) == 0x1F and body:byte(2) == 0x8B, "not a pprof profile")
    assert_status({ itb.status.BAD_INPUT }, function()
        itb.write_heap_profile("/nonexistent-directory-for-itb-tests/heap.prof")
    end)
end)

run("pool counters", function()
    local want = itb.pool_stats_len()
    assert(type(want) == "number" and want > 0)
    local first = itb.pool_stats()
    assert(#first == want, "slot count does not match the length query")
    -- Slot 0 carries the hash-array tier count, and the vector holds
    -- five slots per tier plus the eight slots of the two byte pools.
    local tiers = first[1]
    assert(tiers > 0 and 1 + 5 * tiers + 8 == want, "slot layout mismatch")
    -- The counters are monotonic totals since library load, so work
    -- done between two snapshots can only raise them.
    local pipe <close> = itb.create("singlemsg-triple-mac-v1")
    pipe:decrypt_message(pipe:encrypt_message(payload(64 * 1024, 3)))
    local second = itb.pool_stats()
    local rose = false
    for i = 1, want do
        assert(second[i] >= first[i], "counter went backwards at slot " .. i)
        if second[i] > first[i] then
            rose = true
        end
    end
    assert(rose, "no counter moved across a round trip")
end)

run("drbg round trip through a loaded blob", function()
    for _, name in ipairs({ "csprng", "aesitb128" }) do
        local sender <close> = itb.create("singlemsg-triple-mac-v1",
            itb.opts({ drbg = name }))
        local receiver <close> = itb.load(sender:save())
        local wire = sender:encrypt_message("drbg " .. name)
        assert(receiver:decrypt_message(wire) == "drbg " .. name)
        local back = receiver:encrypt_message("reverse " .. name)
        assert(sender:decrypt_message(back) == "reverse " .. name)
    end
end)

run("drbg inspect, default and unknown name", function()
    local pipe <close> = itb.create("singlemsg-triple-mac-v1",
        itb.opts({ drbg = "csprng" }))
    local record = itb.inspect(pipe:save())
    assert(record:find('"drbg":"csprng"', 1, true), record)
    -- With no drbg set the record carries no drbg key, and no shipped
    -- profile names one.
    local plain <close> = itb.create("singlemsg-triple-mac-v1")
    local default = itb.inspect(plain:save())
    assert(not default:find('"drbg":', 1, true), default)
    local looked = itb.lookup("singlemsg-triple-mac-v1")
    assert(not looked:find('"drbg":', 1, true), looked)
    local err = assert_status({ itb.status.RECIPE_PRIMITIVE_UNKNOWN }, function()
        itb.create("singlemsg-triple-mac-v1", itb.opts({ drbg = "nope" }))
    end)
    assert(tostring(err):find("nope", 1, true), tostring(err))
end)

run("drbg survives a register copy", function()
    local pipe <close> = itb.create("singlemsg-triple-mac-v1",
        itb.opts({ drbg = "csprng" }))
    -- The inspection-only fields are dropped; drbg is a recipe field
    -- and stays in the registered copy.
    local record = itb.inspect(pipe:save())
        :gsub('"name":"[^"]*",?', "")
        :gsub('"nonce_bits":%d+,?', "")
        :gsub('"barrier_fill":%d+,?', "")
        :gsub('"container_mode":%d+,?', "")
    itb.register("lua-binding-test-drbg-copy", record)
    local looked = itb.lookup("lua-binding-test-drbg-copy")
    assert(looked:find('"drbg":"csprng"', 1, true), looked)
end)

-- ---------------------------------------------------------------------

if failures > 0 then
    print(("%d test(s) FAILED"):format(failures))
    os.exit(1)
end
print("all tests passed")

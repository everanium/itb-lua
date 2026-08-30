--- itb_eitb.lua — command-line demonstrator for the ITB Lua binding.
--
-- Subcommands:
--
--     itb_eitb.lua version                                library + binding versions
--     itb_eitb.lua hashes                                 shipped hash primitive roster
--     itb_eitb.lua profiles                               built-in Triple profile names
--     itb_eitb.lua encrypt <profile> <in-file> <out-file> Single Message encrypt
--     itb_eitb.lua decrypt <profile> <blob-hex> <in-file> <out-file>
--
-- `encrypt` prints the session blob to stderr as hex; feed that hex
-- back to `decrypt` on the receiving side.

local itb = require "itb"

local USAGE = [[
usage: eitb version
       eitb hashes
       eitb profiles
       eitb encrypt <profile> <in-file> <out-file>
       eitb decrypt <profile> <blob-hex> <in-file> <out-file>]]

local function read_file(path)
    local f, err = io.open(path, "rb")
    if not f then error(err, 0) end
    local data = f:read("a")
    f:close()
    return data
end

local function write_file(path, data)
    local f, err = io.open(path, "wb")
    if not f then error(err, 0) end
    assert(f:write(data))
    f:close()
end

local function cmd_version()
    print("libitb " .. itb.version())
    print("itb-lua " .. itb._VERSION)
end

local function cmd_hashes()
    for i, h in ipairs(itb.hashes()) do
        print(("%2d  %-12s %d bits"):format(i - 1, h.name, h.width))
    end
end

local function cmd_profiles()
    for _, name in ipairs(itb.profiles()) do
        print(name)
    end
end

-- Profiles whose canonical name begins with "streaming-" route
-- through the one-shot streaming buffered pair instead of the Single
-- Message pair.
local function is_streaming_profile(profile)
    return profile:sub(1, 10) == "streaming-"
end

-- Recursively create the parent directory of `path` (mkdir -p).
-- Lua's stdlib has no mkdir; shell out via os.execute with single-
-- quote escaping of the path.
local function ensure_parent_dir(path)
    local dir = path:match("^(.*)/[^/]+$")
    if not dir or dir == "" then return end
    local escaped = "'" .. dir:gsub("'", [['\'']]) .. "'"
    os.execute("mkdir -p " .. escaped)
end

local function cmd_encrypt(profile, infile, outfile)
    local plain = read_file(infile)
    local pipe <close> = itb.create(profile)
    local wire = is_streaming_profile(profile)
        and pipe:encrypt_stream_one_shot(plain)
        or pipe:encrypt_message(plain)
    ensure_parent_dir(outfile)
    write_file(outfile, wire)
    io.stderr:write(itb.tohex(pipe:blob()) .. "\n")
    print(("encrypted %s -> %s (%d -> %d bytes)")
        :format(infile, outfile, #plain, #wire))
end

local function cmd_decrypt(profile, blob_hex, infile, outfile)
    local ok, blob = pcall(itb.fromhex, blob_hex)
    if not ok then error("blob hex: " .. tostring(blob), 0) end
    local wire = read_file(infile)
    local pipe <close> = itb.open(profile, blob)
    local plain = is_streaming_profile(profile)
        and pipe:decrypt_stream_one_shot(wire)
        or pipe:decrypt_message(wire)
    ensure_parent_dir(outfile)
    write_file(outfile, plain)
    print(("decrypted %s -> %s (%d -> %d bytes)")
        :format(infile, outfile, #wire, #plain))
end

local function main(argv)
    local known_shape =
        (#argv == 1 and (argv[1] == "version" or argv[1] == "hashes"
            or argv[1] == "profiles"))
        or (#argv == 4 and argv[1] == "encrypt")
        or (#argv == 5 and argv[1] == "decrypt")
    if not known_shape then
        io.stderr:write(USAGE .. "\n")
        return 2
    end
    local ok, err = pcall(function()
        -- Go-runtime pacing caps applied before any cipher work.
        itb.set_memory_limit(512 * 1024 * 1024)
        itb.set_gc_percent(20)
        if argv[1] == "version" then
            cmd_version()
        elseif argv[1] == "hashes" then
            cmd_hashes()
        elseif argv[1] == "profiles" then
            cmd_profiles()
        elseif argv[1] == "encrypt" then
            cmd_encrypt(argv[2], argv[3], argv[4])
        else
            cmd_decrypt(argv[2], argv[3], argv[4], argv[5])
        end
    end)
    if not ok then
        io.stderr:write("eitb: " .. tostring(err) .. "\n")
        return 1
    end
    return 0
end

os.exit(main(arg))

--- The maintenance operations that mutate a live Pipeline handle
--- between iterations: master rotation (--rekey-every) and blob reopen
--- (--blob-cycle-every).

local itb = require "itb3"

local payload = require "payload"
local state = require "state"

local M = {}

-- Byte length of each fresh master drawn for a rotation. Matches the
-- size Init auto-generates for both the parallax and the wrapper
-- master.
local REKEY_MASTER_SIZE = 32

-- Master rotation. Rotates the parallax + wrapper masters on every
-- active Pipeline and retains the refreshed blob for subsequent blob
-- reopens. Masters are drawn fresh from the OS CSPRNG on every
-- rotation regardless of --seed (master rotation is pipeline keying,
-- not plaintext content); a disabled layer passes no bytes, which
-- Rekey ignores. The eight inner seeds and the MAC key are untouched
-- by design — Rekey targets only the two outer-layer master secrets.
local function rekey_pipes(w, it)
    local r = w.run
    local perm = r.cfg.parallax and payload.fill_random(REKEY_MASTER_SIZE) or ""
    local wrap = r.cfg.wrapper and payload.fill_random(REKEY_MASTER_SIZE) or ""

    -- Handle mutation. Rekey rewrites the outer-layer keying of a live
    -- handle in place. This binding runs single, so no cipher call can
    -- be in flight while it happens and no lock is needed to keep one
    -- clear of it; the shared-handle bindings take a write lock here,
    -- which is where one would stand.
    if r.stream_pipe ~= nil then
        local ok, res = pcall(function()
            return r.stream_pipe:rekey(perm, wrap)
        end)
        if not ok then
            state.worker_fail(w, string.format("g%d iter %d: Rekey(%s): %s",
                w.id, it, r.stream_profile, state.status_detail(res)))
            return false
        end
        r.stream_blob = res
    end
    if r.msg_pipe ~= nil then
        local ok, res = pcall(function()
            return r.msg_pipe:rekey(perm, wrap)
        end)
        if not ok then
            state.worker_fail(w, string.format("g%d iter %d: Rekey(%s): %s",
                w.id, it, r.msg_profile, state.status_detail(res)))
            return false
        end
        r.msg_blob = res
    end
    r.rekeys = r.rekeys + 1
    state.log_line(string.format(
        "rekey: g%d iter %d rotated parallax + wrapper masters (rekey #%d)",
        w.id, it, r.rekeys))
    return true
end

-- Blob reopen. Reopens every active Pipeline from its retained blob: a
-- fresh handle is loaded from the blob, the running handle is freed,
-- and the fresh one is swapped in, so every later iteration
-- round-trips through seeds and masters that survived a blob crossing.
-- The input is the blob Init or the latest Rekey handed out, not a
-- fresh Save: that is what a receiver holds, and reopening from it
-- proves the handed-out bytes rather than the live state. The blob
-- carries the Pipeline's full shape, so no override reaches the
-- reopen. On a Load failure the running handle stays and the failure
-- aborts the run.
local function blob_cycle_pipes(w, it)
    local r = w.run
    if r.stream_pipe ~= nil then
        local ok, fresh = pcall(itb.load, r.stream_blob)
        if not ok then
            state.worker_fail(w, string.format("g%d iter %d: Load(%s): %s",
                w.id, it, r.stream_profile, state.status_detail(fresh)))
            return false
        end
        r.stream_pipe:free()
        r.stream_pipe = fresh
    end
    if r.msg_pipe ~= nil then
        local ok, fresh = pcall(itb.load, r.msg_blob)
        if not ok then
            state.worker_fail(w, string.format("g%d iter %d: Load(%s): %s",
                w.id, it, r.msg_profile, state.status_detail(fresh)))
            return false
        end
        r.msg_pipe:free()
        r.msg_pipe = fresh
    end
    r.blob_cycles = r.blob_cycles + 1
    state.log_line(string.format(
        "blob-cycle: g%d iter %d reopened from session blob (cycle #%d)",
        w.id, it, r.blob_cycles))
    return true
end

--- Runs the periodic Pipeline-mutating operations after a completed
--- iteration: master rotation (--rekey-every) and blob reopen
--- (--blob-cycle-every). Both intervals count per-worker iterations;
--- the warmup iteration (iter 0) never triggers because the worker
--- loop calls this for iter >= 1 only. Returns false after recording a
--- worker error.
function M.worker_maintenance(w, it)
    local cfg = w.run.cfg
    if cfg.rekey_every > 0 and it % cfg.rekey_every == 0 then
        if not rekey_pipes(w, it) then
            return false
        end
    end
    if cfg.blob_cycle_every > 0 and it % cfg.blob_cycle_every == 0 then
        if not blob_cycle_pipes(w, it) then
            return false
        end
    end
    return true
end

return M

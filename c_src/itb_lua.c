/*
 * itb_lua.c — Lua 5.4 C module over the libitb shared library's
 * Triple Pipeline surface (ITB_Triple_*, cmd/cshared).
 *
 * The module is a thin proxy: every hash-name / MAC-name / cipher-name
 * / profile-name is an opaque string passed through to Go for
 * validation; no ITB construction logic lives here. Compiled as a
 * plain `lua_State`-based module (no LuaJIT FFI) loadable via
 * `require "itb"`.
 *
 * Surface registered on the module table:
 *
 *   itb.create(profile [, opts])            -> Pipeline
 *   itb.open(profile, blob [, opts [, perm, wrap]]) -> Pipeline
 *   itb.register_profile(name, opts)
 *   itb.hashes()                            -> { {name=..., width=...}, ... }
 *   itb.profiles()                          -> { "streaming-aead-triple-mac-v1", ... }
 *   itb.version()                           -> string
 *   itb.set_memory_limit(bytes)             -> previous limit
 *   itb.set_gc_percent(pct)                 -> previous percent
 *   itb.now()                               -> monotonic seconds (number)
 *   itb.status                              -> { OK=0, BAD_INPUT=4, ... }
 *
 * Pipeline userdata methods (metatable "itb.pipeline"):
 *   :encrypt_message(plain) / :decrypt_message(wire)
 *   :encrypt_stream_one_shot(plain) / :decrypt_stream_one_shot(wire)
 *   :encrypt_stream() / :decrypt_stream()   -> Stream session
 *   :blob() :rekey(perm, wrap) :close() :free()
 *
 * Stream userdata methods (metatable "itb.stream"):
 *   :write(src) :finish() :read([max]) -> chunk, finished
 *   :drain_all() -> string  :free()
 *
 * Session-parent-pin: a Stream userdata's uservalue slot 1 holds a
 * reference to its parent Pipeline userdata, so the Lua GC cannot
 * collect (and thereby free) the Pipeline while the session is live.
 *
 * Errors are raised as table objects {status=int, label=string,
 * message=string} with a __tostring metamethod, so pcall callers can
 * branch on err.status against itb.status.*.
 *
 * Output-buffer discipline: variable-size outputs pre-allocate
 * len + len/4 + 65536 bytes and retry once with the exact reported
 * size when the call returns BUFFER_TOO_SMALL with outLen > cap.
 */

/* clock_gettime / CLOCK_MONOTONIC under -std=c11. */
#define _POSIX_C_SOURCE 200112L

#include <lua.h>
#include <lauxlib.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

#include "libitb.h"

#define ITB_LUA_VERSION "0.3.3"

#define PIPE_MT "itb.pipeline"
#define STREAM_MT "itb.stream"
#define ERROR_MT "itb.error"

/* Cast a borrowed const input pointer to the non-const void* the cgo
 * header declares; Go copies inputs before returning. */
#define MUT(p) ((void *)(uintptr_t)(const void *)(p))

/* ---- status codes (mirrors cmd/cshared/internal/capi/errors.go) --- */

enum {
    ST_OK = 0,
    ST_BAD_HASH = 1,
    ST_BAD_KEY_BITS = 2,
    ST_BAD_HANDLE = 3,
    ST_BAD_INPUT = 4,
    ST_BUFFER_TOO_SMALL = 5,
    ST_ENCRYPT_FAILED = 6,
    ST_DECRYPT_FAILED = 7,
    ST_SEED_WIDTH_MIX = 8,
    ST_BAD_MAC = 9,
    ST_MAC_FAILURE = 10,
    ST_BLOB_MODE_MISMATCH = 19,
    ST_BLOB_MALFORMED = 20,
    ST_BLOB_VERSION_TOO_NEW = 21,
    ST_BLOB_TOO_MANY_OPTS = 22,
    ST_STREAM_TRUNCATED = 23,
    ST_STREAM_AFTER_FINAL = 24,
    ST_TRIPLE_CLOSED = 25,
    ST_PROFILE_EXISTS = 26,
    ST_INTERNAL = 99,
};

typedef struct {
    int code;
    const char *name;  /* itb.status key */
    const char *label; /* human-readable */
} status_row;

static const status_row STATUS_ROWS[] = {
    {ST_OK, "OK", "ok"},
    {ST_BAD_HASH, "BAD_HASH", "unknown hash name"},
    {ST_BAD_KEY_BITS, "BAD_KEY_BITS", "invalid key bits"},
    {ST_BAD_HANDLE, "BAD_HANDLE", "invalid handle"},
    {ST_BAD_INPUT, "BAD_INPUT", "invalid input"},
    {ST_BUFFER_TOO_SMALL, "BUFFER_TOO_SMALL", "output buffer too small"},
    {ST_ENCRYPT_FAILED, "ENCRYPT_FAILED", "encrypt failed"},
    {ST_DECRYPT_FAILED, "DECRYPT_FAILED", "decrypt failed"},
    {ST_SEED_WIDTH_MIX, "SEED_WIDTH_MIX", "seed width mismatch"},
    {ST_BAD_MAC, "BAD_MAC", "unknown MAC name or invalid MAC handle"},
    {ST_MAC_FAILURE, "MAC_FAILURE", "MAC verification failed"},
    {ST_BLOB_MODE_MISMATCH, "BLOB_MODE_MISMATCH", "blob mode mismatch"},
    {ST_BLOB_MALFORMED, "BLOB_MALFORMED", "malformed state blob"},
    {ST_BLOB_VERSION_TOO_NEW, "BLOB_VERSION_TOO_NEW", "blob version too new"},
    {ST_BLOB_TOO_MANY_OPTS, "BLOB_TOO_MANY_OPTS", "too many blob export opts"},
    {ST_STREAM_TRUNCATED, "STREAM_TRUNCATED", "stream truncated before terminator"},
    {ST_STREAM_AFTER_FINAL, "STREAM_AFTER_FINAL", "stream chunk after terminator"},
    {ST_TRIPLE_CLOSED, "TRIPLE_CLOSED", "Triple Pipeline is closed"},
    {ST_PROFILE_EXISTS, "PROFILE_EXISTS", "profile name already registered"},
    {ST_INTERNAL, "INTERNAL", "internal error"},
};

static const char *status_label(int code) {
    size_t i;
    for (i = 0; i < sizeof(STATUS_ROWS) / sizeof(STATUS_ROWS[0]); i++) {
        if (STATUS_ROWS[i].code == code) {
            return STATUS_ROWS[i].label;
        }
    }
    return "unknown status";
}

/* Shipped built-in Triple profile names (mirrors the profile registry
 * in triple/profile.go; the C ABI exposes no profile enumeration). */
static const char *const PROFILE_NAMES[] = {
    "streaming-aead-triple-mac-v1",
    "streaming-noaead-triple-v1",
    "singlemsg-triple-mac-v1",
    "singlemsg-triple-nomac-v1",
    "blob-triple-mac-v1",
    "streaming-aead-triple-mac-mixed-v1",
    "streaming-noaead-triple-mixed-v1",
    "singlemsg-triple-mac-mixed-v1",
    "singlemsg-triple-nomac-mixed-v1",
};

/* ---- error raising ------------------------------------------------ */

/* Pushes the ITB_LastError diagnostic (NUL-stripped) or "". */
static void push_last_error(lua_State *L) {
    size_t need = 0;
    int rc = ITB_LastError(NULL, 0, &need);
    if ((rc != ST_OK && rc != ST_BUFFER_TOO_SMALL) || need <= 1) {
        lua_pushliteral(L, "");
        return;
    }
    {
        luaL_Buffer b;
        char *p = luaL_buffinitsize(L, &b, need);
        rc = ITB_LastError(p, need, &need);
        if (rc != ST_OK) {
            luaL_pushresultsize(&b, 0);
            lua_pop(L, 1);
            lua_pushliteral(L, "");
            return;
        }
        luaL_pushresultsize(&b, need > 0 ? need - 1 : 0);
    }
}

/* Raises an error object {status, label, message} (never returns). */
static int raise_status(lua_State *L, int rc) {
    lua_createtable(L, 0, 3);
    lua_pushinteger(L, rc);
    lua_setfield(L, -2, "status");
    lua_pushstring(L, status_label(rc));
    lua_setfield(L, -2, "label");
    push_last_error(L);
    lua_setfield(L, -2, "message");
    luaL_setmetatable(L, ERROR_MT);
    return lua_error(L);
}

static int l_error_tostring(lua_State *L) {
    lua_Integer st;
    const char *label, *msg;
    luaL_checktype(L, 1, LUA_TTABLE);
    lua_getfield(L, 1, "label");
    lua_getfield(L, 1, "status");
    lua_getfield(L, 1, "message");
    label = lua_tostring(L, -3);
    st = lua_tointeger(L, -2);
    msg = lua_tostring(L, -1);
    if (label == NULL) label = "unknown status";
    if (msg == NULL) msg = "";
    if (*msg != '\0') {
        lua_pushfstring(L, "itb: %s (status %d): %s", label, (int)st, msg);
    } else {
        lua_pushfstring(L, "itb: %s (status %d)", label, (int)st);
    }
    return 1;
}

/* ---- userdata payloads -------------------------------------------- */

typedef struct {
    uintptr_t handle; /* 0 after free() */
} lpipe;

typedef struct {
    uintptr_t handle; /* 0 after free() */
    int ended;
} lstream;

static lpipe *check_pipe(lua_State *L, int idx) {
    lpipe *p = (lpipe *)luaL_checkudata(L, idx, PIPE_MT);
    if (p->handle == 0) {
        luaL_error(L, "itb: pipeline already freed");
    }
    return p;
}

static lstream *check_stream(lua_State *L, int idx) {
    lstream *s = (lstream *)luaL_checkudata(L, idx, STREAM_MT);
    if (s->handle == 0) {
        luaL_error(L, "itb: stream session already freed");
    }
    return s;
}

/* ---- variable-size output helpers --------------------------------- */

/* Pre-allocation formula for message / one-shot stream outputs. */
static size_t out_cap(size_t payload) {
    size_t cap = payload + payload / 4 + 65536;
    return cap < 65536 ? 65536 : cap;
}

typedef int (*cipher_fn)(uintptr_t, void *, size_t, void *, size_t, size_t *);

/* Runs one buffer-in / buffer-out cipher entry with the retry-once
 * discipline and leaves the produced bytes on the stack as a string. */
static int cipher_call(lua_State *L, cipher_fn fn, uintptr_t handle,
                       const char *src, size_t srclen) {
    size_t cap = out_cap(srclen);
    int attempt;
    for (attempt = 0; attempt < 2; attempt++) {
        luaL_Buffer b;
        char *p = luaL_buffinitsize(L, &b, cap);
        size_t n = 0;
        int rc = fn(handle, MUT(src), srclen, p, cap, &n);
        if (rc == ST_BUFFER_TOO_SMALL && n > cap && attempt == 0) {
            luaL_pushresultsize(&b, 0);
            lua_pop(L, 1); /* discard the undersized buffer */
            cap = n;
            continue;
        }
        if (rc != ST_OK) {
            luaL_pushresultsize(&b, 0);
            lua_pop(L, 1);
            return raise_status(L, rc);
        }
        luaL_pushresultsize(&b, n);
        return 1;
    }
    /* Second BUFFER_TOO_SMALL after an exact-size retry — surface it. */
    return raise_status(L, ST_BUFFER_TOO_SMALL);
}

/* ---- module functions ---------------------------------------------- */

/* Floor capacity for blob output buffers (Init / Rekey). */
#define BLOB_CAP ((size_t)(64 * 1024))

/* Pushes a fresh Pipeline userdata wrapping `handle` with the string
 * at `blob_idx` stored as its blob uservalue. */
static void push_pipe(lua_State *L, uintptr_t handle, int blob_idx) {
    lpipe *p;
    blob_idx = lua_absindex(L, blob_idx);
    p = (lpipe *)lua_newuserdatauv(L, sizeof(*p), 1);
    p->handle = handle;
    luaL_setmetatable(L, PIPE_MT);
    lua_pushvalue(L, blob_idx);
    lua_setiuservalue(L, -2, 1);
}

/* itb.create(profile [, opts]) -> Pipeline */
static int l_create(lua_State *L) {
    const char *profile = luaL_checkstring(L, 1);
    const char *opts = luaL_optstring(L, 2, "");
    size_t cap = BLOB_CAP;
    int attempt;
    for (attempt = 0; attempt < 2; attempt++) {
        luaL_Buffer b;
        char *p = luaL_buffinitsize(L, &b, cap);
        size_t n = 0;
        uintptr_t handle = 0;
        int rc = ITB_Triple_Init(MUT(profile), MUT(opts), p, cap, &n, &handle);
        if (rc == ST_BUFFER_TOO_SMALL && n > cap && attempt == 0) {
            /* libitb closes the undersized attempt before returning;
             * the retry re-runs Init and yields a fresh session. */
            luaL_pushresultsize(&b, 0);
            lua_pop(L, 1);
            cap = n;
            continue;
        }
        if (rc != ST_OK) {
            luaL_pushresultsize(&b, 0);
            lua_pop(L, 1);
            return raise_status(L, rc);
        }
        luaL_pushresultsize(&b, n); /* blob string on stack */
        push_pipe(L, handle, -1);
        return 1;
    }
    return raise_status(L, ST_BUFFER_TOO_SMALL);
}

/* itb.open(profile, blob [, opts [, perm, wrap]]) -> Pipeline */
static int l_open(lua_State *L) {
    const char *profile = luaL_checkstring(L, 1);
    size_t bloblen = 0;
    const char *blob = luaL_checklstring(L, 2, &bloblen);
    const char *opts = luaL_optstring(L, 3, "");
    size_t permlen = 0, wraplen = 0, count = 0;
    const char *perm = "", *wrap = "";
    uintptr_t handle = 0;
    int rc;
    if (!lua_isnoneornil(L, 4) || !lua_isnoneornil(L, 5)) {
        perm = luaL_checklstring(L, 4, &permlen);
        wrap = luaL_checklstring(L, 5, &wraplen);
        if (permlen == 0 || wraplen == 0) {
            return luaL_error(L, "itb: master override buffers must be non-empty");
        }
        count = 2;
    }
    rc = ITB_Triple_Open(MUT(profile), MUT(blob), bloblen, MUT(opts),
                         MUT(perm), permlen, MUT(wrap), wraplen, count,
                         &handle);
    if (rc != ST_OK) {
        return raise_status(L, rc);
    }
    push_pipe(L, handle, 2);
    return 1;
}

/* itb.register_profile(name, opts) */
static int l_register_profile(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    const char *opts = luaL_checkstring(L, 2);
    int rc = ITB_Triple_RegisterProfile(MUT(name), MUT(opts));
    if (rc != ST_OK) {
        return raise_status(L, rc);
    }
    return 0;
}

/* itb.version() -> string */
static int l_version(lua_State *L) {
    size_t need = 0;
    int rc = ITB_Version(NULL, 0, &need);
    if (rc != ST_OK && rc != ST_BUFFER_TOO_SMALL) {
        return raise_status(L, rc);
    }
    if (need <= 1) {
        lua_pushliteral(L, "");
        return 1;
    }
    {
        luaL_Buffer b;
        char *p = luaL_buffinitsize(L, &b, need);
        rc = ITB_Version(p, need, &need);
        if (rc != ST_OK) {
            luaL_pushresultsize(&b, 0);
            lua_pop(L, 1);
            return raise_status(L, rc);
        }
        luaL_pushresultsize(&b, need > 0 ? need - 1 : 0);
    }
    return 1;
}

/* itb.hashes() -> array of {name=..., width=...} in registry order */
static int l_hashes(lua_State *L) {
    int count = ITB_HashCount();
    int i;
    lua_createtable(L, count, 0);
    for (i = 0; i < count; i++) {
        char name[128];
        size_t n = 0;
        int rc = ITB_HashName(i, name, sizeof(name), &n);
        if (rc != ST_OK) {
            return raise_status(L, rc);
        }
        lua_createtable(L, 0, 2);
        lua_pushlstring(L, name, n > 0 ? n - 1 : 0);
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, ITB_HashWidth(i));
        lua_setfield(L, -2, "width");
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

/* itb.profiles() -> array of shipped built-in profile names */
static int l_profiles(lua_State *L) {
    size_t count = sizeof(PROFILE_NAMES) / sizeof(PROFILE_NAMES[0]);
    size_t i;
    lua_createtable(L, (int)count, 0);
    for (i = 0; i < count; i++) {
        lua_pushstring(L, PROFILE_NAMES[i]);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

/* itb.set_memory_limit(bytes) -> previous limit */
static int l_set_memory_limit(lua_State *L) {
    lua_Integer limit = luaL_checkinteger(L, 1);
    lua_pushinteger(L, (lua_Integer)ITB_SetMemoryLimit((int64_t)limit));
    return 1;
}

/* itb.set_gc_percent(pct) -> previous percent */
static int l_set_gc_percent(lua_State *L) {
    lua_Integer pct = luaL_checkinteger(L, 1);
    lua_pushinteger(L, (lua_Integer)ITB_SetGCPercent((int)pct));
    return 1;
}

/* itb.now() -> monotonic wall-clock seconds (for benchmarking; Lua's
 * os.clock reports process CPU time, which over-counts the Go
 * runtime's worker threads). */
static int l_now(lua_State *L) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    lua_pushnumber(L, (lua_Number)ts.tv_sec + (lua_Number)ts.tv_nsec * 1e-9);
    return 1;
}

/* ---- Pipeline methods ---------------------------------------------- */

static int l_pipe_encrypt_message(lua_State *L) {
    lpipe *p = check_pipe(L, 1);
    size_t n = 0;
    const char *src = luaL_checklstring(L, 2, &n);
    return cipher_call(L, ITB_Triple_EncryptMessage, p->handle, src, n);
}

static int l_pipe_decrypt_message(lua_State *L) {
    lpipe *p = check_pipe(L, 1);
    size_t n = 0;
    const char *src = luaL_checklstring(L, 2, &n);
    return cipher_call(L, ITB_Triple_DecryptMessage, p->handle, src, n);
}

static int l_pipe_encrypt_stream_one_shot(lua_State *L) {
    lpipe *p = check_pipe(L, 1);
    size_t n = 0;
    const char *src = luaL_checklstring(L, 2, &n);
    return cipher_call(L, ITB_Triple_EncryptStream, p->handle, src, n);
}

static int l_pipe_decrypt_stream_one_shot(lua_State *L) {
    lpipe *p = check_pipe(L, 1);
    size_t n = 0;
    const char *src = luaL_checklstring(L, 2, &n);
    return cipher_call(L, ITB_Triple_DecryptStream, p->handle, src, n);
}

static int l_pipe_blob(lua_State *L) {
    check_pipe(L, 1);
    lua_getiuservalue(L, 1, 1);
    return 1;
}

/* pipe:rekey(perm, wrap) — rotates the parallax + wrapper masters and
 * refreshes the blob uservalue. */
static int l_pipe_rekey(lua_State *L) {
    lpipe *p = check_pipe(L, 1);
    size_t permlen = 0, wraplen = 0;
    const char *perm = luaL_checklstring(L, 2, &permlen);
    const char *wrap = luaL_checklstring(L, 3, &wraplen);
    size_t cap = BLOB_CAP;
    int attempt;
    /* Never shrink below the current blob size. */
    lua_getiuservalue(L, 1, 1);
    {
        size_t cur = 0;
        lua_tolstring(L, -1, &cur);
        if (cur > cap) cap = cur;
    }
    lua_pop(L, 1);
    for (attempt = 0; attempt < 2; attempt++) {
        luaL_Buffer b;
        char *buf = luaL_buffinitsize(L, &b, cap);
        size_t n = 0;
        int rc = ITB_Triple_Rekey(p->handle, MUT(perm), permlen, MUT(wrap),
                                  wraplen, buf, cap, &n);
        if (rc == ST_BUFFER_TOO_SMALL && n > cap && attempt == 0) {
            luaL_pushresultsize(&b, 0);
            lua_pop(L, 1);
            cap = n;
            continue;
        }
        if (rc != ST_OK) {
            luaL_pushresultsize(&b, 0);
            lua_pop(L, 1);
            return raise_status(L, rc);
        }
        luaL_pushresultsize(&b, n);
        lua_setiuservalue(L, 1, 1); /* refresh the stored blob */
        return 0;
    }
    return raise_status(L, ST_BUFFER_TOO_SMALL);
}

/* pipe:close() — zeroes the key material and marks the Pipeline
 * closed (idempotent); the handle stays registered until free(). */
static int l_pipe_close(lua_State *L) {
    lpipe *p = check_pipe(L, 1);
    int rc = ITB_Triple_Close(p->handle);
    if (rc != ST_OK) {
        return raise_status(L, rc);
    }
    return 0;
}

/* pipe:free() — releases the handle (libitb closes and zeroes key
 * material first). Safe to call more than once; also the __gc /
 * __close metamethod. */
static int l_pipe_free(lua_State *L) {
    lpipe *p = (lpipe *)luaL_checkudata(L, 1, PIPE_MT);
    if (p->handle != 0) {
        uintptr_t handle = p->handle;
        p->handle = 0;
        ITB_Triple_Free(handle);
    }
    return 0;
}

/* Shared body of encrypt_stream / decrypt_stream: opens a session and
 * pins the parent Pipeline in the session's uservalue slot so the GC
 * cannot collect the Pipeline while the session is live. */
static int pipe_stream_begin(lua_State *L, int encrypt) {
    lpipe *p = check_pipe(L, 1);
    uintptr_t sh = 0;
    int rc = encrypt ? ITB_Triple_EncryptStreamBegin(p->handle, &sh)
                     : ITB_Triple_DecryptStreamBegin(p->handle, &sh);
    lstream *s;
    if (rc != ST_OK) {
        return raise_status(L, rc);
    }
    s = (lstream *)lua_newuserdatauv(L, sizeof(*s), 1);
    s->handle = sh;
    s->ended = 0;
    luaL_setmetatable(L, STREAM_MT);
    lua_pushvalue(L, 1);         /* the parent Pipeline userdata */
    lua_setiuservalue(L, -2, 1); /* session-parent-pin */
    return 1;
}

static int l_pipe_encrypt_stream(lua_State *L) {
    return pipe_stream_begin(L, 1);
}

static int l_pipe_decrypt_stream(lua_State *L) {
    return pipe_stream_begin(L, 0);
}

/* ---- Stream methods ------------------------------------------------ */

static int l_stream_write(lua_State *L) {
    lstream *s = check_stream(L, 1);
    size_t n = 0;
    const char *src = luaL_checklstring(L, 2, &n);
    int rc = ITB_Triple_StreamWrite(s->handle, MUT(src), n);
    if (rc != ST_OK) {
        return raise_status(L, rc);
    }
    return 0;
}

/* sess:finish() — signals end-of-input (named `finish` because `end`
 * is a Lua keyword). Idempotent on the Lua side. */
static int l_stream_finish(lua_State *L) {
    lstream *s = check_stream(L, 1);
    int rc;
    if (s->ended) {
        return 0;
    }
    rc = ITB_Triple_StreamEnd(s->handle);
    if (rc != ST_OK) {
        return raise_status(L, rc);
    }
    s->ended = 1;
    return 0;
}

/* sess:read([max]) -> chunk, finished. Partial drains are normal; a
 * read before finish() never blocks. */
static int l_stream_read(lua_State *L) {
    lstream *s = check_stream(L, 1);
    lua_Integer max = luaL_optinteger(L, 2, 1 << 20);
    luaL_Buffer b;
    char *p;
    size_t n = 0;
    int fin = 0;
    int rc;
    luaL_argcheck(L, max > 0, 2, "max must be positive");
    p = luaL_buffinitsize(L, &b, (size_t)max);
    rc = ITB_Triple_StreamRead(s->handle, p, (size_t)max, &n, &fin);
    if (rc != ST_OK) {
        luaL_pushresultsize(&b, 0);
        lua_pop(L, 1);
        return raise_status(L, rc);
    }
    luaL_pushresultsize(&b, n);
    lua_pushboolean(L, fin != 0);
    return 2;
}

/* sess:drain_all() -> string. Calls finish() (if not yet called) and
 * returns every remaining output byte. */
static int l_stream_drain_all(lua_State *L) {
    lstream *s = check_stream(L, 1);
    luaL_Buffer b;
    if (!s->ended) {
        int rc = ITB_Triple_StreamEnd(s->handle);
        if (rc != ST_OK) {
            return raise_status(L, rc);
        }
        s->ended = 1;
    }
    luaL_buffinit(L, &b);
    for (;;) {
        const size_t step = 1 << 20;
        char *p = luaL_prepbuffsize(&b, step);
        size_t n = 0;
        int fin = 0;
        int rc = ITB_Triple_StreamRead(s->handle, p, step, &n, &fin);
        if (rc != ST_OK) {
            return raise_status(L, rc);
        }
        luaL_addsize(&b, n);
        if (fin) {
            break;
        }
    }
    luaL_pushresult(&b);
    return 1;
}

/* sess:free() — cancels (if still running) and releases the session.
 * Safe from any state and more than once; also __gc / __close. */
static int l_stream_free(lua_State *L) {
    lstream *s = (lstream *)luaL_checkudata(L, 1, STREAM_MT);
    if (s->handle != 0) {
        uintptr_t handle = s->handle;
        s->handle = 0;
        ITB_Triple_StreamFree(handle);
    }
    return 0;
}

/* ---- registration --------------------------------------------------- */

static const luaL_Reg PIPE_METHODS[] = {
    {"encrypt_message", l_pipe_encrypt_message},
    {"decrypt_message", l_pipe_decrypt_message},
    {"encrypt_stream_one_shot", l_pipe_encrypt_stream_one_shot},
    {"decrypt_stream_one_shot", l_pipe_decrypt_stream_one_shot},
    {"encrypt_stream", l_pipe_encrypt_stream},
    {"decrypt_stream", l_pipe_decrypt_stream},
    {"blob", l_pipe_blob},
    {"rekey", l_pipe_rekey},
    {"close", l_pipe_close},
    {"free", l_pipe_free},
    {NULL, NULL},
};

static const luaL_Reg STREAM_METHODS[] = {
    {"write", l_stream_write},
    {"finish", l_stream_finish},
    {"read", l_stream_read},
    {"drain_all", l_stream_drain_all},
    {"free", l_stream_free},
    {NULL, NULL},
};

static const luaL_Reg MODULE_FUNCS[] = {
    {"create", l_create},
    {"open", l_open},
    {"register_profile", l_register_profile},
    {"version", l_version},
    {"hashes", l_hashes},
    {"profiles", l_profiles},
    {"set_memory_limit", l_set_memory_limit},
    {"set_gc_percent", l_set_gc_percent},
    {"now", l_now},
    {NULL, NULL},
};

static void make_udata_mt(lua_State *L, const char *name,
                          const luaL_Reg *methods, lua_CFunction gc) {
    luaL_newmetatable(L, name);
    lua_pushcfunction(L, gc);
    lua_setfield(L, -2, "__gc");
    lua_pushcfunction(L, gc);
    lua_setfield(L, -2, "__close");
    lua_newtable(L);
    luaL_setfuncs(L, methods, 0);
    lua_setfield(L, -2, "__index");
    lua_pushliteral(L, "protected");
    lua_setfield(L, -2, "__metatable");
    lua_pop(L, 1);
}

int luaopen_itb(lua_State *L);

int luaopen_itb(lua_State *L) {
    size_t i;
    luaL_checkversion(L);

    make_udata_mt(L, PIPE_MT, PIPE_METHODS, l_pipe_free);
    make_udata_mt(L, STREAM_MT, STREAM_METHODS, l_stream_free);

    luaL_newmetatable(L, ERROR_MT);
    lua_pushcfunction(L, l_error_tostring);
    lua_setfield(L, -2, "__tostring");
    lua_pop(L, 1);

    luaL_newlib(L, MODULE_FUNCS);

    /* itb.status — named status codes for pcall error branching. */
    lua_createtable(L, 0, (int)(sizeof(STATUS_ROWS) / sizeof(STATUS_ROWS[0])));
    for (i = 0; i < sizeof(STATUS_ROWS) / sizeof(STATUS_ROWS[0]); i++) {
        lua_pushinteger(L, STATUS_ROWS[i].code);
        lua_setfield(L, -2, STATUS_ROWS[i].name);
    }
    lua_setfield(L, -2, "status");

    lua_pushliteral(L, ITB_LUA_VERSION);
    lua_setfield(L, -2, "_VERSION");

    return 1;
}

#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include "ngx_http_lua_cache_control.h"

#define ASSIGN_NUMBER_OR_RET(field, target, flag)                              \
    do {                                                                       \
        lua_getfield(L, n, field);                                             \
        switch(lua_type(L, -1)) {                                              \
            case LUA_TNUMBER:                                                  \
                target = lua_tonumber(L, -1);                                  \
                flag = 1;                                                      \
                break;                                                         \
            case LUA_TNIL:                                                     \
                break;                                                         \
            default:                                                           \
                return luaL_error(L, "Bad args option value");                 \
        }                                                                      \
    } while(0)

#define ASSIGN_IF_SET(field, value, flag)                                      \
    if (flag) { field = value; }

static int ngx_http_lua_ngx_get_cache_data(lua_State *L);
static int ngx_http_lua_ngx_set_cache_data(lua_State *L);
static int ngx_http_lua_ngx_cache_purge(lua_State *L);

int
ngx_http_lua_inject_cache_control_api(lua_State *L) {
    /* register reference maps */
    lua_newtable(L);    /* http_cache */

    /* .cache.purge */
    lua_pushcfunction(L, ngx_http_lua_ngx_cache_purge);
    lua_setfield(L, -2, "purge");

    /* .cache.get_metadata */
    lua_pushcfunction(L, ngx_http_lua_ngx_get_cache_data);
    lua_setfield(L, -2, "get_metadata");

    /* .cache.get_metadata */
    lua_pushcfunction(L, ngx_http_lua_ngx_set_cache_data);
    lua_setfield(L, -2, "set_metadata");

    //lua_setfield(L, -2, "cache");

    return 1;
}

static int
ngx_http_lua_ngx_get_cache_data(lua_State *L) {
    int                          n;
    ngx_http_request_t          *r;
    ngx_http_cache_t            *c;
    ngx_http_file_cache_t       *cache, cache_tmp;
    ngx_http_file_cache_sh_t    *sh, sh_tmp;
    ngx_http_file_cache_node_t  *fcn, fcn_tmp;
    u_char                      *p;


    n = lua_gettop(L);

    if (n != 0) {
        return luaL_error(L, "expecting no arguments");
    }

    r = ngx_http_lua_get_request(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua cache.metadata");

    // TODO setup empty return
    lua_createtable(L, 0, 2 /* nrec */); /* return table */

    c = r->cache;
    if (!c) {
        /* empty response */
        return 1;
    }

    /* make copies of all structs, to avoid locking for too long */
    fcn = c->node;
    cache = c->file_cache;
    sh = cache ? cache->sh : NULL;
    memset(&cache_tmp, 0, sizeof(cache_tmp));
    memset(&fcn_tmp, 0, sizeof(fcn_tmp));
    memset(&sh_tmp, 0, sizeof(sh_tmp));

    ngx_shmtx_lock(&c->file_cache->shpool->mutex);

    if (fcn) {
        fcn_tmp = *c->node;
    }

    if (cache) {
        cache_tmp = *c->file_cache;
        if (sh) {
            sh_tmp = *cache->sh;
            cache_tmp.sh = &sh_tmp;
        }
    }

    ngx_shmtx_unlock(&c->file_cache->shpool->mutex);

    p = ngx_pnalloc(r->pool, 2*NGX_HTTP_CACHE_KEY_LEN);
    if (!p) {
        return luaL_error(L, "Cannot allocate space for cache key string");
    }

    ngx_hex_dump(p, c->key, NGX_HTTP_CACHE_KEY_LEN);
    lua_pushlstring(L, "key", sizeof("key")-1);
    lua_pushlstring(L, (char*)p, 2*NGX_HTTP_CACHE_KEY_LEN);
    lua_rawset(L, -3);

    lua_pushlstring(L, "crc32", sizeof("crc32")-1);
    lua_pushnumber(L, c->crc32);
    lua_rawset(L, -3);

    lua_pushlstring(L, "valid_sec", sizeof("valid_sec")-1);
    lua_pushnumber(L, c->valid_sec);
    lua_rawset(L, -3);

    lua_pushlstring(L, "last_modified", sizeof("last_modified")-1);
    lua_pushnumber(L, c->last_modified);
    lua_rawset(L, -3);

    lua_pushlstring(L, "date", sizeof("date")-1);
    lua_pushnumber(L, c->date);
    lua_rawset(L, -3);

    lua_pushlstring(L, "length", sizeof("length")-1);
    lua_pushnumber(L, c->length);
    lua_rawset(L, -3);

    lua_pushlstring(L, "fs_size", sizeof("fs_size")-1);
    lua_pushnumber(L, c->fs_size);
    lua_rawset(L, -3);

    lua_pushlstring(L, "min_uses", sizeof("min_uses")-1);
    lua_pushnumber(L, c->min_uses);
    lua_rawset(L, -3);

    lua_pushlstring(L, "error", sizeof("error")-1);
    lua_pushnumber(L, c->error);
    lua_rawset(L, -3);

    lua_pushlstring(L, "valid_msec", sizeof("valid_msec")-1);
    lua_pushnumber(L, c->valid_msec);
    lua_rawset(L, -3);

    /* shared memory block */
    if (sh) {
        lua_createtable(L, 0, 2 /* nrec */); /* subtable */

        lua_pushlstring(L, "size", sizeof("size")-1);
        lua_pushnumber(L, sh_tmp.size);
        lua_rawset(L, -3);

        lua_setfield(L, -2, "sh");
    }

    /* cache entry */
    if (cache) {
        lua_createtable(L, 0, 8 /* nrec */); /* subtable */

        lua_pushlstring(L, "max_size", sizeof("max_size")-1);
        lua_pushnumber(L, cache_tmp.max_size);
        lua_rawset(L, -3);

        lua_pushlstring(L, "bsize", sizeof("bsize")-1);
        lua_pushnumber(L, cache_tmp.bsize);
        lua_rawset(L, -3);

        lua_pushlstring(L, "inactive", sizeof("inactive")-1);
        lua_pushnumber(L, cache_tmp.inactive);
        lua_rawset(L, -3);

        lua_pushlstring(L, "files", sizeof("files")-1);
        lua_pushnumber(L, cache_tmp.files);
        lua_rawset(L, -3);

        lua_pushlstring(L, "loader_files", sizeof("loader_files")-1);
        lua_pushnumber(L, cache_tmp.loader_files);
        lua_rawset(L, -3);

        lua_pushlstring(L, "loader_sleep", sizeof("loader_sleep")-1);
        lua_pushnumber(L, cache_tmp.loader_sleep);
        lua_rawset(L, -3);

        lua_pushlstring(L, "loader_threshold", sizeof("loader_threshold")-1);
        lua_pushnumber(L, cache_tmp.inactive);
        lua_rawset(L, -3);

        lua_setfield(L, -2, "cache");
    }

    /* file_cache_node */
    if (fcn) {
        lua_createtable(L, 0, 11 /* nrec */); /* subtable */

        lua_pushlstring(L, "count", sizeof("count")-1);
        lua_pushnumber(L, fcn_tmp.count);
        lua_rawset(L, -3);

        lua_pushlstring(L, "uses", sizeof("uses")-1);
        lua_pushnumber(L, fcn_tmp.uses);
        lua_rawset(L, -3);

        lua_pushlstring(L, "valid_msec", sizeof("valid_msec")-1);
        lua_pushnumber(L, fcn_tmp.valid_msec);
        lua_rawset(L, -3);

        lua_pushlstring(L, "error", sizeof("error")-1);
        lua_pushnumber(L, fcn_tmp.error);
        lua_rawset(L, -3);

        lua_pushlstring(L, "exists", sizeof("exists")-1);
        lua_pushnumber(L, fcn_tmp.exists);
        lua_rawset(L, -3);

        lua_pushlstring(L, "updating", sizeof("updating")-1);
        lua_pushnumber(L, fcn_tmp.updating);
        lua_rawset(L, -3);

        lua_pushlstring(L, "deleting", sizeof("deleting")-1);
        lua_pushnumber(L, fcn_tmp.deleting);
        lua_rawset(L, -3);

        lua_pushlstring(L, "exists", sizeof("exists")-1);
        lua_pushnumber(L, fcn_tmp.exists);
        lua_rawset(L, -3);

        lua_pushlstring(L, "expire", sizeof("expire")-1);
        lua_pushnumber(L, fcn_tmp.expire);
        lua_rawset(L, -3);

        lua_pushlstring(L, "valid_sec", sizeof("valid_sec")-1);
        lua_pushnumber(L, fcn_tmp.valid_sec);
        lua_rawset(L, -3);

        lua_pushlstring(L, "fs_size", sizeof("fs_size")-1);
        lua_pushnumber(L, fcn_tmp.fs_size);
        lua_rawset(L, -3);

        lua_setfield(L, -2, "fcn");
    }

    return 1;
}

static int
ngx_http_lua_ngx_set_cache_data(lua_State *L) {
    ngx_http_request_t              *r;
    ngx_http_cache_t                *c, c_tmp;
    ngx_http_file_cache_node_t      *fcn, fcn_tmp;
    int                              n; /* top of stack when we start. */
    struct {
        uint                         valid_sec:1;
        uint                         last_modified:1;
        uint                         date:1;
        uint                         min_uses:1;
        uint                         valid_msec:1;
        uint                         fcn_uses:1;
        uint                         fcn_valid_msec:1;
        uint                         fcn_expire:1;
        uint                         fcn_valid_sec:1;
    } isset;

    n = lua_gettop(L);
    if (n != 1) {
        return luaL_error(L, "only one argument is expected, but got %d", n);
    }

    luaL_checktype(L, -1, LUA_TTABLE);

    r = ngx_http_lua_get_request(L);
    if (lua_type(L, -1) != LUA_TTABLE) {
        return luaL_error(L, "the argument is not a table, "
                "but a %s",
                lua_typename(L, lua_type(L, -1)));
    }

    c = r->cache;
    if (!c) {
        lua_pushboolean(L, 0);
        return 1;
    }

    /* setup dummy copies of structs, to write into */
    fcn = c->node;
    memset(&c_tmp, 0, sizeof(c_tmp));
    memset(&fcn_tmp, 0, sizeof(fcn_tmp));
    memset(&isset, 0, sizeof(isset));

    ASSIGN_NUMBER_OR_RET("valid_sec", c_tmp.valid_sec, isset.valid_sec);
    ASSIGN_NUMBER_OR_RET("last_modified", c_tmp.last_modified,
                         isset.last_modified);
    ASSIGN_NUMBER_OR_RET("date", c_tmp.date, isset.date);
    ASSIGN_NUMBER_OR_RET("min_uses", c_tmp.min_uses, isset.min_uses);
    ASSIGN_NUMBER_OR_RET("valid_msec", c_tmp.valid_msec, isset.valid_msec);

    /* pop all we pushed on stack */
    lua_pop(L, lua_gettop(L)-n);

    /* file_cache_node */
    if (fcn && lua_type(L, n+1) == LUA_TTABLE) {
        /* push the fcn subtable onto the stack */
        lua_getfield(L, n, "fcn");
        ASSIGN_NUMBER_OR_RET("uses", fcn_tmp.uses, isset.fcn_uses);
        ASSIGN_NUMBER_OR_RET("valid_msec", fcn_tmp.valid_msec,
                             isset.fcn_valid_msec);
        ASSIGN_NUMBER_OR_RET("expire", fcn_tmp.expire, isset.fcn_expire);
        ASSIGN_NUMBER_OR_RET("valid_sec", fcn_tmp.valid_sec,
                             isset.fcn_valid_sec);

        /* pop all the entries we pushed on the stack*/
        lua_pop(L, lua_gettop(L)-n);
    }

    /* write out changes */
    ngx_shmtx_lock(&c->file_cache->shpool->mutex);

    if (isset.valid_sec) {
        c->valid_sec = c_tmp.valid_sec;
        if (c->buf && c->buf->pos) {
            ngx_http_file_cache_header_t  *h;

            h = (ngx_http_file_cache_header_t *) c->buf->pos;
            h->valid_sec = c->valid_sec;
        }
    }
    ASSIGN_IF_SET(c->last_modified, c_tmp.last_modified, isset.last_modified);
    ASSIGN_IF_SET(c->date, c_tmp.date, isset.date);
    ASSIGN_IF_SET(c->min_uses, c_tmp.min_uses, isset.min_uses);
    ASSIGN_IF_SET(c->valid_msec, c_tmp.valid_msec, isset.valid_msec);

    if (fcn) {
        ASSIGN_IF_SET(fcn->uses, fcn_tmp.uses, isset.fcn_uses);
        ASSIGN_IF_SET(fcn->valid_msec, fcn_tmp.valid_msec,isset.fcn_valid_msec);
        ASSIGN_IF_SET(fcn->expire, fcn_tmp.expire, isset.fcn_expire);
        ASSIGN_IF_SET(fcn->valid_sec, fcn_tmp.valid_sec, isset.fcn_valid_sec);
    }

    ngx_shmtx_unlock(&c->file_cache->shpool->mutex);

    /* pop the parameter off */
    lua_pop(L, 1);
    /* push a true as a return */
    lua_pushboolean(L, 1);
    return 1;
}

static int
ngx_http_lua_ngx_cache_purge(lua_State *L) {
    int                          n;
    ngx_http_request_t          *r;
    ngx_http_cache_t            *c;
    ngx_http_file_cache_t       *cache;


    n = lua_gettop(L);

    if (n != 0) {
        return luaL_error(L, "expecting no arguments");
    }

    r = ngx_http_lua_get_request(L);
    if (!r->cache || !r->cache->node || !r->cache->node->exists
        || r->cache->node->deleting) {
        lua_pushboolean (L, 0);
        return 1;
    }
    /* Inspired by Piotr Sikora's Purge module.
     * https://github.com/FRiCKLE/ngx_cache_purge
     */
    ngx_shmtx_lock(&r->cache->file_cache->shpool->mutex);
    if (!r->cache || !r->cache->node || !r->cache->node->exists) {
        /* race between concurrent purges, backoff */
        ngx_shmtx_unlock(&r->cache->file_cache->shpool->mutex);

        lua_pushboolean (L, 0);
        return 1;
    }

    c = r->cache;
    cache = c->file_cache;

#  if defined(nginx_version) && (nginx_version >= 1000001)
    cache->sh->size -= c->node->fs_size;
    c->node->fs_size = 0;
#  else
    cache->sh->size -= (c->node->length + cache->bsize - 1) / cache->bsize;
    c->node->length = 0;
#  endif

    c->node->exists = 0;
#  if defined(nginx_version) \
      && ((nginx_version >= 8001) \
          || ((nginx_version < 8000) && (nginx_version >= 7060)))
    c->node->updating = 0;
#  endif

    ngx_shmtx_unlock(&r->cache->file_cache->shpool->mutex);

    if (ngx_delete_file(r->cache->file.name.data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed while "
                      "attempting to purge bad stale.",
                      r->cache->file.name.data);
    }

    lua_pushboolean (L, 1);
    return 1;
}


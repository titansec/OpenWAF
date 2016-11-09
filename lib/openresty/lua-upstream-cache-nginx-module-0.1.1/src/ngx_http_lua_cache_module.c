#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_lua_api.h"
#include "ngx_http_lua_cache_control.h"

ngx_module_t ngx_http_lua_cache_module;

static ngx_int_t
ngx_http_lua_cache_init(ngx_conf_t *cf);

static ngx_http_module_t ngx_http_lua_cache_ctx = {
    NULL, /* preconfiguration */
    ngx_http_lua_cache_init, /* postconfiguration */
    NULL, /* create main configuration */
    NULL, /* init main configuration */
    NULL, /* create server configuration */
    NULL, /* merge server configuration */
    NULL, /* create location configuration */
    NULL /* merge location configuration */
};

ngx_module_t ngx_http_lua_cache_module = {
    NGX_MODULE_V1,
    &ngx_http_lua_cache_ctx, /* module context */
    NULL, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_lua_cache_init(ngx_conf_t *cf)
{
    ngx_http_lua_add_package_preload(cf, "http_cache",
                                     ngx_http_lua_inject_cache_control_api);
    return NGX_OK;
}

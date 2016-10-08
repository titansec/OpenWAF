
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_twaf_variables_str(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_twaf_variables_stat(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_twaf_variables_add(ngx_conf_t *cf);


static ngx_http_module_t ngx_http_twaf_variables_module_ctx = {
    ngx_http_twaf_variables_add,            /* proconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


ngx_module_t ngx_http_twaf_variables_module = {
    NGX_MODULE_V1,
    &ngx_http_twaf_variables_module_ctx,/* module context */
    NULL,                               /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_twaf_variables_vars[] = {

    {ngx_string("stat_accepted"), NULL,
     ngx_http_twaf_variables_stat, 1, NGX_HTTP_VAR_NOCACHEABLE, 0},

    {ngx_string("stat_handled"), NULL,
     ngx_http_twaf_variables_stat, 2, NGX_HTTP_VAR_NOCACHEABLE, 0},

    {ngx_string("stat_requests"), NULL,
     ngx_http_twaf_variables_stat, 3, NGX_HTTP_VAR_NOCACHEABLE, 0},

    {ngx_string("bytes_in"), NULL,
     ngx_http_twaf_variables_stat, 4, NGX_HTTP_VAR_NOCACHEABLE, 0},

    {ngx_string("exten"), NULL,
     ngx_http_twaf_variables_str, 1, NGX_HTTP_VAR_NOCACHEABLE, 0},

    {ngx_null_string, NULL, NULL, 0, 0, 0}
};


static ngx_int_t 
ngx_http_twaf_variables_str(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  value;

    switch (data) {
    case 1:
        value = r->exten;
        break;
    default:
        ngx_str_null(&value);
        break;
    }

    v->data = value.data;
    v->len = value.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t 
ngx_http_twaf_variables_stat(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{

    u_char            *p;
    ngx_atomic_int_t   value = 0;

    p = ngx_pcalloc(r->pool, NGX_ATOMIC_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

#if (NGX_STAT_STUB)
    switch (data) {
    case 1:
        value = *ngx_stat_accepted;
        break;
    case 2:
        value = *ngx_stat_handled;
        break;
    case 3:
        value = *ngx_stat_requests;
        break;
    case 4:
        value = (ngx_atomic_int_t) r->request_length;
        break;
    default:
        value = 0;
        break;
    }
#endif

    v->len = ngx_sprintf(p, "%uA", value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t 
ngx_http_twaf_variables_add(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_twaf_variables_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

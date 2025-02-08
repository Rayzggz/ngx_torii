#ifndef NGX_HTTP_TORII_AUTH_MODULE_H
#define NGX_HTTP_TORII_AUTH_MODULE_H

#include <ngx_core.h>
#include <ngx_http.h>



typedef struct {
    ngx_str_t                uri;
    ngx_array_t             *vars;
} ngx_http_torii_auth_request_conf_t;

typedef struct {
    ngx_uint_t               done;
    ngx_uint_t               status;
    ngx_http_request_t      *subrequest;
} ngx_http_torii_auth_request_ctx_t;

typedef struct {
    ngx_int_t                 index;
    ngx_http_complex_value_t  value;
    ngx_http_set_variable_pt  set_handler;
} ngx_http_torii_auth_request_variable_t;


static ngx_int_t ngx_http_torii_auth_request_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_torii_auth_request_done(ngx_http_request_t *r,
                                                  void *data, ngx_int_t rc);
static ngx_int_t ngx_http_torii_auth_request_set_variables(ngx_http_request_t *r,
                                                           ngx_http_torii_auth_request_conf_t *tarf, ngx_http_torii_auth_request_ctx_t *ctx);
static ngx_int_t ngx_http_torii_auth_request_variable(ngx_http_request_t *r,
                                                      ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_torii_auth_request_create_conf(ngx_conf_t *cf);
static char *ngx_http_torii_auth_request_merge_conf(ngx_conf_t *cf,
                                                    void *parent, void *child);
static ngx_int_t ngx_http_torii_auth_request_init(ngx_conf_t *cf);
static char *ngx_http_torii_auth_request(ngx_conf_t *cf, ngx_command_t *cmd,
                                         void *conf);
static char *ngx_http_torii_auth_request_set(ngx_conf_t *cf, ngx_command_t *cmd,
                                             void *conf);

#endif //NGX_HTTP_TORII_AUTH_MODULE_H

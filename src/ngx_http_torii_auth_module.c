#include "ngx_http_torii_auth_module.h"
#include <ngx_config.h>


static ngx_table_elt_t *ngx_http_torii_auth_request_clone_header(ngx_http_request_t *r,
                                                                ngx_list_t *list,
                                                                ngx_table_elt_t *src);
static void ngx_http_torii_auth_request_map_header_ptrs(ngx_http_headers_out_t *dst,
                                                        ngx_http_headers_out_t *src,
                                                        ngx_table_elt_t *src_header,
                                                        ngx_table_elt_t *dst_header);
static ngx_int_t ngx_http_torii_auth_request_copy_str(ngx_pool_t *pool,
                                                      ngx_str_t *dst,
                                                      ngx_str_t *src);


static ngx_command_t  ngx_http_torii_auth_request_commands[] = {

        { ngx_string("torii_auth_request"),
          NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
          ngx_http_torii_auth_request,
          NGX_HTTP_LOC_CONF_OFFSET,
          0,
          NULL },

        { ngx_string("torii_auth_request_set"),
          NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
          ngx_http_torii_auth_request_set,
          NGX_HTTP_LOC_CONF_OFFSET,
          0,
          NULL },

        ngx_null_command
};


static ngx_http_module_t  ngx_http_torii_auth_request_module_ctx = {
        NULL,                                  /* preconfiguration */
        ngx_http_torii_auth_request_init,      /* postconfiguration */

        NULL,                                  /* create main configuration */
        NULL,                                  /* init main configuration */

        NULL,                                  /* create server configuration */
        NULL,                                  /* merge server configuration */

        ngx_http_torii_auth_request_create_conf, /* create location configuration */
        ngx_http_torii_auth_request_merge_conf   /* merge location configuration */
};


ngx_module_t  ngx_http_torii_auth_request_module = {
        NGX_MODULE_V1,
        &ngx_http_torii_auth_request_module_ctx,   /* module context */
        ngx_http_torii_auth_request_commands,        /* module directives */
        NGX_HTTP_MODULE,                             /* module type */
        NULL,                                        /* init master */
        NULL,                                        /* init module */
        NULL,                                        /* init process */
        NULL,                                        /* init thread */
        NULL,                                        /* exit thread */
        NULL,                                        /* exit process */
        NULL,                                        /* exit master */
        NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_torii_auth_request_handler(ngx_http_request_t *r)
{
    ngx_http_torii_auth_request_conf_t  *tarf;
    ngx_http_torii_auth_request_ctx_t   *ctx;
    ngx_http_request_t                  *sr;
    ngx_http_post_subrequest_t          *ps;

    tarf = ngx_http_get_module_loc_conf(r, ngx_http_torii_auth_request_module);

    if (tarf->uri.len == 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "torii auth request handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_torii_auth_request_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return NGX_AGAIN;
        }

        if (ctx->status >= 200 && ctx->status < 300) {
            if (ngx_http_torii_auth_request_set_variables(r, tarf, ctx) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_OK;
        }

        sr = ctx->subrequest;

        if (ngx_http_torii_auth_request_set_variables(r, tarf, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        {
            ngx_int_t  rc;
            ngx_chain_t *out;

            if (ngx_http_torii_auth_request_copy_response(r, sr, ctx) != NGX_OK) {
                return NGX_ERROR;
            }

            rc = ngx_http_send_header(r);
            if (rc == NGX_ERROR) {
                return rc;
            }

            if (r->header_only) {
                ngx_http_finalize_request(r, NGX_OK);
                return NGX_DONE;
            }

            out = sr->out;
            if (out == NULL && sr->upstream) {
                out = sr->upstream->out_bufs;
            }

            rc = ngx_http_output_filter(r, out);
            ngx_http_finalize_request(r, rc);
            return NGX_DONE;
        }
    }


    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_torii_auth_request_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_http_torii_auth_request_done;
    ps->data = ctx;


    if (ngx_http_subrequest(r, &tarf->uri, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_WAITED|NGX_HTTP_SUBREQUEST_IN_MEMORY)
        != NGX_OK)
    {
        return NGX_ERROR;
    }


    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        return NGX_ERROR;
    }


    ctx->subrequest = sr;

    ngx_http_set_ctx(r, ctx, ngx_http_torii_auth_request_module);

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_torii_auth_request_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_torii_auth_request_ctx_t  *ctx = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "torii auth request done s:%ui", r->headers_out.status);

    ctx->done = 1;
    if (r->headers_out.status != 0) {
        ctx->status = r->headers_out.status;
    } else if (rc > 0) {
        ctx->status = rc;
    } else {
        ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_torii_auth_request_set_variables(ngx_http_request_t *r,
                                          ngx_http_torii_auth_request_conf_t *tarf, ngx_http_torii_auth_request_ctx_t *ctx)
{
    ngx_str_t                          val;
    ngx_http_variable_t               *v;
    ngx_http_variable_value_t         *vv;
    ngx_http_torii_auth_request_variable_t  *av, *last;
    ngx_http_core_main_conf_t         *cmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "torii auth request set variables");

    if (tarf->vars == NULL) {
        return NGX_OK;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    v = cmcf->variables.elts;

    av = tarf->vars->elts;
    last = av + tarf->vars->nelts;

    while (av < last) {
        vv = &r->variables[av->index];

        if (ngx_http_complex_value(ctx->subrequest, &av->value, &val)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        vv->valid = 1;
        vv->not_found = 0;
        vv->data = val.data;
        vv->len = val.len;

        if (av->set_handler) {
            av->set_handler(r, vv, v[av->index].data);
        }

        av++;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_torii_auth_request_variable(ngx_http_request_t *r,
                                     ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "torii auth request variable");

    v->not_found = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_http_torii_auth_request_copy_response(ngx_http_request_t *r,
                                          ngx_http_request_t *sr,
                                          ngx_http_torii_auth_request_ctx_t *ctx)
{
    ngx_list_part_t           *part;
    ngx_table_elt_t           *header;
    ngx_http_headers_out_t    *dst;
    ngx_http_headers_out_t    *src;
    ngx_uint_t                 i;

    dst = &r->headers_out;
    src = &sr->headers_out;

    if (ngx_list_init(&dst->headers, r->pool, 20, sizeof(ngx_table_elt_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_list_init(&dst->trailers, r->pool, 4, sizeof(ngx_table_elt_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    dst->server = NULL;
    dst->date = NULL;
    dst->content_length = NULL;
    dst->content_encoding = NULL;
    dst->location = NULL;
    dst->refresh = NULL;
    dst->last_modified = NULL;
    dst->content_range = NULL;
    dst->accept_ranges = NULL;
    dst->www_authenticate = NULL;
    dst->expires = NULL;
    dst->etag = NULL;
    dst->cache_control = NULL;
    dst->link = NULL;
    dst->override_charset = NULL;

    dst->status = ctx->status ? ctx->status : src->status;
    if (ngx_http_torii_auth_request_copy_str(r->pool, &dst->status_line,
                                             &src->status_line)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    dst->content_length_n = src->content_length_n;
    dst->content_offset = src->content_offset;
    dst->date_time = src->date_time;
    dst->last_modified_time = src->last_modified_time;
    if (ngx_http_torii_auth_request_copy_str(r->pool, &dst->content_type,
                                             &src->content_type)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    dst->content_type_len = src->content_type_len;
    if (ngx_http_torii_auth_request_copy_str(r->pool, &dst->charset,
                                             &src->charset)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    dst->content_type_lowcase = NULL;
    dst->content_type_hash = src->content_type_hash;

    part = &src->headers.part;
    header = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        {
            ngx_table_elt_t  *ho;

            ho = ngx_http_torii_auth_request_clone_header(r, &dst->headers, &header[i]);
            if (ho == NULL) {
                return NGX_ERROR;
            }

            ngx_http_torii_auth_request_map_header_ptrs(dst, src, &header[i], ho);
        }
    }

    part = &src->trailers.part;
    header = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (ngx_http_torii_auth_request_clone_header(r, &dst->trailers, &header[i]) == NULL) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_table_elt_t *
ngx_http_torii_auth_request_clone_header(ngx_http_request_t *r,
                                         ngx_list_t *list,
                                         ngx_table_elt_t *src)
{
    ngx_table_elt_t  *dst;

    dst = ngx_list_push(list);
    if (dst == NULL) {
        return NULL;
    }

    ngx_memcpy(dst, src, sizeof(ngx_table_elt_t));
    dst->next = NULL;

    if (src->key.len) {
        dst->key.data = ngx_pnalloc(r->pool, src->key.len);
        if (dst->key.data == NULL) {
            return NULL;
        }
        ngx_memcpy(dst->key.data, src->key.data, src->key.len);
    } else {
        dst->key.data = NULL;
    }

    if (src->value.len) {
        dst->value.data = ngx_pnalloc(r->pool, src->value.len);
        if (dst->value.data == NULL) {
            return NULL;
        }
        ngx_memcpy(dst->value.data, src->value.data, src->value.len);
    } else {
        dst->value.data = NULL;
    }

    if (src->lowcase_key && src->key.len) {
        dst->lowcase_key = ngx_pnalloc(r->pool, src->key.len);
        if (dst->lowcase_key == NULL) {
            return NULL;
        }
        ngx_memcpy(dst->lowcase_key, src->lowcase_key, src->key.len);
    } else {
        dst->lowcase_key = NULL;
    }

    return dst;
}


static void
ngx_http_torii_auth_request_map_header_ptrs(ngx_http_headers_out_t *dst,
                                            ngx_http_headers_out_t *src,
                                            ngx_table_elt_t *src_header,
                                            ngx_table_elt_t *dst_header)
{
    if (src->server == src_header) {
        dst->server = dst_header;
    }

    if (src->date == src_header) {
        dst->date = dst_header;
    }

    if (src->content_length == src_header) {
        dst->content_length = dst_header;
    }

    if (src->content_encoding == src_header) {
        dst->content_encoding = dst_header;
    }

    if (src->location == src_header) {
        dst->location = dst_header;
    }

    if (src->refresh == src_header) {
        dst->refresh = dst_header;
    }

    if (src->last_modified == src_header) {
        dst->last_modified = dst_header;
    }

    if (src->content_range == src_header) {
        dst->content_range = dst_header;
    }

    if (src->accept_ranges == src_header) {
        dst->accept_ranges = dst_header;
    }

    if (src->www_authenticate == src_header) {
        dst->www_authenticate = dst_header;
    }

    if (src->expires == src_header) {
        dst->expires = dst_header;
    }

    if (src->etag == src_header) {
        dst->etag = dst_header;
    }

    if (src->cache_control == src_header) {
        dst->cache_control = dst_header;
    }

    if (src->link == src_header) {
        dst->link = dst_header;
    }
}


static ngx_int_t
ngx_http_torii_auth_request_copy_str(ngx_pool_t *pool, ngx_str_t *dst,
                                     ngx_str_t *src)
{
    if (src->len == 0 || src->data == NULL) {
        dst->len = 0;
        dst->data = NULL;
        return NGX_OK;
    }

    dst->data = ngx_pnalloc(pool, src->len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst->data, src->data, src->len);
    dst->len = src->len;

    return NGX_OK;
}


static void *
ngx_http_torii_auth_request_create_conf(ngx_conf_t *cf)
{
    ngx_http_torii_auth_request_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_torii_auth_request_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->vars = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_torii_auth_request_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_torii_auth_request_conf_t *prev = parent;
    ngx_http_torii_auth_request_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->uri, prev->uri, "");
    ngx_conf_merge_ptr_value(conf->vars, prev->vars, NULL);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_torii_auth_request_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_torii_auth_request_handler;

    return NGX_OK;
}


static char *
ngx_http_torii_auth_request(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_torii_auth_request_conf_t *tarf = conf;
    ngx_str_t        *value;

    if (tarf->uri.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        tarf->uri.len = 0;
        tarf->uri.data = (u_char *) "";
        return NGX_CONF_OK;
    }

    tarf->uri = value[1];

    return NGX_CONF_OK;
}


static char *
ngx_http_torii_auth_request_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_torii_auth_request_conf_t *tarf = conf;
    ngx_str_t                         *value;
    ngx_http_variable_t               *v;
    ngx_http_torii_auth_request_variable_t  *av;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    if (tarf->vars == NGX_CONF_UNSET_PTR) {
        tarf->vars = ngx_array_create(cf->pool, 1,
                                      sizeof(ngx_http_torii_auth_request_variable_t));
        if (tarf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    av = ngx_array_push(tarf->vars);
    if (av == NULL) {
        return NGX_CONF_ERROR;
    }

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    av->index = ngx_http_get_variable_index(cf, &value[1]);
    if (av->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = ngx_http_torii_auth_request_variable;
        v->data = (uintptr_t) av;
    }

    av->set_handler = v->set_handler;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &av->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

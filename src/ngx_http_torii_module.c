
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 *
 * The nginx connector of Server Torii, derived from ngx_http_auth_request_module.
 *
 * Every protected request is sent to Server Torii as a subrequest. Torii answers
 * with a Torii-Decision response header:
 *
 *   "pass"           the request continues;
 *   any other value  the request stops here, and the response of the subrequest
 *                    (status, headers and body) is sent to the client;
 *   absent           Torii did not decide; torii_on_error applies.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_TORII_ON_ERROR_DENY  0
#define NGX_HTTP_TORII_ON_ERROR_PASS  1


typedef struct {
    ngx_flag_t                 enable;
    ngx_str_t                  endpoint;
    ngx_uint_t                 on_error;
    ngx_http_complex_value_t  *site;
    ngx_http_complex_value_t  *features;
} ngx_http_torii_loc_conf_t;


typedef struct {
    ngx_uint_t                 done;
    ngx_uint_t                 too_big;
    ngx_int_t                  rc;
    ngx_http_request_t        *subrequest;
} ngx_http_torii_ctx_t;


static ngx_int_t ngx_http_torii_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_torii_done(ngx_http_request_t *r, void *data,
    ngx_int_t rc);
static ngx_int_t ngx_http_torii_finish(ngx_http_request_t *r,
    ngx_http_torii_loc_conf_t *tlcf, ngx_http_torii_ctx_t *ctx);
static ngx_int_t ngx_http_torii_respond(ngx_http_request_t *r,
    ngx_http_request_t *sr);
static ngx_int_t ngx_http_torii_copy_headers(ngx_http_request_t *r,
    ngx_http_request_t *sr);
static ngx_table_elt_t *ngx_http_torii_find_header(ngx_list_t *headers,
    ngx_str_t *name);
static void ngx_http_torii_set_variable(ngx_http_request_t *r, ngx_int_t index,
    ngx_str_t *value);
static ngx_int_t ngx_http_torii_conf_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_torii_result_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_torii_add_variables(ngx_conf_t *cf);
static void *ngx_http_torii_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_torii_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_torii_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_http_torii_on_error[] = {
    { ngx_string("deny"), NGX_HTTP_TORII_ON_ERROR_DENY },
    { ngx_string("pass"), NGX_HTTP_TORII_ON_ERROR_PASS },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_torii_commands[] = {

    { ngx_string("torii"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_torii_loc_conf_t, enable),
      NULL },

    { ngx_string("torii_site"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_torii_loc_conf_t, site),
      NULL },

    { ngx_string("torii_features"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_torii_loc_conf_t, features),
      NULL },

    { ngx_string("torii_endpoint"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_torii_loc_conf_t, endpoint),
      NULL },

    { ngx_string("torii_on_error"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_torii_loc_conf_t, on_error),
      &ngx_http_torii_on_error },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_torii_module_ctx = {
    ngx_http_torii_add_variables,          /* preconfiguration */
    ngx_http_torii_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_torii_create_loc_conf,        /* create location configuration */
    ngx_http_torii_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_torii_module = {
    NGX_MODULE_V1,
    &ngx_http_torii_module_ctx,            /* module context */
    ngx_http_torii_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_torii_site_name = ngx_string("torii_site");
static ngx_str_t  ngx_http_torii_features_name = ngx_string("torii_features");
static ngx_str_t  ngx_http_torii_decision_name = ngx_string("torii_decision");
static ngx_str_t  ngx_http_torii_reason_name = ngx_string("torii_reason");

static ngx_str_t  ngx_http_torii_decision_header = ngx_string("Torii-Decision");
static ngx_str_t  ngx_http_torii_reason_header = ngx_string("Torii-Reason");

static ngx_str_t  ngx_http_torii_pass = ngx_string("pass");
static ngx_str_t  ngx_http_torii_error = ngx_string("error");

static ngx_int_t  ngx_http_torii_decision_index;
static ngx_int_t  ngx_http_torii_reason_index;


static ngx_int_t
ngx_http_torii_handler(ngx_http_request_t *r)
{
    ngx_http_request_t         *sr;
    ngx_http_torii_ctx_t       *ctx;
    ngx_http_variable_value_t  *vv;
    ngx_http_torii_loc_conf_t  *tlcf;
    ngx_http_post_subrequest_t *ps;

    /*
     * subrequests are never checked: the check is itself a subrequest, and
     * the client request they belong to has been checked already
     */

    if (r != r->main) {
        return NGX_DECLINED;
    }

    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_torii_module);

    if (!tlcf->enable) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "torii handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_torii_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return NGX_AGAIN;
        }

        return ngx_http_torii_finish(r, tlcf, ctx);
    }

    /*
     * an internal redirect clears the module context and runs the access
     * phase again, but keeps the variables: a request that already has
     * a decision is not sent to Torii twice, which would count it twice
     */

    vv = &r->variables[ngx_http_torii_decision_index];

    if (vv->valid && !vv->not_found && vv->len) {
        return NGX_DECLINED;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_torii_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_http_torii_done;
    ps->data = ctx;

    if (ngx_http_subrequest(r, &tlcf->endpoint, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_IN_MEMORY
                            |NGX_HTTP_SUBREQUEST_WAITED)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * allocate fake request body to avoid attempts to read it and to make
     * sure real body file (if already read) won't be closed by upstream
     */

    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        return NGX_ERROR;
    }

    ctx->subrequest = sr;

    ngx_http_set_ctx(r, ctx, ngx_http_torii_module);

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_torii_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_torii_ctx_t  *ctx = data;

    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "torii check done s:%ui rc:%i", r->headers_out.status, rc);

    ctx->done = 1;
    ctx->rc = rc;

    /*
     * A response that does not fit into subrequest_output_buffer_size makes
     * the output filter fail, and nginx then marks the client connection
     * as broken although nothing is wrong with it: the client request would
     * be closed without a response.  This is a configuration problem of the
     * check, not of the client, so the mark is taken back and the check
     * counts as "no decision", leaving the answer to torii_on_error.
     */

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->headers_out.content_length_n
        > (off_t) clcf->subrequest_output_buffer_size)
    {
        ctx->too_big = 1;
        r->connection->error = 0;

        return NGX_OK;
    }

    return rc;
}


static ngx_int_t
ngx_http_torii_finish(ngx_http_request_t *r, ngx_http_torii_loc_conf_t *tlcf,
    ngx_http_torii_ctx_t *ctx)
{
    ngx_list_t          *headers;
    ngx_table_elt_t     *decision, *reason;
    ngx_http_request_t  *sr;

    sr = ctx->subrequest;

    /*
     * the headers Torii sent are read where the upstream module parsed them,
     * so that proxy_hide_header cannot hide the decision
     */

    headers = sr->upstream ? &sr->upstream->headers_in.headers
                           : &sr->headers_out.headers;

    decision = ngx_http_torii_find_header(headers,
                                          &ngx_http_torii_decision_header);

    if (decision == NULL || decision->value.len == 0 || ctx->too_big
        || ctx->rc == NGX_ERROR)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "torii: no decision from \"%V\", status: %ui%s, %s",
                      &tlcf->endpoint, sr->headers_out.status,
                      ctx->too_big
                      ? ", response exceeds subrequest_output_buffer_size" : "",
                      tlcf->on_error == NGX_HTTP_TORII_ON_ERROR_PASS
                      ? "passing the request" : "denying the request");

        ngx_http_torii_set_variable(r, ngx_http_torii_decision_index,
                                    &ngx_http_torii_error);

        if (tlcf->on_error == NGX_HTTP_TORII_ON_ERROR_PASS) {
            return NGX_DECLINED;
        }

        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    ngx_http_torii_set_variable(r, ngx_http_torii_decision_index,
                                &decision->value);

    reason = ngx_http_torii_find_header(headers, &ngx_http_torii_reason_header);
    if (reason) {
        ngx_http_torii_set_variable(r, ngx_http_torii_reason_index,
                                    &reason->value);
    }

    if (decision->value.len == ngx_http_torii_pass.len
        && ngx_strncasecmp(decision->value.data, ngx_http_torii_pass.data,
                           ngx_http_torii_pass.len)
           == 0)
    {
        /*
         * Torii has no objection; other access modules still have their say,
         * so this is NGX_DECLINED and not NGX_OK, which would grant access
         * outright in the "satisfy any" mode
         */

        return NGX_DECLINED;
    }

    return ngx_http_torii_respond(r, sr);
}


/*
 * Sends the response of the check subrequest to the client and finalizes
 * the request.  NGX_DONE tells the access phase that nothing is left to do.
 */

static ngx_int_t
ngx_http_torii_respond(ngx_http_request_t *r, ngx_http_request_t *sr)
{
    size_t        len;
    ngx_int_t     rc;
    ngx_buf_t    *b, *body;
    ngx_chain_t   out;

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    body = sr->out ? sr->out->buf : NULL;
    len = body ? (size_t) (body->last - body->pos) : 0;

    r->headers_out.status = sr->headers_out.status;
    r->headers_out.content_length_n = len;

    r->headers_out.content_type = sr->headers_out.content_type;
    r->headers_out.content_type_len = sr->headers_out.content_type_len;
    r->headers_out.content_type_lowcase = NULL;
    r->headers_out.charset = sr->headers_out.charset;

    if (ngx_http_torii_copy_headers(r, sr) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (len) {
        /* the subrequest shares the pool of the request, the body stays valid */
        b->pos = body->pos;
        b->last = body->last;
        b->memory = 1;
    }

    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_http_finalize_request(r, rc);
        return NGX_DONE;
    }

    ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));

    return NGX_DONE;
}


static ngx_int_t
ngx_http_torii_copy_headers(ngx_http_request_t *r, ngx_http_request_t *sr)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h, *ho;

    part = &sr->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        /* nginx writes its own Date and Server; Torii-* is for the connector */

        if ((h[i].key.len == 4
             && ngx_strncasecmp(h[i].key.data, (u_char *) "Date", 4) == 0)
            || (h[i].key.len == 6
                && ngx_strncasecmp(h[i].key.data, (u_char *) "Server", 6) == 0)
            || (h[i].key.len >= 6
                && ngx_strncasecmp(h[i].key.data, (u_char *) "Torii-", 6) == 0))
        {
            continue;
        }

        ho = ngx_list_push(&r->headers_out.headers);
        if (ho == NULL) {
            return NGX_ERROR;
        }

        *ho = h[i];

#if (nginx_version >= 1023000)
        ho->next = NULL;
#endif
    }

    return NGX_OK;
}


static ngx_table_elt_t *
ngx_http_torii_find_header(ngx_list_t *headers, ngx_str_t *name)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    part = &headers->part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == name->len
            && ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0)
        {
            return &h[i];
        }
    }

    return NULL;
}


/* sets the variable explicitly, so that it survives internal redirects */

static void
ngx_http_torii_set_variable(ngx_http_request_t *r, ngx_int_t index,
    ngx_str_t *value)
{
    ngx_http_variable_value_t  *vv;

    vv = &r->variables[index];

    vv->valid = 1;
    vv->not_found = 0;
    vv->no_cacheable = 0;
    vv->data = value->data;
    vv->len = value->len;
}


/*
 * $torii_site and $torii_features.  The check runs in the location of
 * torii_endpoint, while the values belong to the location of the client
 * request, hence the configuration of the main request.
 */

static ngx_int_t
ngx_http_torii_conf_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                   value;
    ngx_http_complex_value_t   *cv;
    ngx_http_torii_loc_conf_t  *tlcf;

    tlcf = ngx_http_get_module_loc_conf(r->main, ngx_http_torii_module);

    cv = *(ngx_http_complex_value_t **) ((char *) tlcf + data);

    if (cv == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_http_complex_value(r->main, cv, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = value.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = value.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_torii_result_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_torii_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_torii_site_name,
                                NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_torii_conf_variable;
    var->data = offsetof(ngx_http_torii_loc_conf_t, site);

    var = ngx_http_add_variable(cf, &ngx_http_torii_features_name,
                                NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_torii_conf_variable;
    var->data = offsetof(ngx_http_torii_loc_conf_t, features);

    var = ngx_http_add_variable(cf, &ngx_http_torii_decision_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_torii_result_variable;

    ngx_http_torii_decision_index = ngx_http_get_variable_index(cf,
                                                &ngx_http_torii_decision_name);
    if (ngx_http_torii_decision_index == NGX_ERROR) {
        return NGX_ERROR;
    }

    var = ngx_http_add_variable(cf, &ngx_http_torii_reason_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_torii_result_variable;

    ngx_http_torii_reason_index = ngx_http_get_variable_index(cf,
                                                  &ngx_http_torii_reason_name);
    if (ngx_http_torii_reason_index == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void *
ngx_http_torii_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_torii_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_torii_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->endpoint = { 0, NULL };
     *     conf->site = NULL;
     *     conf->features = NULL;
     */

    conf->enable = NGX_CONF_UNSET;
    conf->on_error = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_torii_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_torii_loc_conf_t *prev = parent;
    ngx_http_torii_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->endpoint, prev->endpoint, "/_torii");
    ngx_conf_merge_uint_value(conf->on_error, prev->on_error,
                              NGX_HTTP_TORII_ON_ERROR_DENY);

    if (conf->site == NULL) {
        conf->site = prev->site;
    }

    if (conf->features == NULL) {
        conf->features = prev->features;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_torii_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_torii_handler;

    return NGX_OK;
}

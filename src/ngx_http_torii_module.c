
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
 *
 * When a request has been served, the module tells Torii what became of it in
 * a request report: one datagram holding one JSON object.  The reports feed
 * the traffic analysis of Torii, which otherwise sees a request only before
 * it is served.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_TORII_ON_ERROR_DENY  0
#define NGX_HTTP_TORII_ON_ERROR_PASS  1


#define NGX_HTTP_TORII_REPORT_URI_MAX      2048
#define NGX_HTTP_TORII_REPORT_HEADER_MAX   512
#define NGX_HTTP_TORII_REPORT_SHORT_MAX    128

/* after a failed send, reports are skipped for this long */
#define NGX_HTTP_TORII_REPORT_RETRY        1000

/* $torii_header_order names at most this many headers, in this many bytes */
#define NGX_HTTP_TORII_ORDER_NAMES_MAX     64
#define NGX_HTTP_TORII_ORDER_MAX           1024

/* how many values of each list of the ClientHello $torii_tls holds */
#define NGX_HTTP_TORII_TLS_VERSIONS_MAX    8
#define NGX_HTTP_TORII_TLS_CIPHERS_MAX     64
#define NGX_HTTP_TORII_TLS_EXTENSIONS_MAX  64
#define NGX_HTTP_TORII_TLS_GROUPS_MAX      32
#define NGX_HTTP_TORII_TLS_FORMATS_MAX     8
#define NGX_HTTP_TORII_TLS_SIGALGS_MAX     48
#define NGX_HTTP_TORII_TLS_ALPN_MAX        64

/* 5 bytes for a 16-bit value and its separator, 7 separators between fields */
#define NGX_HTTP_TORII_TLS_MAX                                                \
    (4 + 7                                                                    \
     + 5 * (NGX_HTTP_TORII_TLS_VERSIONS_MAX + NGX_HTTP_TORII_TLS_CIPHERS_MAX  \
            + NGX_HTTP_TORII_TLS_EXTENSIONS_MAX                               \
            + NGX_HTTP_TORII_TLS_GROUPS_MAX + NGX_HTTP_TORII_TLS_SIGALGS_MAX) \
     + 3 * NGX_HTTP_TORII_TLS_FORMATS_MAX + NGX_HTTP_TORII_TLS_ALPN_MAX)

/* the key of a report field is a string literal */
#define ngx_http_torii_field(field, key, value, max)                          \
    ngx_http_torii_set_field(field, (u_char *) key, sizeof(key) - 1, value,   \
                             max)


typedef struct {
    ngx_syslog_peer_t          peer;
    ngx_msec_t                 retry;
} ngx_http_torii_log_t;


typedef struct {
    ngx_str_t                  key;
    ngx_str_t                  value;
} ngx_http_torii_field_t;


typedef struct {
    ngx_flag_t                 enable;
    ngx_str_t                  endpoint;
    ngx_uint_t                 on_error;
    ngx_http_complex_value_t  *site;
    ngx_http_complex_value_t  *features;
    ngx_http_torii_log_t      *log;
} ngx_http_torii_loc_conf_t;


typedef struct {
    ngx_uint_t                 done;
    ngx_uint_t                 too_big;
    ngx_int_t                  rc;
    ngx_http_request_t        *subrequest;
} ngx_http_torii_ctx_t;


static ngx_int_t ngx_http_torii_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_torii_endpoint_handler(ngx_http_request_t *r);
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
static ngx_int_t ngx_http_torii_header_order_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_torii_tls_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_torii_tls_init(ngx_conf_t *cf);
static void ngx_http_torii_tls_message(int write_p, int version,
    int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
static u_char *ngx_http_torii_tls_client_hello(u_char *dst, const u_char *p,
    size_t len);
#endif
static ngx_int_t ngx_http_torii_log_handler(ngx_http_request_t *r);
static u_char *ngx_http_torii_report(ngx_http_request_t *r,
    ngx_http_torii_loc_conf_t *tlcf, size_t *len);
static void ngx_http_torii_set_field(ngx_http_torii_field_t *field,
    u_char *key, size_t key_len, ngx_str_t *value, size_t max);
static char *ngx_http_torii_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
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

    { ngx_string("torii_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_torii_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

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
static ngx_str_t  ngx_http_torii_header_order_name =
    ngx_string("torii_header_order");
static ngx_str_t  ngx_http_torii_tls_name = ngx_string("torii_tls");

#if (NGX_HTTP_SSL)
/* where a connection keeps what its ClientHello held */
static int  ngx_http_torii_tls_index = -1;
#endif

static ngx_str_t  ngx_http_torii_decision_header = ngx_string("Torii-Decision");
static ngx_str_t  ngx_http_torii_reason_header = ngx_string("Torii-Reason");

static ngx_str_t  ngx_http_torii_pass = ngx_string("pass");
static ngx_str_t  ngx_http_torii_error = ngx_string("error");

static ngx_int_t  ngx_http_torii_decision_index;
static ngx_int_t  ngx_http_torii_reason_index;

#if (NGX_HTTP_CACHE)
static ngx_str_t  ngx_http_torii_cache_name =
    ngx_string("upstream_cache_status");
static ngx_int_t  ngx_http_torii_cache_index;
#endif


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


/*
 * The check must end up in an internal location.  In a server that uses
 * "torii on" without the location of torii_endpoint the check would be served
 * by whatever location matches its URI, usually the application itself: every
 * client request would be sent there a second time.  The access phase is not
 * run for subrequests, so this is a handler of the preaccess phase.
 */

static ngx_int_t
ngx_http_torii_endpoint_handler(ngx_http_request_t *r)
{
    ngx_http_torii_ctx_t       *ctx;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_torii_loc_conf_t  *tlcf;

    if (r == r->main) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r->main, ngx_http_torii_module);

    if (ctx == NULL || ctx->subrequest != r) {
        return NGX_DECLINED;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->internal) {
        return NGX_DECLINED;
    }

    tlcf = ngx_http_get_module_loc_conf(r->main, ngx_http_torii_module);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "torii: the check \"%V\" did not reach an internal location, "
                  "is torii_endpoints.conf included in this server?",
                  &tlcf->endpoint);

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
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
     * A check that fails after Torii sent its headers ends with NGX_ERROR:
     * the response does not fit into subrequest_output_buffer_size, or Torii
     * stalled or went away before the body was complete.  nginx would then
     * terminate the client request without a response, and in the first case
     * it has also marked the client connection as broken although nothing is
     * wrong with it.  This is a problem of the check, not of the client
     * (a client that went away ends the check with another code), so the
     * mark is taken back and the check counts as "no decision", leaving the
     * answer to torii_on_error.
     */

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->headers_out.content_length_n
        > (off_t) clcf->subrequest_output_buffer_size)
    {
        ctx->too_big = 1;
    }

    if (ctx->too_big || rc == NGX_ERROR) {
        r->connection->error = 0;

        return NGX_OK;
    }

    return rc;
}


static ngx_int_t
ngx_http_torii_finish(ngx_http_request_t *r, ngx_http_torii_loc_conf_t *tlcf,
    ngx_http_torii_ctx_t *ctx)
{
    off_t                len;
    ngx_list_t          *headers;
    ngx_uint_t           incomplete;
    ngx_table_elt_t     *decision, *reason;
    ngx_http_request_t  *sr;

    sr = ctx->subrequest;

    /*
     * Torii stalled or went away in the middle of the body: nginx ends the
     * check as if it were complete, but a part of a page is not an answer
     */

    len = sr->out ? sr->out->buf->last - sr->out->buf->pos : 0;

    incomplete = sr->headers_out.content_length_n >= 0
                 && sr->headers_out.content_length_n != len;

    /*
     * the headers Torii sent are read where the upstream module parsed them,
     * so that proxy_hide_header cannot hide the decision
     */

    headers = sr->upstream ? &sr->upstream->headers_in.headers
                           : &sr->headers_out.headers;

    decision = ngx_http_torii_find_header(headers,
                                          &ngx_http_torii_decision_header);

    if (decision == NULL || decision->value.len == 0 || ctx->too_big
        || incomplete || ctx->rc == NGX_ERROR)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "torii: no decision from \"%V\", status: %ui%s, %s",
                      &tlcf->endpoint, sr->headers_out.status,
                      ctx->too_big
                      ? ", response exceeds subrequest_output_buffer_size"
                      : incomplete ? ", response is incomplete" : "",
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


/*
 * The log phase runs once for every client request, whatever became of it
 * and whatever access_log says, so this is where the request is reported.
 */

static ngx_int_t
ngx_http_torii_log_handler(ngx_http_request_t *r)
{
    size_t                      len;
    u_char                     *report;
    ssize_t                     n;
    ngx_http_torii_log_t       *tl;
    ngx_http_torii_loc_conf_t  *tlcf;

    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_torii_module);

    tl = tlcf->log;

    /*
     * only requests of a Torii site are reported: a server block that
     * neither names a site nor checks its requests has nothing to do with
     * Torii, and its traffic must not end up in the default site
     */

    if (tl == NULL || (!tlcf->enable && tlcf->site == NULL)) {
        return NGX_OK;
    }

    /*
     * while Torii is away every send fails, for a Unix socket with an alert
     * in the error log; trying once in a while keeps both the log and the
     * request path quiet
     */

    if (tl->peer.busy
        || (tl->retry && (ngx_msec_int_t) (ngx_current_msec - tl->retry) < 0))
    {
        return NGX_OK;
    }

    report = ngx_http_torii_report(r, tlcf, &len);
    if (report == NULL) {
        return NGX_ERROR;
    }

    n = ngx_syslog_send(&tl->peer, report, len);

    if (n == NGX_AGAIN) {
        /*
         * the socket buffer is full: Torii is there but busy, so only this
         * report is lost and the next one is tried as usual
         */

        tl->retry = 0;

        return NGX_OK;
    }

    if (n < 0) {
        /* Torii is not running: the report is lost */

        if (tl->retry == 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "torii: sending a request report failed, "
                          "reports are skipped until it works again");
        }

        tl->retry = ngx_current_msec + NGX_HTTP_TORII_REPORT_RETRY;

        if (tl->retry == 0) {
            tl->retry = 1;
        }

        return NGX_OK;
    }

    tl->retry = 0;

    return NGX_OK;
}


/* builds the JSON object of a request report in the pool of the request */

static u_char *
ngx_http_torii_report(ngx_http_request_t *r, ngx_http_torii_loc_conf_t *tlcf,
    size_t *len)
{
    off_t                       bytes;
    size_t                      size;
    u_char                     *buf, *p, *fp;
    ngx_str_t                   site, fetch, cache, empty;
    ngx_uint_t                  i, j, n, status, ustatus;
    ngx_time_t                 *tp;
    ngx_list_part_t            *part;
    ngx_msec_int_t              rt, urt, uct, uht;
    ngx_table_elt_t            *h, *fetches[3], *lang;
    ngx_http_variable_value_t  *vv;
    ngx_http_upstream_state_t  *state;
    ngx_http_torii_field_t      fields[13];

    static ngx_str_t  fetch_names[] = {
        ngx_string("Sec-Fetch-Dest"),
        ngx_string("Sec-Fetch-Mode"),
        ngx_string("Sec-Fetch-Site")
    };

    ngx_str_null(&empty);
    ngx_memzero(fields, sizeof(fields));
    n = 0;

    ngx_str_null(&site);

    if (tlcf->site
        && ngx_http_complex_value(r, tlcf->site, &site) != NGX_OK)
    {
        return NULL;
    }

    ngx_http_torii_field(&fields[n++], "site", &site,
                         NGX_HTTP_TORII_REPORT_SHORT_MAX);
    ngx_http_torii_field(&fields[n++], "ip", &r->connection->addr_text,
                         NGX_HTTP_TORII_REPORT_SHORT_MAX);
    ngx_http_torii_field(&fields[n++], "host", &r->headers_in.server,
                         NGX_HTTP_TORII_REPORT_HEADER_MAX);
    ngx_http_torii_field(&fields[n++], "method", &r->method_name,
                         NGX_HTTP_TORII_REPORT_SHORT_MAX);
    ngx_http_torii_field(&fields[n++], "uri", &r->unparsed_uri,
                         NGX_HTTP_TORII_REPORT_URI_MAX);

    vv = &r->variables[ngx_http_torii_decision_index];
    if (vv->valid && !vv->not_found) {
        fields[n].value.data = vv->data;
        fields[n].value.len = vv->len;
    }
    ngx_http_torii_field(&fields[n], "decision", &fields[n].value,
                         NGX_HTTP_TORII_REPORT_SHORT_MAX);
    n++;

    vv = &r->variables[ngx_http_torii_reason_index];
    if (vv->valid && !vv->not_found) {
        fields[n].value.data = vv->data;
        fields[n].value.len = vv->len;
    }
    ngx_http_torii_field(&fields[n], "reason", &fields[n].value,
                         NGX_HTTP_TORII_REPORT_SHORT_MAX);
    n++;

    ngx_http_torii_field(&fields[n++], "ua",
                         r->headers_in.user_agent
                         ? &r->headers_in.user_agent->value : &empty,
                         NGX_HTTP_TORII_REPORT_HEADER_MAX);
    ngx_http_torii_field(&fields[n++], "referer",
                         r->headers_in.referer
                         ? &r->headers_in.referer->value : &empty,
                         NGX_HTTP_TORII_REPORT_HEADER_MAX);
    ngx_http_torii_field(&fields[n++], "proto", &r->http_protocol,
                         NGX_HTTP_TORII_REPORT_SHORT_MAX);
    ngx_http_torii_field(&fields[n++], "ctype",
                         &r->headers_out.content_type,
                         NGX_HTTP_TORII_REPORT_SHORT_MAX);

    /* the request headers that have no field in headers_in, in one pass */

    fetches[0] = NULL;
    fetches[1] = NULL;
    fetches[2] = NULL;
    lang = NULL;

    part = &r->headers_in.headers.part;
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

        if (h[i].key.len == sizeof("Sec-Fetch-Dest") - 1) {
            for (j = 0; j < 3; j++) {
                if (fetches[j] == NULL
                    && ngx_strncasecmp(h[i].key.data, fetch_names[j].data,
                                       fetch_names[j].len)
                       == 0)
                {
                    fetches[j] = &h[i];
                    break;
                }
            }

        } else if (lang == NULL
                   && h[i].key.len == sizeof("Accept-Language") - 1
                   && ngx_strncasecmp(h[i].key.data,
                                      (u_char *) "Accept-Language",
                                      sizeof("Accept-Language") - 1)
                      == 0)
        {
            lang = &h[i];
        }
    }

    /* only browsers send Sec-Fetch-*; the three are reported as one value */

    ngx_str_null(&fetch);

    if (fetches[0] || fetches[1] || fetches[2]) {
        fetch.data = ngx_pnalloc(r->pool,
                                 3 * NGX_HTTP_TORII_REPORT_SHORT_MAX + 2);
        if (fetch.data == NULL) {
            return NULL;
        }

        fp = fetch.data;

        for (i = 0; i < 3; i++) {
            h = fetches[i];

            if (i) {
                *fp++ = '/';
            }

            if (h) {
                fp = ngx_cpymem(fp, h->value.data,
                                ngx_min(h->value.len,
                                        NGX_HTTP_TORII_REPORT_SHORT_MAX));
            }
        }

        fetch.len = fp - fetch.data;
    }

    ngx_http_torii_field(&fields[n++], "fetch", &fetch,
                         3 * NGX_HTTP_TORII_REPORT_SHORT_MAX + 2);

    /* the cache status has no public accessor other than its variable */

    ngx_str_null(&cache);

#if (NGX_HTTP_CACHE)

    vv = ngx_http_get_flushed_variable(r, ngx_http_torii_cache_index);

    if (vv && !vv->not_found) {
        cache.data = vv->data;
        cache.len = vv->len;
    }

#endif

    ngx_http_torii_field(&fields[n++], "cache", &cache,
                         NGX_HTTP_TORII_REPORT_SHORT_MAX);

    size = sizeof("{\"v\":1,\"ts\":,\"status\":,\"conn_reqs\":,\"lang\":true"
                  ",\"incomplete\":true"
                  ",\"rt\":,\"urt\":,\"uct\":,\"uht\":,\"ustatus\":,\"bytes\":"
                  ",\"req_len\":}")
           + 2 * NGX_TIME_T_LEN + 8 * NGX_INT_T_LEN + 2 * NGX_OFF_T_LEN;

    for (i = 0; i < n; i++) {
        if (fields[i].value.len) {
            size += sizeof(",\"\":\"\"") - 1 + fields[i].key.len
                    + fields[i].value.len
                    + ngx_escape_json(NULL, fields[i].value.data,
                                      fields[i].value.len);
        }
    }

    buf = ngx_pnalloc(r->pool, size);
    if (buf == NULL) {
        return NULL;
    }

    tp = ngx_timeofday();

    p = ngx_sprintf(buf, "{\"v\":1,\"ts\":%T%03M", tp->sec, tp->msec);

    for (i = 0; i < n; i++) {
        if (fields[i].value.len == 0) {
            continue;
        }

        p = ngx_sprintf(p, ",\"%V\":\"", &fields[i].key);
        p = (u_char *) ngx_escape_json(p, fields[i].value.data,
                                       fields[i].value.len);
        *p++ = '"';
    }

    /* the status as $status has it */

    if (r->err_status) {
        status = r->err_status;

    } else if (r->headers_out.status) {
        status = r->headers_out.status;

    } else if (r->http_version == NGX_HTTP_VERSION_9) {
        status = 9;

    } else {
        status = 0;
    }

    p = ngx_sprintf(p, ",\"status\":%ui,\"conn_reqs\":%ui", status,
                    r->connection->requests);

    if (lang) {
        p = ngx_cpymem(p, ",\"lang\":true", sizeof(",\"lang\":true") - 1);
    }

    /*
     * what $request_completion tells: the client went away, or the request
     * was given up, before the whole response was sent; the status is then
     * still the one of the response that was begun
     */

    if (!r->request_complete) {
        p = ngx_cpymem(p, ",\"incomplete\":true",
                       sizeof(",\"incomplete\":true") - 1);
    }

    rt = (ngx_msec_int_t) ((tp->sec - r->start_sec) * 1000
                           + (tp->msec - r->start_msec));

    p = ngx_sprintf(p, ",\"rt\":%i", (ngx_int_t) ngx_max(rt, 0));

    /* the last upstream that was tried is the one that answered */

    if (r->upstream_states && r->upstream_states->nelts) {
        state = r->upstream_states->elts;
        state += r->upstream_states->nelts - 1;

        urt = (ngx_msec_int_t) state->response_time;
        ustatus = state->status;

        if (urt >= 0) {
            p = ngx_sprintf(p, ",\"urt\":%i", (ngx_int_t) urt);
        }

        /* both stay -1 when the upstream was not reached, or sent no header */

        uct = (ngx_msec_int_t) state->connect_time;
        uht = (ngx_msec_int_t) state->header_time;

        if (uct >= 0) {
            p = ngx_sprintf(p, ",\"uct\":%i", (ngx_int_t) uct);
        }

        if (uht >= 0) {
            p = ngx_sprintf(p, ",\"uht\":%i", (ngx_int_t) uht);
        }

        if (ustatus) {
            p = ngx_sprintf(p, ",\"ustatus\":%ui", ustatus);
        }
    }

    bytes = r->connection->sent - (off_t) r->header_size;

    p = ngx_sprintf(p, ",\"bytes\":%O,\"req_len\":%O}", ngx_max(bytes, 0),
                    r->request_length);

    *len = p - buf;

    return buf;
}


/* a field with an empty value is left out of the report */

static void
ngx_http_torii_set_field(ngx_http_torii_field_t *field, u_char *key,
    size_t key_len, ngx_str_t *value, size_t max)
{
    field->key.data = key;
    field->key.len = key_len;

    field->value.data = value->data;
    field->value.len = ngx_min(value->len, max);
}


static char *
ngx_http_torii_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_torii_loc_conf_t *tlcf = conf;

    ngx_str_t  *value;

    if (tlcf->log != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        tlcf->log = NULL;
        return NGX_CONF_OK;
    }

    if (ngx_strncmp(value[1].data, "syslog:", 7) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\", expected \"off\" or "
                           "\"syslog:server=address\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    tlcf->log = ngx_pcalloc(cf->pool, sizeof(ngx_http_torii_log_t));
    if (tlcf->log == NULL) {
        return NGX_CONF_ERROR;
    }

    /* the address is parsed, and later written to, the way access_log does */

    return ngx_syslog_process_conf(cf, &tlcf->log->peer);
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


/*
 * $torii_header_order: the names of the request headers, in the order and
 * the case the client sent them, separated by commas.  Browsers send their
 * headers in a fixed order that the HTTP libraries of scripts do not follow,
 * and Torii cannot see the order in the check: its HTTP server keeps headers
 * in a map.
 *
 * In HTTP/2 and HTTP/3 the names are in lower case and the pseudo headers are
 * not listed.  nginx makes a "host" header out of ":authority" there, at a
 * place that depends on its version, so "host" is left out; and it puts the
 * cookies into one "cookie" header at the end.
 */

static ngx_int_t
ngx_http_torii_header_order_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char            ch, *p, *buf;
    ngx_uint_t        i, j, n;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    r = r->main;

    buf = ngx_pnalloc(r->pool, NGX_HTTP_TORII_ORDER_MAX);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    p = buf;
    n = 0;

    part = &r->headers_in.headers.part;
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

        if (r->http_version >= NGX_HTTP_VERSION_20
            && h[i].key.len == 4
            && ngx_strncasecmp(h[i].key.data, (u_char *) "host", 4) == 0)
        {
            continue;
        }

        /* a name that does not fit ends the list: a gap would misstate it */

        if (n == NGX_HTTP_TORII_ORDER_NAMES_MAX
            || (size_t) (buf + NGX_HTTP_TORII_ORDER_MAX - p)
               < h[i].key.len + 1)
        {
            break;
        }

        if (n++) {
            *p++ = ',';
        }

        /* with "ignore_invalid_headers off" a name may hold any character */

        for (j = 0; j < h[i].key.len; j++) {
            ch = h[i].key.data[j];
            *p++ = (ch <= 0x20 || ch >= 0x7f || ch == ',') ? '?' : ch;
        }
    }

    if (n == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = p - buf;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = buf;

    return NGX_OK;
}


/*
 * $torii_tls: what the ClientHello of the connection held, see
 * ngx_http_torii_tls_client_hello().  It is empty when there is nothing to
 * tell: a request without TLS, an nginx without the SSL module, a connection
 * whose ClientHello this module did not see.
 */

static ngx_int_t
ngx_http_torii_tls_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HTTP_SSL)

    ngx_str_t         *hello;
    ngx_connection_t  *c;

    c = r->connection;

    if (c->ssl && ngx_http_torii_tls_index != -1) {
        hello = SSL_get_ex_data(c->ssl->connection, ngx_http_torii_tls_index);

        if (hello) {
            v->len = hello->len;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = hello->data;

            return NGX_OK;
        }
    }

#endif

    v->not_found = 1;

    return NGX_OK;
}


#if (NGX_HTTP_SSL)

/*
 * The ClientHello is read in the message callback of OpenSSL, set for the
 * SSL context of every server.  The ClientHello callback would be the place
 * made for it, but nginx 1.29 and newer use it themselves, and it cannot be
 * shared.
 *
 * For an HTTP/3 connection this works when nginx uses the QUIC API of the SSL
 * library (seen with OpenSSL 3.5.4 and nginx 1.30.7).  With its
 * compatibility layer for an OpenSSL without that API, nginx sets a message
 * callback of its own for the connection, which takes the place of this one:
 * nothing is known of the ClientHello then, and $torii_tls is empty.
 */

static ngx_int_t
ngx_http_torii_tls_init(ngx_conf_t *cf)
{
    ngx_uint_t                   s;
    ngx_http_ssl_srv_conf_t     *sscf;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;

    if (ngx_http_torii_tls_index == -1) {
        ngx_http_torii_tls_index = SSL_get_ex_new_index(0, NULL, NULL, NULL,
                                                        NULL);
        if (ngx_http_torii_tls_index == -1) {
            ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                          "SSL_get_ex_new_index() failed");
            return NGX_ERROR;
        }
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        if (sscf == NULL || sscf->ssl.ctx == NULL) {
            continue;
        }

        SSL_CTX_set_msg_callback(sscf->ssl.ctx, ngx_http_torii_tls_message);
    }

    return NGX_OK;
}


static void
ngx_http_torii_tls_message(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    u_char            *last, text[NGX_HTTP_TORII_TLS_MAX];
    ngx_str_t         *hello;
    const u_char      *p;
    ngx_connection_t  *c;

    p = buf;

    /* called for every record and message of the connection: leave early */

    if (write_p || content_type != SSL3_RT_HANDSHAKE || len < 4
        || p[0] != SSL3_MT_CLIENT_HELLO)
    {
        return;
    }

    /* the first ClientHello counts: a second one answers HelloRetryRequest */

    if (SSL_get_ex_data(ssl, ngx_http_torii_tls_index) != NULL) {
        return;
    }

    c = ngx_ssl_get_connection(ssl);
    if (c == NULL) {
        return;
    }

    /* the message follows its type and a length of three bytes */

    last = ngx_http_torii_tls_client_hello(text, p + 4, len - 4);

    if (last == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "torii tls: malformed ClientHello");
        return;
    }

    hello = ngx_palloc(c->pool, sizeof(ngx_str_t) + (last - text));
    if (hello == NULL) {
        return;
    }

    hello->len = last - text;
    hello->data = (u_char *) hello + sizeof(ngx_str_t);
    ngx_memcpy(hello->data, text, hello->len);

    if (SSL_set_ex_data(ssl, ngx_http_torii_tls_index, hello) == 0) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "torii tls: \"%V\"", hello);
}


/* reads a vector that follows its length of one or two bytes */

static ngx_inline ngx_int_t
ngx_http_torii_tls_vector(const u_char **pos, const u_char *last,
    ngx_uint_t prefix, const u_char **data, size_t *len)
{
    size_t         n;
    const u_char  *p;

    p = *pos;

    if ((size_t) (last - p) < prefix) {
        return NGX_ERROR;
    }

    n = (prefix == 1) ? p[0] : ((size_t) p[0] << 8) + p[1];
    p += prefix;

    if ((size_t) (last - p) < n) {
        return NGX_ERROR;
    }

    *data = p;
    *len = n;
    *pos = p + n;

    return NGX_OK;
}


/*
 * Writes a 16-bit value as four hexadecimal digits.  A client that follows
 * RFC 8701 puts values picked at random out of sixteen reserved ones into its
 * lists; they are all written as 0a0a, so that the same client always reads
 * the same while it still shows that it does so, and where.
 */

static ngx_inline u_char *
ngx_http_torii_tls_value(u_char *dst, ngx_uint_t value)
{
    static u_char  hex[] = "0123456789abcdef";

    if ((value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0xff)) {
        value = 0x0a0a;
    }

    *dst++ = hex[(value >> 12) & 0xf];
    *dst++ = hex[(value >> 8) & 0xf];
    *dst++ = hex[(value >> 4) & 0xf];
    *dst++ = hex[value & 0xf];

    return dst;
}


/* writes at most max values of a list of 16-bit values, separated by commas */

static u_char *
ngx_http_torii_tls_values(u_char *dst, const u_char *data, size_t len,
    ngx_uint_t max)
{
    ngx_uint_t  n;

    for (n = 0; len >= 2 && n < max; n++) {
        if (n) {
            *dst++ = ',';
        }

        dst = ngx_http_torii_tls_value(dst, ((ngx_uint_t) data[0] << 8)
                                            + data[1]);
        data += 2;
        len -= 2;
    }

    return dst;
}


/*
 * Writes what a ClientHello holds as eight fields separated by "|":
 *
 *     legacy_version | cipher suites | extension types | supported versions
 *     | supported groups | EC point formats | signature algorithms | ALPN
 *
 * Every field but the first is a list separated by commas, in the order of
 * the client; a field the client did not send is empty.  Values are in
 * hexadecimal as they are on the wire, ALPN protocols are names.  Nothing is
 * sorted or hashed: that is left to Torii, which can then derive whatever
 * fingerprint it wants from the same data.
 *
 * The lists are cut at the limits NGX_HTTP_TORII_TLS_MAX is made of, so dst
 * needs that many bytes.  Returns NULL for a message that is not a
 * ClientHello; OpenSSL refuses such a handshake a moment later.
 */

static u_char *
ngx_http_torii_tls_client_hello(u_char *dst, const u_char *p, size_t len)
{
    u_char         ch, *start;
    size_t         n, size[5];
    ngx_uint_t     i, type, count;
    const u_char  *last, *end, *data, *ext[5];

    /* the extensions that have a field of their own, in the order above */

    static ngx_uint_t  types[] = {
        0x002b,     /* supported_versions */
        0x000a,     /* supported_groups */
        0x000b,     /* ec_point_formats */
        0x000d,     /* signature_algorithms */
        0x0010      /* application_layer_protocol_negotiation */
    };

    last = p + len;

    for (i = 0; i < 5; i++) {
        ext[i] = NULL;
        size[i] = 0;
    }

    /* legacy_version and random */

    if (len < 34) {
        return NULL;
    }

    dst = ngx_http_torii_tls_value(dst, ((ngx_uint_t) p[0] << 8) + p[1]);
    p += 34;

    /* legacy_session_id */

    if (ngx_http_torii_tls_vector(&p, last, 1, &data, &n) != NGX_OK) {
        return NULL;
    }

    if (ngx_http_torii_tls_vector(&p, last, 2, &data, &n) != NGX_OK) {
        return NULL;
    }

    *dst++ = '|';
    dst = ngx_http_torii_tls_values(dst, data, n,
                                    NGX_HTTP_TORII_TLS_CIPHERS_MAX);

    /* legacy_compression_methods */

    if (ngx_http_torii_tls_vector(&p, last, 1, &data, &n) != NGX_OK) {
        return NULL;
    }

    *dst++ = '|';

    /* a ClientHello may end here, without extensions */

    if (p < last) {
        if (ngx_http_torii_tls_vector(&p, last, 2, &data, &n) != NGX_OK) {
            return NULL;
        }

        p = data;
        end = data + n;
        count = 0;

        while (p < end) {
            if (end - p < 2) {
                return NULL;
            }

            type = ((ngx_uint_t) p[0] << 8) + p[1];
            p += 2;

            if (ngx_http_torii_tls_vector(&p, end, 2, &data, &n) != NGX_OK) {
                return NULL;
            }

            if (count < NGX_HTTP_TORII_TLS_EXTENSIONS_MAX) {
                if (count++) {
                    *dst++ = ',';
                }

                dst = ngx_http_torii_tls_value(dst, type);
            }

            for (i = 0; i < 5; i++) {
                if (type == types[i] && ext[i] == NULL) {
                    ext[i] = data;
                    size[i] = n;
                }
            }
        }
    }

    /* a list that is malformed in itself leaves its field empty */

    for (i = 0; i < 5; i++) {
        *dst++ = '|';

        if (ext[i] == NULL) {
            continue;
        }

        p = ext[i];
        end = p + size[i];

        switch (i) {

        case 0:
            if (ngx_http_torii_tls_vector(&p, end, 1, &data, &n) == NGX_OK) {
                dst = ngx_http_torii_tls_values(dst, data, n,
                                             NGX_HTTP_TORII_TLS_VERSIONS_MAX);
            }

            break;

        case 1:
            if (ngx_http_torii_tls_vector(&p, end, 2, &data, &n) == NGX_OK) {
                dst = ngx_http_torii_tls_values(dst, data, n,
                                               NGX_HTTP_TORII_TLS_GROUPS_MAX);
            }

            break;

        case 2:
            if (ngx_http_torii_tls_vector(&p, end, 1, &data, &n) == NGX_OK) {
                n = ngx_min(n, NGX_HTTP_TORII_TLS_FORMATS_MAX);

                /* these are single bytes */

                for (count = 0; count < n; count++) {
                    if (count) {
                        *dst++ = ',';
                    }

                    dst = ngx_hex_dump(dst, (u_char *) &data[count], 1);
                }
            }

            break;

        case 3:
            if (ngx_http_torii_tls_vector(&p, end, 2, &data, &n) == NGX_OK) {
                dst = ngx_http_torii_tls_values(dst, data, n,
                                              NGX_HTTP_TORII_TLS_SIGALGS_MAX);
            }

            break;

        default:
            if (ngx_http_torii_tls_vector(&p, end, 2, &data, &n) != NGX_OK) {
                break;
            }

            p = data;
            end = data + n;
            start = dst;

            /* a name that does not fit ends the list */

            while (ngx_http_torii_tls_vector(&p, end, 1, &data, &n) == NGX_OK
                   && (size_t) (dst - start) + n + 1
                      <= NGX_HTTP_TORII_TLS_ALPN_MAX)
            {
                if (dst != start) {
                    *dst++ = ',';
                }

                while (n--) {
                    ch = *data++;
                    *dst++ = (ch <= 0x20 || ch >= 0x7f || ch == ','
                              || ch == '|')
                             ? '?' : ch;
                }
            }

            break;
        }
    }

    return dst;
}

#endif


static ngx_int_t
ngx_http_torii_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_torii_header_order_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_torii_header_order_variable;

    /* declared also without the SSL module, where it is always empty */

    var = ngx_http_add_variable(cf, &ngx_http_torii_tls_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_torii_tls_variable;

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

#if (NGX_HTTP_CACHE)

    ngx_http_torii_cache_index = ngx_http_get_variable_index(cf,
                                                   &ngx_http_torii_cache_name);
    if (ngx_http_torii_cache_index == NGX_ERROR) {
        return NGX_ERROR;
    }

#endif

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
    conf->log = NGX_CONF_UNSET_PTR;

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

    ngx_conf_merge_ptr_value(conf->log, prev->log, NULL);

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

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_torii_endpoint_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_torii_log_handler;

#if (NGX_HTTP_SSL)

    if (ngx_http_torii_tls_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

#endif

    return NGX_OK;
}

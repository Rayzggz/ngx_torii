# ⛩️ngx_torii

The Nginx connector for [server_torii](https://github.com/Rayzggz/server_torii).

Every protected request is checked by Server Torii in a subrequest. When Torii
lets the request through, it continues as usual. Otherwise the module sends
Torii's answer (the block page, the rate-limit page, the CAPTCHA page with its
cookie, or a redirect) to the client directly, in the same request. No
`error_page` and no second round trip to Torii are involved.

This version speaks connector protocol v1 and is **not compatible** with the
`torii_auth_request` directives of earlier versions.

## Requirements

- nginx 1.13.10 or newer (the module keeps the response of the check in memory,
  which needs `subrequest_output_buffer_size`), or an OpenResty based on one.
  Tested with nginx 1.14.2, 1.16.1, 1.18.0, 1.20.2, 1.22.1, 1.24.0, 1.26.3, 1.28.0
  and 1.30.6, and with OpenResty 1.27.1.2, built into nginx and as a dynamic module.
- A server_torii that serves `/v1/check` and `/v1/public/`.

## Build

```bash
./configure --add-module=/path/to/ngx_torii            # static
./configure --add-dynamic-module=/path/to/ngx_torii    # dynamic: ngx_http_torii_module.so
```

## Configuration

Copy `conf/` to `<nginx conf dir>/torii/`, then:

```nginx
http {
    # Server Torii, over a Unix socket or TCP.
    upstream torii_backend {
        server unix:/run/server_torii.sock;   # or: server 127.0.0.1:25555;
        keepalive 32;
    }

    server {
        server_name example.com;

        torii_site example;                    # the site in torii.yml
        include torii/torii_endpoints.conf;    # once per server block

        location / {
            torii on;
            proxy_pass http://localhost:3001/;
        }

        location /api/ {
            torii on;
            torii_features "-challenge";       # do not challenge the API
            proxy_pass http://localhost:3001/;
        }
    }
}
```

`torii_endpoints.conf` declares the two locations the connector needs: the
internal check location `/_torii`, and `/torii/` for the endpoints browsers call
(CAPTCHA submission and the like). If `web_path` in `torii.yml` is not `/torii`,
change the second location to match. `torii_params.conf` holds the request
headers both locations send to Torii.

The Unix socket must be writable by the nginx worker user; see `listen` and
`unix_socket_mode` in `torii.yml`.

## Sites

A site is identified by its ID, never by the `Host` header the client sent. `torii_site` names
the site of a server block; the ID is one from `sites` in `torii.yml` (letters, digits and
underscores, at most 32 characters). Torii keeps rate counters, temporary blocks, logs and
traffic analysis separately for every site.

## Request reports

Torii sees a request before it is served. To learn what became of it (the status, how long it
took, whether it was an asset) the module sends Torii a *request report* when the request has
been served. Torii's traffic analysis works on these reports.

```nginx
http {
    torii_log syslog:server=unix:/run/server_torii_log.sock;   # or server=127.0.0.1:25555
}
```

The address is one of `log_listen` in `torii.yml`. Nothing else is needed: no `access_log`
line, no `log_format`. A report is sent for every request of a server block that uses Torii
(`torii on` or `torii_site`), including locations with `torii off` or `access_log off`, such as
static files. `torii_log off;` switches reports off for a server or location.

A report is one datagram holding one JSON object. Empty and zero fields are left out.

| Field | Content |
| --- | --- |
| `v`, `ts` | Format version (1); when the request ended, milliseconds since the Unix epoch |
| `site`, `ip`, `host`, `method`, `uri` | The site ID, client address, host, method and URI as requested |
| `status`, `decision`, `reason` | Response status; Torii's decision and the check behind it |
| `ua`, `referer`, `proto` | `User-Agent`, `Referer`, protocol |
| `conn_reqs` | Requests made over the connection so far |
| `fetch`, `lang` | `Sec-Fetch-Dest/Mode/Site` joined by `/`; whether `Accept-Language` was sent |
| `ctype` | `Content-Type` of the response |
| `rt`, `urt`, `ustatus`, `cache` | Time to serve and upstream time in milliseconds, upstream status, cache status |
| `bytes`, `req_len` | Response body size sent, request size |

Cookies, `Authorization`, other headers and bodies are never sent. `uri` is cut at 2048 bytes,
`ua` and `referer` at 512.

Reports are sent without blocking and are not retried: when Torii is not running or its socket
buffer is full, they are lost. A full buffer costs only the report that did not fit. When Torii
is not running the module skips reports for a second after a failed send, so an absent Torii
costs neither time nor log lines per request. A report is trusted by Torii and
not authenticated, so use a Unix socket or a loopback address.

## Directives

All directives are valid in `http`, `server` and `location`.

| Directive | Default | Meaning |
| --- | --- | --- |
| `torii on \| off` | `off` | Check requests with Server Torii. |
| `torii_site id` | — | The ID of the site in `torii.yml` whose rules apply. Without it Torii uses its `default_site`, or gives no decision when none is configured. May contain variables. |
| `torii_features "list"` | — | Force checks on or off for this location: `+name` or `-name`, separated by spaces or commas, for example `"-challenge +http_flood"`. Names are those of the sections in the site's `Server.yml`; case, `_` and `-` are ignored. The lists of the site are switched the same way, by the name they have in `lists`: `"-url_block"`. |
| `torii_endpoint uri` | `/_torii` | The location the check is sent to. It must be `internal`: a check that reaches any other location is refused and counts as "no decision", so a server without `torii_endpoints.conf` does not send its checks to the application. |
| `torii_log syslog:server=address \| off` | `off` | Where request reports are sent: a Unix datagram socket (`server=unix:/path`) or UDP (`server=host:port`). See *Request reports*. |
| `torii_on_error deny \| pass` | `deny` | What to do when Torii gives no decision (unreachable, timed out, unknown site, response too large or incomplete): answer 503, or let the request through. The error is logged either way. |

## Variables

| Variable | Value |
| --- | --- |
| `$torii_decision` | `pass`, `block`, `challenge`, `rate_limit`, or `error` when Torii gave no decision. Empty when the request was not checked. A challenge is the CAPTCHA page of the site, or a redirect to its external provider. |
| `$torii_reason` | The check behind the decision, with the list or custom rule that decided where there is one: `Lists:url_block`, `CustomRules:block-wp-scan`, `HTTPFlood`. For a challenge it is the check whose rule asked for it, or `Challenge` when the site challenges every client. |
| `$torii_site`, `$torii_features` | The values configured for the location of the request. |

```nginx
log_format torii '$remote_addr "$request" $status $torii_decision $torii_reason';
```

## Behavior notes

- **One check per client request.** An internal redirect (`try_files`,
  `error_page`, `index`) runs the access phase again, but a request that already
  has a decision is not sent to Torii a second time. `torii_features` of the
  location reached by the redirect therefore does not apply.
- **Subrequests are not checked** (SSI includes and the like); the client request
  they belong to has been.
- **The request body is never sent to Torii** by the check. Torii sees the
  original method in the `Torii-Method` header.
- **Other access modules still apply.** A pass from Torii does not grant access
  by itself, also with `satisfy any`.
- **Response size.** Torii's answer is held in memory, limited by
  `subrequest_output_buffer_size` in `torii_endpoints.conf` (64k). A larger page
  counts as "no decision", and so does a response that Torii does not finish.
- **Timeouts.** `torii_endpoints.conf` sets short proxy timeouts so that a slow
  Torii cannot hold client requests; `max_conns` on the upstream server bounds
  the number of concurrent checks.

## Protocol

Request headers sent to Torii (see `conf/torii_params.conf`): `Torii-Site`,
`Torii-Client-IP`, `Torii-Host`, `Torii-URI`, `Torii-Method`, `Torii-Features`,
plus the headers of the client request.

Response of `/v1/check`:

- `Torii-Decision: pass` — the request continues.
- `Torii-Decision: <anything else>` — the response (status, headers, body) is
  sent to the client. `Torii-*`, `Date` and `Server` headers are not copied.
- no `Torii-Decision` header — no decision; `torii_on_error` applies.

## Tests

`t/run.sh` starts a real nginx with the module in front of a real Server Torii:

```bash
NGINX_BIN=/path/to/sbin/nginx TORII_BIN=/path/to/server_torii \
TORII_SRC=/path/to/server_torii-checkout bash t/run.sh
```

nginx must be built with `--with-debug` and `--with-http_v2_module`; for a dynamic build
also set `NGX_TORII_MODULE=/path/to/ngx_http_torii_module.so`.

`t/matrix.sh` downloads and builds a list of nginx and OpenResty versions with the module
and runs that test against each:

```bash
TORII_SRC=/path/to/server_torii-checkout bash t/matrix.sh                 # the default list
TORII_SRC=/path/to/server_torii-checkout bash t/matrix.sh 1.26.3 1.28.0+dynamic openresty-1.27.1.2
```

The test covers request reports (their content, delivery over a Unix socket, locations that are
neither checked nor logged, an unreachable socket, and a block made by Torii's traffic analysis
from them), checks over TCP and a Unix socket, the pages and cookies of each
decision, HEAD and POST, keepalive, HTTP/2, `torii off`, `torii_features`,
`torii_on_error`, an unreachable Torii, an oversized or incomplete response, internal
redirects and the log variables. Running it against an nginx built with
AddressSanitizer also checks the module for memory errors.

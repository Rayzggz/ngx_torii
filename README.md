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
  which needs `subrequest_output_buffer_size`). Tested with nginx 1.30.6.
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
            torii_features "-captcha";         # no CAPTCHA for the API
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

## Directives

All directives are valid in `http`, `server` and `location`.

| Directive | Default | Meaning |
| --- | --- | --- |
| `torii on \| off` | `off` | Check requests with Server Torii. |
| `torii_site name` | — | The site whose rules apply. Without it Torii picks the site by `Host`. May contain variables. |
| `torii_features "list"` | — | Force checks on or off for this location: `+name` or `-name`, separated by spaces or commas, for example `"-captcha +http_flood"`. Names are those of the sections in the site's `Server.yml`; case, `_` and `-` are ignored. |
| `torii_endpoint uri` | `/_torii` | The internal location the check is sent to. |
| `torii_on_error deny \| pass` | `deny` | What to do when Torii gives no decision (unreachable, timed out, unknown site, response too large): answer 503, or let the request through. The error is logged either way. |

## Variables

| Variable | Value |
| --- | --- |
| `$torii_decision` | `pass`, `block`, `captcha`, `rate_limit`, `external`, or `error` when Torii gave no decision. Empty when the request was not checked. |
| `$torii_reason` | The check that stopped the request, for example `URLBlock` or `HTTPFlood`. |
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
  counts as "no decision". This relies on Torii sending `Content-Length`, which
  it does for its pages.
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

It covers checks over TCP and a Unix socket, the pages and cookies of each
decision, HEAD and POST, keepalive, HTTP/2, `torii off`, `torii_features`,
`torii_on_error`, an unreachable Torii, an oversized response, internal
redirects and the log variables. Running it against an nginx built with
AddressSanitizer also checks the module for memory errors.

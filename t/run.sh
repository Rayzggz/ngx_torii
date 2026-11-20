#!/usr/bin/env bash
# Integration test: a real nginx with this module in front of a real Server Torii.
#
#   NGINX_BIN=/path/to/sbin/nginx TORII_BIN=/path/to/server_torii \
#   TORII_SRC=/path/to/server_torii-checkout bash t/run.sh
#
# nginx must be built with --with-debug and --with-http_v2_module. The tests of $torii_tls
# need --with-http_ssl_module as well and are skipped without it.
# TORII_SRC provides the test rules and pages (tests/e2e/fixtures) and the GeoIP
# database. Everything runs on loopback out of a temporary directory.
#
# When the module was built with --add-dynamic-module, also set
# NGX_TORII_MODULE=/path/to/ngx_http_torii_module.so. t/matrix.sh builds nginx
# versions and runs this test against each.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${NGINX_BIN:?set NGINX_BIN to an nginx built with this module}"
: "${TORII_BIN:?set TORII_BIN to a server_torii binary}"
: "${TORII_SRC:?set TORII_SRC to a server_torii checkout}"
NGX_TORII_MODULE=${NGX_TORII_MODULE:-}
BASE_PORT=${BASE_PORT:-28100}
KEEP=${KEEP:-0}
# nginx does not free its configuration on exit; under ASAN that is reported as a leak
# and fails "nginx -t". Memory errors are still reported.
export ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0}

TORII_PORT=$BASE_PORT
P_TCP=$((BASE_PORT + 1))      # checks over TCP
P_UNIX=$((BASE_PORT + 2))     # checks over the Unix socket
P_FEAT=$((BASE_PORT + 3))     # torii_features turns the URL block list off
P_DENY=$((BASE_PORT + 4))     # unknown site, torii_on_error deny
P_PASS=$((BASE_PORT + 5))     # unknown site, torii_on_error pass
P_DEAD=$((BASE_PORT + 6))     # Torii unreachable
P_SMALL=$((BASE_PORT + 7))    # response larger than subrequest_output_buffer_size
P_APP=$((BASE_PORT + 8))      # the protected application
P_H2=$((BASE_PORT + 9))       # HTTP/2 without TLS
P_LOG=$((BASE_PORT + 10))     # a site whose traffic Torii analyzes
P_CAP=$((BASE_PORT + 11))     # request reports sent to a socket the test reads
P_GONE=$((BASE_PORT + 12))    # request reports sent to a socket nobody listens on
STALL_PORT=$((BASE_PORT + 13)) # a Torii that stops in the middle of its response
P_STALL=$((BASE_PORT + 14))   # checks sent to it, torii_on_error pass
P_NOEP=$((BASE_PORT + 15))    # "torii on" without the endpoint locations
SEEN_PORT=$((BASE_PORT + 16)) # a Torii that records the headers of every check
P_SEEN=$((BASE_PORT + 17))    # checks sent to it
P_TLS=$((BASE_PORT + 18))     # the same over TLS, HTTP/1.1 and HTTP/2
P_BROWSER=$((BASE_PORT + 19)) # TLS, with the browser integrity check of Torii switched on

RUN=$(mktemp -d "${TMPDIR:-/tmp}/ngx-torii-t.XXXXXXXX")
ASSERTIONS=0
PIDS=()

cleanup() {
    local status=$?
    trap - EXIT
    if [[ -f "$RUN/nginx/logs/nginx.pid" ]]; then kill -QUIT "$(cat "$RUN/nginx/logs/nginx.pid")" 2>/dev/null || true; fi
    for pid in "${PIDS[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    if (( status != 0 )); then
        echo "--- nginx error log (non-debug lines)" >&2
        grep -v '\[debug\]' "$RUN/nginx/logs/error.log" 2>/dev/null | tail -n 20 >&2 || true
        echo "--- torii startup log" >&2
        tail -n 10 "$RUN/torii/log/startup.log" 2>/dev/null >&2 || true
    fi
    if [[ "$KEEP" == 1 ]]; then echo "Artifacts: $RUN"; else rm -rf -- "$RUN"; fi
    exit "$status"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
assert_eq() {
    ASSERTIONS=$((ASSERTIONS + 1))
    [[ "$1" == "$2" ]] || fail "${3:-assertion}: expected <$2>, got <$1>"
}
assert_contains() {
    ASSERTIONS=$((ASSERTIONS + 1))
    [[ "$1" == *"$2"* ]] || fail "${3:-assertion}: missing <$2> in <$1>"
}
# get PORT PATH [curl args]: sets CODE, BODY and the headers file $RUN/h.
get() {
    local port=$1 path=$2
    shift 2
    CODE=$(curl --silent --show-error --noproxy '*' --max-time 10 -D "$RUN/h" -o "$RUN/b" \
        -w '%{http_code}' "$@" "http://127.0.0.1:$port$path") || fail "transport error: $port$path"
    BODY=$(cat "$RUN/b")
}
header() { awk -v key="$1:" 'tolower($1)==tolower(key) {$1=""; sub(/^ /, ""); sub(/\r$/, ""); print}' "$RUN/h"; }
header_count() { awk -v key="$1:" 'tolower($1)==tolower(key) {n++} END {print n+0}' "$RUN/h"; }

# ---------------------------------------------------------------- Server Torii
mkdir -p "$RUN/torii/log" "$RUN/torii/data" "$RUN/torii/rules"
cp -R "$TORII_SRC/tests/e2e/fixtures/pages" "$RUN/torii/pages"
cp -R "$TORII_SRC/tests/e2e/fixtures/rules" "$RUN/torii/rules/default"
cp -R "$TORII_SRC/tests/e2e/fixtures/rules" "$RUN/torii/rules/shop"
# A site with traffic analysis: clients that keep getting errors are blocked.
cp -R "$TORII_SRC/tests/e2e/fixtures/rules" "$RUN/torii/rules/logs"
sed -i '/^traffic_analyzer:/,/^  uri_detection:/s/enabled: false/enabled: true/' "$RUN/torii/rules/logs/Server.yml"
sed -i '/^  ip_detection:/,/^[^ ]/s/enabled: false/enabled: true/' "$RUN/torii/rules/logs/Server.yml"
cp "$TORII_SRC/config_example/data/GeoLite2-Country.mmdb" "$RUN/torii/data/"
# A page that does not fit a small subrequest buffer.
head -c 4096 /dev/zero | tr '\0' 'x' >> "$RUN/torii/pages/429.html"
SOCK="$RUN/torii/torii.sock"
LOGSOCK="$RUN/torii/log.sock"
CAPSOCK="$RUN/cap.sock"
cat > "$RUN/torii/torii.yml" <<EOF
listen: ["127.0.0.1:$TORII_PORT", "unix:$SOCK"]
log_listen: ["unix:$LOGSOCK"]
web_path: /torii
error_page: "$RUN/torii/pages"
log_path: "$RUN/torii/log"
global_secret: "test-only-global-secret-never-use-in-production"
node_name: "Node_T"
sites:
  - id: default_site
    rule_path: "$RUN/torii/rules/default"
  - id: shop
    rule_path: "$RUN/torii/rules/shop"
  - id: logs
    rule_path: "$RUN/torii/rules/logs"
default_site: default_site
EOF
"$TORII_BIN" -config "$RUN/torii/torii.yml" > "$RUN/torii/log/startup.log" 2>&1 &
PIDS+=("$!")

# Reads the request reports of one server block, one JSON object per line.
python3 - "$CAPSOCK" > "$RUN/cap.jsonl" <<'PY' &
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(sys.argv[1])
while True:
    print(s.recv(65535).decode("utf-8", "replace"), flush=True)
PY
PIDS+=("$!")

# A Torii that sends its headers and half of the body, then nothing more.
python3 - "$STALL_PORT" <<'PY' &
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(8)
held = []
while True:
    c, _ = s.accept()
    c.recv(65535)
    c.sendall(b"HTTP/1.1 403 Forbidden\r\nTorii-Decision: block\r\nContent-Type: text/html\r\n"
              b"Content-Length: 100\r\n\r\nhalf a page")
    held.append(c)
PY
PIDS+=("$!")

# A Torii that lets every request pass and writes the headers of the check, one JSON object
# per line with the names in lower case.
python3 - "$SEEN_PORT" "$RUN/seen.jsonl" <<'PY' &
import json, socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(64)
out = open(sys.argv[2], "a")
while True:
    c, _ = s.accept()
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = c.recv(65535)
        if not chunk:
            break
        data += chunk
    headers = {}
    for line in data.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    out.write(json.dumps(headers) + "\n")
    out.flush()
    c.sendall(b"HTTP/1.1 200 OK\r\nTorii-Decision: pass\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    c.close()
PY
PIDS+=("$!")

# ----------------------------------------------------------------------- nginx
# "nginx version: nginx/1.26.3" or "nginx version: openresty/1.27.1.2".
NGINX_VERSION=$("$NGINX_BIN" -v 2>&1 | sed -n 's|^nginx version: [^/]*/\([0-9.]*\).*|\1|p')
[[ -n "$NGINX_VERSION" ]] || fail "cannot read the version of $NGINX_BIN"
# version_ge A B: version A is B or newer, comparing the first three components.
version_ge() {
    local a b
    IFS=. read -r -a a <<< "$1"
    IFS=. read -r -a b <<< "$2"
    local i
    for i in 0 1 2; do
        (( ${a[i]:-0} > ${b[i]:-0} )) && return 0
        (( ${a[i]:-0} < ${b[i]:-0} )) && return 1
    done
    return 0
}
# The "http2" directive replaced the "http2" parameter of "listen" in 1.25.1.
if version_ge "$NGINX_VERSION" 1.25.1; then
    H2_LISTEN='' H2_DIRECTIVE='http2 on;'
else
    H2_LISTEN=' http2' H2_DIRECTIVE=''
fi
# $torii_tls needs the SSL module; without it the variable exists and is empty.
HAVE_SSL=0 TLS_SERVER='' NO_SSL=''
if "$NGINX_BIN" -V 2>&1 | grep -q -- '--with-http_ssl_module'; then HAVE_SSL=1; else NO_SSL=', no SSL module'; fi
LOAD_MODULE=''
[[ -z "$NGX_TORII_MODULE" ]] || LOAD_MODULE="load_module $NGX_TORII_MODULE;"
echo "nginx $NGINX_VERSION${NGX_TORII_MODULE:+, dynamic module}$NO_SSL"

mkdir -p "$RUN/nginx/logs" "$RUN/nginx/conf/torii"
cp "$ROOT/conf/"*.conf "$RUN/nginx/conf/torii/"
# The same endpoints with another upstream or buffer size, for the failure cases.
sed 's/torii_backend/torii_unix/' "$ROOT/conf/torii_endpoints.conf" > "$RUN/nginx/conf/torii/unix.conf"
sed 's/torii_backend/torii_dead/' "$ROOT/conf/torii_endpoints.conf" > "$RUN/nginx/conf/torii/dead.conf"
sed 's/subrequest_output_buffer_size 64k/subrequest_output_buffer_size 1k/' \
    "$ROOT/conf/torii_endpoints.conf" > "$RUN/nginx/conf/torii/small.conf"
sed 's/torii_backend/torii_stall/; s/proxy_read_timeout 5s/proxy_read_timeout 1s/' \
    "$ROOT/conf/torii_endpoints.conf" > "$RUN/nginx/conf/torii/stall.conf"
sed 's/torii_backend/torii_seen/' "$ROOT/conf/torii_endpoints.conf" > "$RUN/nginx/conf/torii/seen.conf"

if (( HAVE_SSL )); then
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=torii.test \
        -keyout "$RUN/nginx/conf/tls.key" -out "$RUN/nginx/conf/tls.crt" 2> /dev/null || fail 'cannot make a certificate'
    TLS_SERVER="
    server {
        listen 127.0.0.1:$P_TLS ssl$H2_LISTEN;
        $H2_DIRECTIVE
        ssl_certificate tls.crt;
        ssl_certificate_key tls.key;
        torii on;
        torii_site shop;
        include torii/seen.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
    }

    server {
        listen 127.0.0.1:$P_BROWSER ssl$H2_LISTEN;
        $H2_DIRECTIVE
        ssl_certificate tls.crt;
        ssl_certificate_key tls.key;
        torii on;
        torii_site shop;
        torii_features \"+browser_integrity\";
        include torii/torii_endpoints.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
    }"
fi

cat > "$RUN/nginx/conf/nginx.conf" <<EOF
$LOAD_MODULE
daemon on;
worker_processes 1;
error_log logs/error.log debug;
pid logs/nginx.pid;
events { worker_connections 256; }
http {
    log_format torii '\$request_uri|\$status|\$torii_decision|\$torii_reason|\$torii_site';
    access_log logs/access.log torii;

    upstream torii_backend { server 127.0.0.1:$TORII_PORT; keepalive 8; }
    upstream torii_unix    { server unix:$SOCK; keepalive 8; }
    upstream torii_dead    { server 127.0.0.1:1; }
    upstream torii_stall   { server 127.0.0.1:$STALL_PORT; }
    upstream torii_seen    { server 127.0.0.1:$SEEN_PORT; }

    torii_log syslog:server=unix:$LOGSOCK;

    server {
        listen 127.0.0.1:$P_APP;
        access_log logs/app.log torii;
        location / { return 200 "APP \$request_method \$request_uri\n"; }
        location /missing { return 404 "missing\n"; }
    }

    server {
        listen 127.0.0.1:$P_TCP;
        torii on;
        torii_site shop;
        include torii/torii_endpoints.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
        location /open/ { torii off; proxy_pass http://127.0.0.1:$P_APP; }
        # An internal redirect runs the access phase a second time.
        location /redirected { try_files /nonexistent @app; }
        location @app { proxy_pass http://127.0.0.1:$P_APP; }
    }

    server {
        listen 127.0.0.1:$P_UNIX;
        torii on;
        torii_site shop;
        include torii/unix.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
    }

    server {
        listen 127.0.0.1:$P_FEAT;
        torii on;
        torii_site shop;
        torii_features "-url_block";
        include torii/torii_endpoints.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
        location /strict/ { torii_features "+challenge"; proxy_pass http://127.0.0.1:$P_APP; }
    }

    server {
        listen 127.0.0.1:$P_DENY;
        torii on;
        torii_site no_such_site;
        include torii/torii_endpoints.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
    }

    server {
        listen 127.0.0.1:$P_PASS;
        torii on;
        torii_site no_such_site;
        torii_on_error pass;
        include torii/torii_endpoints.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
    }

    server {
        listen 127.0.0.1:$P_DEAD;
        torii on;
        torii_site shop;
        include torii/dead.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
    }

    server {
        listen 127.0.0.1:$P_SMALL;
        torii on;
        torii_site shop;
        torii_features "+http_flood";
        include torii/small.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
    }

    server {
        listen 127.0.0.1:$P_STALL;
        torii on;
        torii_site shop;
        torii_on_error pass;
        include torii/stall.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
    }

    server {
        listen 127.0.0.1:$P_NOEP;
        torii on;
        torii_site shop;
        torii_on_error pass;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
    }

    server {
        listen 127.0.0.1:$P_LOG;
        torii on;
        torii_site logs;
        include torii/torii_endpoints.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
        # Not checked and not in the access log, but still reported.
        location /assets/ { torii off; access_log off; proxy_pass http://127.0.0.1:$P_APP; }
    }

    server {
        listen 127.0.0.1:$P_CAP;
        torii on;
        torii_site shop;
        torii_log syslog:server=unix:$CAPSOCK;
        include torii/torii_endpoints.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
        location /quiet/ { torii_log off; proxy_pass http://127.0.0.1:$P_APP; }
    }

    server {
        listen 127.0.0.1:$P_GONE;
        torii on;
        torii_site shop;
        torii_log syslog:server=unix:$RUN/gone.sock;
        include torii/torii_endpoints.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
    }

    server {
        listen 127.0.0.1:$P_H2$H2_LISTEN;
        $H2_DIRECTIVE
        torii on;
        torii_site shop;
        include torii/torii_endpoints.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
    }

    server {
        listen 127.0.0.1:$P_SEEN;
        torii on;
        torii_site shop;
        include torii/seen.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
    }
$TLS_SERVER
}
EOF
"$NGINX_BIN" -p "$RUN/nginx" -c conf/nginx.conf -t 2> "$RUN/nginx-t.log" || { cat "$RUN/nginx-t.log" >&2; fail 'nginx -t'; }

# nginx reports every request, the readiness probes below included. A report sent before its
# listener exists is an [alert] in the error log, so nginx starts once the sockets are there.
deadline=$((SECONDS + 20))
until [[ -S "$SOCK" && -S "$LOGSOCK" && -S "$CAPSOCK" ]]; do
    (( SECONDS < deadline )) || fail 'Torii and the report reader did not open their sockets within 20 seconds'
    sleep 0.1
done
"$NGINX_BIN" -p "$RUN/nginx" -c conf/nginx.conf

deadline=$((SECONDS + 20))
until curl --silent --noproxy '*' --max-time 2 "http://127.0.0.1:$P_TCP/torii/health_check" 2>/dev/null | grep -q 'sliver=Node_T'; do
    (( SECONDS < deadline )) || fail 'nginx + Torii not ready within 20 seconds'
    sleep 0.2
done

# ----------------------------------------------------------------------- tests
for port in $P_TCP $P_UNIX; do
    # Pass: the request reaches the application.
    get "$port" /neutral
    assert_eq "$CODE" 200 "pass status ($port)"
    assert_eq "$BODY" 'APP GET /neutral' "pass body ($port)"

    # Deny: the client gets Torii's page in the same request, with nginx's own headers.
    get "$port" /blocked
    assert_eq "$CODE" 403 "block status ($port)"
    assert_contains "$BODY" 'E2E-403 Node_T 127.0.0.1' "block page ($port)"
    assert_contains "$(header Content-Type)" text/html "block content type ($port)"
    assert_eq "$(header Content-Length)" "$(wc -c < "$RUN/b" | tr -d ' ')" "block content length ($port)"
    assert_eq "$(header_count Date)" 1 "one Date header ($port)"
    assert_eq "$(header_count Server)" 1 "one Server header ($port)"
    assert_eq "$(header Torii-Decision)" '' "connector headers stay inside ($port)"

    # The CAPTCHA page arrives with its session cookie.
    get "$port" /challenge
    assert_eq "$CODE" 503 "captcha status ($port)"
    assert_contains "$BODY" E2E-ALTCHA "captcha page ($port)"
    assert_contains "$(header Set-Cookie)" __torii_session_id= "captcha session cookie ($port)"

    # Browser-facing endpoints of Torii.
    get "$port" /torii/health_check
    assert_eq "$CODE" 200 "public endpoint ($port)"
    assert_contains "$BODY" 'sliver=Node_T' "public endpoint body ($port)"
done

# The original method reaches Torii and the application; a request body is not sent to Torii.
get "$P_TCP" /neutral -X POST --data 'a=1&b=2'
assert_eq "$CODE" 200 'POST pass status'
assert_eq "$BODY" 'APP POST /neutral' 'POST pass body'
get "$P_TCP" /blocked -X POST --data 'a=1&b=2'
assert_eq "$CODE" 403 'POST block status'
assert_contains "$BODY" E2E-403 'POST block page'

# HEAD gets the status and headers without a body.
get "$P_TCP" /blocked --head
assert_eq "$CODE" 403 'HEAD block status'
# curl writes the headers of a HEAD response to the body file: nothing may follow them.
assert_eq "$(tail -c 4 "$RUN/b" | od -An -tx1 | tr -d ' \n')" 0d0a0d0a 'HEAD block has no body'

# Several denied requests on one connection: the response is complete each time.
CODES=$(curl --silent --noproxy '*' --max-time 10 -o /dev/null -w '%{http_code} ' \
    "http://127.0.0.1:$P_TCP/blocked" -o /dev/null "http://127.0.0.1:$P_TCP/neutral"     -o /dev/null "http://127.0.0.1:$P_TCP/blocked")
assert_eq "$CODES" '403 200 403 ' 'keepalive sequence'

# torii off and torii_features.
get "$P_TCP" /open/blocked
assert_eq "$CODE" 200 'torii off'
get "$P_FEAT" /blocked
assert_eq "$CODE" 200 'feature forced off at server level'
get "$P_FEAT" /strict/page
assert_eq "$CODE" 503 'feature forced on at location level'
assert_contains "$BODY" E2E-ALTCHA 'location-level feature page'

# No decision: unknown site, Torii unreachable, response too large.
get "$P_DENY" /neutral
assert_eq "$CODE" 503 'unknown site, on_error deny'
get "$P_PASS" /neutral
assert_eq "$CODE" 200 'unknown site, on_error pass'
assert_eq "$BODY" 'APP GET /neutral' 'on_error pass body'
get "$P_DEAD" /neutral
assert_eq "$CODE" 503 'Torii unreachable'
get "$P_SMALL" /neutral
assert_eq "$CODE" 200 'small buffer still fits a pass'
for i in 1 2 3 4 5 6; do get "$P_SMALL" "/flood$i"; done
assert_eq "$CODE" 503 'page larger than the buffer is no decision'
# A response that stops halfway is no decision either, not a closed client connection.
get "$P_STALL" /neutral
assert_eq "$CODE" 200 'incomplete response, on_error pass'
assert_eq "$BODY" 'APP GET /neutral' 'incomplete response, on_error pass body'
# Without the endpoint location the check is refused instead of being sent to the application.
get "$P_NOEP" /neutral
assert_eq "$CODE" 200 'no endpoint location, on_error pass'
sleep 0.3
ASSERTIONS=$((ASSERTIONS + 2))
grep -q 'did not reach an internal location' "$RUN/nginx/logs/error.log" || fail 'a missing endpoint location is not named in the error log'
! grep -q '^/_torii' "$RUN/nginx/logs/app.log" || fail 'the check reached the application'

# One check per client request, even across an internal redirect.
checks_before=$(grep -c 'torii check done' "$RUN/nginx/logs/error.log" || true)
get "$P_TCP" '/redirected?marker=once'
assert_eq "$CODE" 200 'internal redirect status'
assert_eq "$BODY" 'APP GET /redirected?marker=once' 'internal redirect body'
checks_after=$(grep -c 'torii check done' "$RUN/nginx/logs/error.log" || true)
assert_eq "$((checks_after - checks_before))" 1 'one check for a redirected request'

# HTTP/2.
if curl --version | grep -q HTTP2; then
    get "$P_H2" /blocked --http2-prior-knowledge
    assert_eq "$CODE" 403 'HTTP/2 block status'
    assert_contains "$BODY" E2E-403 'HTTP/2 block page'
    get "$P_H2" /neutral --http2-prior-knowledge
    assert_eq "$CODE" 200 'HTTP/2 pass status'
else
    echo 'SKIP: curl has no HTTP/2 support'
fi

# ------------------------------------------------- what the check tells Torii
# seen URI FILTER: the value jq extracts from the headers of the last check for URI.
seen() { jq -r --arg uri "$1" 'select(.["torii-uri"] == $uri) | '"$2" "$RUN/seen.jsonl" | tail -n 1; }

# The names of the request headers as the client sent them. A header the connector sets is
# never the one the client sent, and an empty one is not sent at all.
get "$P_SEEN" /order -A order-test -H 'X-b: 1' -H 'x-A: 2' -H 'Torii-TLS: forged' -H 'Torii-Scheme: forged'
assert_eq "$CODE" 200 'recorded check status'
assert_eq "$(seen /order '.["torii-header-order"]')" 'Host,User-Agent,Accept,X-b,x-A,Torii-TLS,Torii-Scheme' 'header order'
assert_eq "$(seen /order '.["torii-scheme"]')" http 'scheme'
assert_eq "$(seen /order '.["torii-proto"]')" HTTP/1.1 'protocol'
assert_eq "$(seen /order '.["torii-tls"]')" null 'no TLS data without TLS, whatever the client claims'
many=()
for i in $(seq 70); do many+=(-H "X-H$i: 1"); done
get "$P_SEEN" /many "${many[@]}"
assert_eq "$(seen /many '.["torii-header-order"] | split(",") | length')" 64 'header order is cut at 64 names'

if (( HAVE_SSL )); then
    # tls URI FIELD: one of the eight fields of Torii-TLS, counted from 0.
    tls() { seen "$1" '.["torii-tls"] | split("|") | .['"$2"']'; }

    # A ClientHello whose content the client was told on the command line.
    printf 'GET /tls12 HTTP/1.1\r\nHost: torii.test\r\nConnection: close\r\n\r\n' \
        | timeout 10 openssl s_client -quiet -connect "127.0.0.1:$P_TLS" -servername torii.test -tls1_2 \
            -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -sigalgs RSA+SHA256 -alpn http/1.1,torii-x \
            > "$RUN/b" 2> /dev/null || true
    assert_contains "$(cat "$RUN/b")" 'APP GET /tls12' 'request over TLS 1.2'
    assert_eq "$(seen /tls12 '.["torii-tls"] | split("|") | length')" 8 'TLS fields'
    assert_eq "$(tls /tls12 0)" 0303 'TLS legacy version'
    assert_eq "$(tls /tls12 1 | cut -d, -f1)" c02f 'TLS cipher suites'
    assert_contains ",$(tls /tls12 2)," ',0000,' 'TLS extensions: server name'
    assert_contains ",$(tls /tls12 2)," ',0010,' 'TLS extensions: ALPN'
    assert_eq "$(tls /tls12 3)" '' 'TLS supported versions, not sent by a TLS 1.2 client'
    assert_eq "$(tls /tls12 4)" 0017 'TLS groups'
    assert_eq "$(tls /tls12 6)" 0401 'TLS signature algorithms'
    assert_eq "$(tls /tls12 7)" http/1.1,torii-x 'TLS ALPN protocols'
    assert_eq "$(seen /tls12 '.["torii-scheme"]')" https 'scheme over TLS'

    # Every request of a connection has the data of its handshake.
    tcurl() {
        curl --silent --show-error --noproxy '*' --max-time 10 --insecure \
            --resolve "torii.test:$P_TLS:127.0.0.1" --resolve "torii.test:$P_BROWSER:127.0.0.1" "$@"
    }
    tcurl --http1.1 -o /dev/null "https://torii.test:$P_TLS/keep1" -o /dev/null "https://torii.test:$P_TLS/keep2" \
        || fail 'transport error: TLS keepalive'
    assert_contains ",$(tls /keep1 3)," ',0304,' 'TLS supported versions'
    assert_eq "$(seen /keep2 '.["torii-tls"]')" "$(seen /keep1 '.["torii-tls"]')" 'TLS data on a kept connection'

    if curl --version | grep -q HTTP2; then
        tcurl --http2 -o /dev/null -A h2-test -H 'X-b: 1' -H 'x-A: 2' "https://torii.test:$P_TLS/h2" \
            || fail 'transport error: HTTP/2 over TLS'
        assert_eq "$(seen /h2 '.["torii-proto"]')" HTTP/2.0 'protocol over HTTP/2'
        assert_eq "$(seen /h2 '.["torii-header-order"]')" 'user-agent,accept,x-b,x-a' 'header order over HTTP/2'
        assert_eq "$(tls /h2 7 | cut -d, -f1)" h2 'TLS ALPN protocols of an HTTP/2 client'
    fi

    # Torii judges a client by these headers: one that calls itself Chrome is refused for what
    # its request lacks, and when it sends every header Chrome sends, for its TLS handshake.
    CHROME='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'
    browser() { CODE=$(tcurl -o "$RUN/b" -w '%{http_code}' "$@") || fail 'transport error: browser integrity'; }
    browser "https://torii.test:$P_BROWSER/browser-none"
    assert_eq "$CODE" 200 'a client that claims no browser is not judged'
    browser -A "$CHROME" "https://torii.test:$P_BROWSER/browser-name"
    assert_eq "$CODE" 403 'only the name of a browser'
    browser -A "$CHROME" -H 'sec-ch-ua: "Chromium";v="135", "Not-A.Brand";v="8"' -H 'sec-ch-ua-platform: "Windows"' \
        -H 'Accept: text/html,*/*;q=0.8' -H 'Sec-Fetch-Site: none' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Dest: document' \
        -H 'Accept-Encoding: gzip' -H 'Accept-Language: en' "https://torii.test:$P_BROWSER/browser-headers"
    assert_eq "$CODE" 403 'the headers of a browser, the TLS handshake of curl'

    # A handwritten ClientHello: reserved values (RFC 8701) are all written as 0a0a, an
    # extension sent twice counts once, and characters that would break the format are
    # replaced. The same message cut at every length must not be read past its end.
    python3 - "$P_TLS" <<'PY'
import socket, sys

def vec(n, data): return len(data).to_bytes(n, "big") + data
def u16(*values): return b"".join(v.to_bytes(2, "big") for v in values)
def ext(kind, data): return u16(kind) + vec(2, data)

extensions = (
    ext(0x1a1a, b"")
    + ext(0x0000, vec(2, b"\x00" + vec(2, b"torii.test")))
    + ext(0x000a, vec(2, u16(0x2a2a, 0x001d, 0x0017)))
    + ext(0x000b, vec(1, b"\x00\x01"))
    + ext(0x000d, vec(2, u16(0x0403, 0x0804)))
    + ext(0x0010, vec(2, vec(1, b"h2") + vec(1, b"a,b|c")))
    + ext(0x002b, vec(1, u16(0x3a3a, 0x0304, 0x0303)))
    + ext(0x000a, vec(2, u16(0x0018))))
hello = (b"\x03\x03" + bytes(32) + vec(1, b"") + vec(2, u16(0x4a4a, 0x1301, 0xc02f))
         + vec(1, b"\x00") + vec(2, extensions))

def send(body):
    message = b"\x01" + len(body).to_bytes(3, "big") + body
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
    try:
        s.sendall(b"\x16\x03\x01" + len(message).to_bytes(2, "big") + message)
        s.recv(4096)
    except OSError:
        pass
    s.close()

send(hello)
for cut in range(len(hello)):
    send(hello[:cut])
PY
    sleep 0.3
    ASSERTIONS=$((ASSERTIONS + 2))
    grep -qF 'torii tls: "0303|0a0a,1301,c02f|0a0a,0000,000a,000b,000d,0010,002b,000a|0a0a,0304,0303|0a0a,001d,0017|00,01|0403,0804|h2,a?b?c"' \
        "$RUN/nginx/logs/error.log" || fail 'a handwritten ClientHello is not read as expected'
    grep -q 'torii tls: malformed ClientHello' "$RUN/nginx/logs/error.log" || fail 'a cut ClientHello is not refused'
else
    echo "SKIP: nginx has no SSL module, \$torii_tls is not tested"
fi

# ------------------------------------------------------------- request reports
# report N FILTER: the value jq extracts from the N-th captured report.
report() { sed -n "${1}p" "$RUN/cap.jsonl" | jq -r "$2"; }
wait_reports() {
    local want=$1 deadline=$((SECONDS + 5))
    until (( $(wc -l < "$RUN/cap.jsonl") >= want )); do
        (( SECONDS < deadline )) || fail "expected $want request reports, got $(wc -l < "$RUN/cap.jsonl")"
        sleep 0.1
    done
}
# The health check shows its counters to whoever has the key derived from global_secret.
HEALTH_KEY=$(printf '%s' 'torii health key' \
    | openssl dgst -sha256 -hmac 'test-only-global-secret-never-use-in-production' | awk '{print substr($NF,1,32)}')
counter() { get "$P_TCP" "/torii/health_check?key=$HEALTH_KEY"; sed -n "s/^$1=//p" "$RUN/b"; }

# A served request: what the client sent and what became of it.
get "$P_CAP" '/neutral?q=%22x%22&n=1' -A 'Report "UA"\1.0' -e 'https://ref.example/a?b=1' \
    -H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: none' -H 'Accept-Language: en'
assert_eq "$CODE" 200 'reported request status'
wait_reports 1
assert_eq "$(report 1 .v)" 1 'report version'
assert_eq "$(report 1 .site)" shop 'report site'
assert_eq "$(report 1 .ip)" 127.0.0.1 'report client address'
assert_eq "$(report 1 .host)" 127.0.0.1 'report host'
assert_eq "$(report 1 .method)" GET 'report method'
assert_eq "$(report 1 .uri)" '/neutral?q=%22x%22&n=1' 'report URI'
assert_eq "$(report 1 .status)" 200 'report status'
assert_eq "$(report 1 .decision)" pass 'report decision'
assert_eq "$(report 1 .ua)" 'Report "UA"\1.0' 'report user agent, with characters JSON escapes'
assert_eq "$(report 1 .referer)" 'https://ref.example/a?b=1' 'report referer'
assert_eq "$(report 1 .proto)" HTTP/1.1 'report protocol'
assert_eq "$(report 1 .fetch)" document/navigate/none 'report fetch metadata'
assert_eq "$(report 1 .lang)" true 'report Accept-Language'
assert_eq "$(report 1 .ctype)" text/plain 'report content type'
assert_eq "$(report 1 .ustatus)" 200 'report upstream status'
assert_eq "$(report 1 .conn_reqs)" 1 'report connection request count'
assert_eq "$(report 1 .bytes)" "$(wc -c < "$RUN/b" | tr -d ' ')" 'report body size'
assert_eq "$(report 1 '(.rt >= 0) and (.urt >= 0) and (.req_len > 0)')" true 'report timings and request size'
assert_eq "$(report 1 '(.uct >= 0) and (.uht >= .uct) and (.urt >= .uht)')" true 'report upstream connect and header times'
assert_eq "$(report 1 "((.ts / 1000) - $(date +%s)) | fabs < 60")" true 'report timestamp'

# A request Torii answered itself: no upstream was involved.
get "$P_CAP" /blocked
wait_reports 2
assert_eq "$(report 2 '[.status, .decision, .reason, .ustatus, .lang, .ua] | @json')" \
    '[403,"block","Lists:url_block",null,null,"curl/'"$(curl --version | awk 'NR==1 {print $2}')"'"]' 'report of a blocked request'

# torii_log off.
get "$P_CAP" /quiet/page
assert_eq "$CODE" 200 'torii_log off status'
sleep 0.5
assert_eq "$(wc -l < "$RUN/cap.jsonl" | tr -d ' ')" 2 'no report with torii_log off'

# Reports reach Torii over its Unix socket, also from a location that is neither checked nor logged.
before=$(counter reports_accepted)
get "$P_LOG" /assets/pixel
assert_eq "$CODE" 200 'unchecked location status'
deadline=$((SECONDS + 5))
until (( $(counter reports_accepted) > before )); do
    (( SECONDS < deadline )) || fail 'the report of an unchecked, unlogged location did not arrive'
    sleep 0.1
done
ASSERTIONS=$((ASSERTIONS + 1))
assert_eq "$(counter reports_malformed)" 0 'malformed reports'

# The reports drive the traffic analysis: a client that keeps getting errors is blocked on that
# site, and only there.
deadline=$((SECONDS + 30))
while true; do
    for _ in 1 2 3 4 5 6 7 8 9 10; do get "$P_LOG" /missing; done
    [[ "$CODE" != 403 ]] || break
    (( SECONDS < deadline )) || fail 'traffic analysis did not block the failing client'
    sleep 0.3
done
assert_contains "$BODY" E2E-403 'block page of the analyzed site'
get "$P_TCP" /neutral
assert_eq "$CODE" 200 'the block stays on its site'

# Nobody listens: requests are served as usual, and the failure is not logged for each of them.
for _ in $(seq 30); do get "$P_GONE" /neutral; done
assert_eq "$CODE" 200 'status with an unreachable report socket'
ASSERTIONS=$((ASSERTIONS + 1))
# Counted by the module's own warning: nginx before 1.23.4 does not name the socket in its
# "connect() failed" line.
gone=$(grep -c 'sending a request report failed' "$RUN/nginx/logs/error.log" || true)
(( gone >= 1 && gone <= 6 )) || fail "expected a few log lines about the unreachable report socket, got $gone"

# Logs: variables, check count, and nothing alarming.
sleep 0.3
LOG=$(cat "$RUN/nginx/logs/access.log")
assert_contains "$LOG" '/neutral|200|pass|-|shop' 'access log: pass'
assert_contains "$LOG" '/blocked|403|block|Lists:url_block|shop' 'access log: block with reason'
assert_contains "$LOG" '/challenge|503|challenge|Lists:url_captcha|shop' 'access log: challenge with reason'
assert_contains "$LOG" '/neutral|503|error|-|no_such_site' 'access log: error'
assert_contains "$LOG" '/redirected?marker=once|200|pass|-|shop' 'access log: decision survives the redirect'
if (( HAVE_SSL )); then
    assert_contains "$LOG" '/browser-none|200|pass|-|shop' 'access log: no browser claimed'
    assert_contains "$LOG" '/browser-name|403|block|BrowserIntegrity:missing_headers|shop' 'access log: browser integrity rule'
    assert_contains "$LOG" '/browser-headers|403|block|BrowserIntegrity:tls|shop' 'access log: browser integrity by TLS'
fi

"$NGINX_BIN" -p "$RUN/nginx" -c conf/nginx.conf -s quit
for _ in $(seq 50); do [[ -f "$RUN/nginx/logs/nginx.pid" ]] || break; sleep 0.1; done
ASSERTIONS=$((ASSERTIONS + 1))
# nginx 1.22 and older log the handshakes the handwritten ClientHellos fail at the crit level.
if grep -v 'gone.sock\|connect() failed (2: No such file or directory)$\|SSL_do_handshake() failed' "$RUN/nginx/logs/error.log" \
    | grep -E '\[(alert|emerg|crit)\]|AddressSanitizer|LeakSanitizer|runtime error' > "$RUN/bad.log"; then
    head -n 20 "$RUN/bad.log" >&2
    fail 'nginx logged an alert or a sanitizer report'
fi

echo "PASS: $ASSERTIONS assertions"

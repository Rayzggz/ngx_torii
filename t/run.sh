#!/usr/bin/env bash
# Integration test: a real nginx with this module in front of a real Server Torii.
#
#   NGINX_BIN=/path/to/sbin/nginx TORII_BIN=/path/to/server_torii \
#   TORII_SRC=/path/to/server_torii-checkout bash t/run.sh
#
# TORII_SRC provides the test rules and pages (tests/e2e/fixtures) and the GeoIP
# database. Everything runs on loopback out of a temporary directory.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${NGINX_BIN:?set NGINX_BIN to an nginx built with this module}"
: "${TORII_BIN:?set TORII_BIN to a server_torii binary}"
: "${TORII_SRC:?set TORII_SRC to a server_torii checkout}"
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
sed -i '/^AdaptiveTrafficAnalyzer:/,/^  uri_detection:/s/enabled: false/enabled: true/' "$RUN/torii/rules/logs/Server.yml"
sed -i '/^  ip_detection:/,/^[^ ]/s/enabled: false/enabled: true/' "$RUN/torii/rules/logs/Server.yml"
cp "$TORII_SRC/config_example/data/GeoLite2-Country.mmdb" "$RUN/torii/data/"
# A page that does not fit a small subrequest buffer.
head -c 4096 /dev/zero | tr '\0' 'x' >> "$RUN/torii/pages/429.html"
SOCK="$RUN/torii/torii.sock"
LOGSOCK="$RUN/torii/log.sock"
CAPSOCK="$RUN/cap.sock"
cat > "$RUN/torii/torii.yml" <<EOF
port: "$TORII_PORT"
listen: ["127.0.0.1:$TORII_PORT", "unix:$SOCK"]
log_listen: ["unix:$LOGSOCK"]
web_path: /torii
error_page: "$RUN/torii/pages"
log_path: "$RUN/torii/log"
global_secret: "test-only-global-secret-never-use-in-production"
node_name: "Node_T"
enable_gossip: false
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

# ----------------------------------------------------------------------- nginx
mkdir -p "$RUN/nginx/logs" "$RUN/nginx/conf/torii"
cp "$ROOT/conf/"*.conf "$RUN/nginx/conf/torii/"
# The same endpoints with another upstream or buffer size, for the failure cases.
sed 's/torii_backend/torii_unix/' "$ROOT/conf/torii_endpoints.conf" > "$RUN/nginx/conf/torii/unix.conf"
sed 's/torii_backend/torii_dead/' "$ROOT/conf/torii_endpoints.conf" > "$RUN/nginx/conf/torii/dead.conf"
sed 's/subrequest_output_buffer_size 64k/subrequest_output_buffer_size 1k/' \
    "$ROOT/conf/torii_endpoints.conf" > "$RUN/nginx/conf/torii/small.conf"

cat > "$RUN/nginx/conf/nginx.conf" <<EOF
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

    torii_log syslog:server=unix:$LOGSOCK;

    server {
        listen 127.0.0.1:$P_APP;
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
        location /strict/ { torii_features "+captcha"; proxy_pass http://127.0.0.1:$P_APP; }
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
        listen 127.0.0.1:$P_H2;
        http2 on;
        torii on;
        torii_site shop;
        include torii/torii_endpoints.conf;
        location / { proxy_pass http://127.0.0.1:$P_APP; }
    }
}
EOF
"$NGINX_BIN" -p "$RUN/nginx" -c conf/nginx.conf -t 2> "$RUN/nginx-t.log" || { cat "$RUN/nginx-t.log" >&2; fail 'nginx -t'; }
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
counter() { get "$P_TCP" /torii/health_check; sed -n "s/^$1=//p" "$RUN/b"; }

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
assert_eq "$(report 1 "((.ts / 1000) - $(date +%s)) | fabs < 60")" true 'report timestamp'

# A request Torii answered itself: no upstream was involved.
get "$P_CAP" /blocked
wait_reports 2
assert_eq "$(report 2 '[.status, .decision, .reason, .ustatus, .lang, .ua] | @json')" \
    '[403,"block","URLBlock",null,null,"curl/'"$(curl --version | awk 'NR==1 {print $2}')"'"]' 'report of a blocked request'

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
gone=$(grep -c 'gone.sock' "$RUN/nginx/logs/error.log" || true)
(( gone >= 1 && gone <= 6 )) || fail "expected a few log lines about the unreachable report socket, got $gone"

# Logs: variables, check count, and nothing alarming.
sleep 0.3
LOG=$(cat "$RUN/nginx/logs/access.log")
assert_contains "$LOG" '/neutral|200|pass|-|shop' 'access log: pass'
assert_contains "$LOG" '/blocked|403|block|URLBlock|shop' 'access log: block with reason'
assert_contains "$LOG" '/challenge|503|captcha|URLCAPTCHA|shop' 'access log: captcha with reason'
assert_contains "$LOG" '/neutral|503|error|-|no_such_site' 'access log: error'
assert_contains "$LOG" '/redirected?marker=once|200|pass|-|shop' 'access log: decision survives the redirect'

"$NGINX_BIN" -p "$RUN/nginx" -c conf/nginx.conf -s quit
for _ in $(seq 50); do [[ -f "$RUN/nginx/logs/nginx.pid" ]] || break; sleep 0.1; done
ASSERTIONS=$((ASSERTIONS + 1))
if grep -v 'gone.sock' "$RUN/nginx/logs/error.log" \
    | grep -E '\[(alert|emerg|crit)\]|AddressSanitizer|LeakSanitizer|runtime error' > "$RUN/bad.log"; then
    head -n 20 "$RUN/bad.log" >&2
    fail 'nginx logged an alert or a sanitizer report'
fi

echo "PASS: $ASSERTIONS assertions"

#!/usr/bin/env bash
# Builds nginx versions with this module and runs the integration test against each.
#
#   TORII_SRC=/path/to/server_torii-checkout bash t/matrix.sh [TARGET...]
#
# A TARGET is an nginx version ("1.26.3"), an OpenResty version ("openresty-1.27.1.2"), either
# one followed by "+dynamic" to build the module as a shared object ("1.26.3+dynamic").
# Without targets the default list below is used.
#
# BUILD_ONLY=1 needs no Server Torii: each target is built and "nginx -t" loads a configuration
# that uses the module's directives, and the integration test is not run. CI does this.
#
# Sources are downloaded from nginx.org and openresty.org; builds are kept in CACHE
# (default ~/.cache/ngx-torii-matrix) and reused. Needs a C toolchain, zlib and PCRE2
# headers, curl, perl (OpenResty) and Go (to build Server Torii).
#
# nginx before 1.21.5 needs the original PCRE library, which current distributions no longer
# ship headers for; its source is downloaded and built into nginx for those versions.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_ONLY=${BUILD_ONLY:-0}
[[ "$BUILD_ONLY" == 1 ]] || : "${TORII_SRC:?set TORII_SRC to a server_torii checkout, or BUILD_ONLY=1}"
CACHE=${CACHE:-$HOME/.cache/ngx-torii-matrix}
JOBS=${JOBS:-$(nproc 2>/dev/null || echo 2)}
PCRE1_VERSION=8.45
DEFAULT_TARGETS=(1.14.2 1.16.1 1.18.0 1.20.2 1.22.1 1.24.0 1.26.3 1.28.0 1.30.7 1.30.7+dynamic openresty-1.27.1.2)

targets=("$@")
(( ${#targets[@]} > 0 )) || targets=("${DEFAULT_TARGETS[@]}")
mkdir -p "$CACHE/src"

# version_ge A B: version A is B or newer, comparing the first three components.
version_ge() {
    local a b i
    IFS=. read -r -a a <<< "$1"
    IFS=. read -r -a b <<< "$2"
    for i in 0 1 2; do
        (( ${a[i]:-0} > ${b[i]:-0} )) && return 0
        (( ${a[i]:-0} < ${b[i]:-0} )) && return 1
    done
    return 0
}

# fetch URL DIR: downloads an archive once and unpacks it into DIR.
fetch() {
    local url=$1 archive
    archive="$CACHE/src/$(basename "$url")"
    if [[ ! -f "$archive" ]]; then
        echo "  downloading $url"
        curl --fail --silent --show-error --location --retry 3 -o "$archive.part" "$url"
        mv "$archive.part" "$archive"
    fi
    tar -xzf "$archive" -C "$2"
}

# build TARGET: prints nothing; sets NGINX_BIN and MODULE_SO.
build() {
    local target=$1 spec dynamic=0 flavor=nginx version dir src add log
    spec=$target
    if [[ "$spec" == *+dynamic ]]; then dynamic=1 spec=${spec%+dynamic}; fi
    if [[ "$spec" == openresty-* ]]; then flavor=openresty version=${spec#openresty-}; else version=$spec; fi
    dir="$CACHE/build/$target"
    log="$dir/build.log"
    NGINX_BIN="$dir/prefix/sbin/nginx"
    [[ "$flavor" == nginx ]] || NGINX_BIN="$dir/prefix/nginx/sbin/nginx"
    MODULE_SO=''
    (( dynamic == 0 )) || MODULE_SO="$dir/ngx_http_torii_module.so"

    # Rebuild when the module source is newer than the last build.
    if [[ -x "$NGINX_BIN" && "$dir/.built" -nt "$ROOT/src/ngx_http_torii_module.c" && "$dir/.built" -nt "$ROOT/config" ]]; then
        return 0
    fi
    rm -rf "$dir"
    mkdir -p "$dir"

    if [[ "$flavor" == nginx ]]; then
        fetch "https://nginx.org/download/nginx-$version.tar.gz" "$dir"
        src="$dir/nginx-$version"
    else
        fetch "https://openresty.org/download/openresty-$version.tar.gz" "$dir"
        src="$dir/openresty-$version"
    fi

    add=--add-module
    (( dynamic == 0 )) || add=--add-dynamic-module
    # --with-debug: the test counts the module's debug log lines.
    local -a args=(--prefix="$dir/prefix" --with-debug --with-http_v2_module "$add=$ROOT")
    if [[ "$flavor" == nginx ]]; then
        args+=(--without-http_gzip_module)
        if ! version_ge "$version" 1.21.5; then
            fetch "https://sourceforge.net/projects/pcre/files/pcre/$PCRE1_VERSION/pcre-$PCRE1_VERSION.tar.gz" "$dir"
            args+=(--with-pcre="$dir/pcre-$PCRE1_VERSION")
        fi
        # Old nginx sources trip warnings that newer compilers turned on; they are not ours to fix.
        version_ge "$version" 1.22.0 || args+=(--with-cc-opt=-Wno-error)
    fi
    (
        cd "$src"
        ./configure "${args[@]}"
        make -j"$JOBS"
        make install
    ) > "$log" 2>&1 || { tail -n 30 "$log" >&2; return 1; }
    if (( dynamic == 1 )); then
        cp "$(find "$src" -name ngx_http_torii_module.so -print -quit)" "$MODULE_SO"
    fi
    touch "$dir/.built"
}

# smoke: "nginx -t" on a configuration with every directive of the module. Nothing is started,
# but "nginx -t" binds the listen address for a moment.
smoke() {
    local dir load='' status=0
    dir=$(mktemp -d "${TMPDIR:-/tmp}/ngx-torii-smoke.XXXXXXXX")
    mkdir -p "$dir/logs" "$dir/conf/torii"
    cp "$ROOT/conf/"*.conf "$dir/conf/torii/"
    [[ -z "$MODULE_SO" ]] || load="load_module $MODULE_SO;"
    cat > "$dir/conf/nginx.conf" <<EOF
$load
error_log logs/error.log;
pid logs/nginx.pid;
events {}
http {
    access_log off;
    upstream torii_backend { server 127.0.0.1:1; }
    torii_log syslog:server=127.0.0.1:1;
    server {
        listen 127.0.0.1:${BASE_PORT:-28100};
        torii on;
        torii_site smoke;
        torii_on_error pass;
        torii_features "-url_block";
        include torii/torii_endpoints.conf;
        location / { return 200; }
        location /open/ { torii off; torii_log off; return 200; }
    }
}
EOF
    # nginx does not free its configuration on exit; under ASAN that is reported as a leak.
    ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0} "$NGINX_BIN" -p "$dir" -c conf/nginx.conf -t 2>&1 || status=$?
    rm -rf -- "$dir"
    return "$status"
}

if [[ "$BUILD_ONLY" != 1 ]]; then
    echo "Building Server Torii"
    (cd "$TORII_SRC" && go build -o "$CACHE/server_torii" ./cmd/server_torii)
fi

passed=() failed=()
for target in "${targets[@]}"; do
    echo "== $target"
    if ! build "$target"; then
        echo "   BUILD FAILED (log: $CACHE/build/$target/build.log)"
        failed+=("$target (build)")
        continue
    fi
    if [[ "$BUILD_ONLY" == 1 ]]; then
        if smoke | sed 's/^/   /'; then passed+=("$target"); else failed+=("$target (nginx -t)"); fi
        continue
    fi
    if NGINX_BIN="$NGINX_BIN" NGX_TORII_MODULE="$MODULE_SO" TORII_BIN="$CACHE/server_torii" TORII_SRC="$TORII_SRC" \
        bash "$ROOT/t/run.sh" 2>&1 | sed 's/^/   /'; then
        passed+=("$target")
    else
        failed+=("$target (test)")
    fi
done

echo
echo "Passed: ${passed[*]:-none}"
if (( ${#failed[@]} > 0 )); then
    printf 'Failed: %s\n' "${failed[*]}"
    exit 1
fi

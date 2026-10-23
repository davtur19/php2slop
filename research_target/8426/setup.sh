#!/usr/bin/env bash
# Idempotent stock-target setup for the PHP 8.4.26 multi-worker replication kit.
#
# Run as the unprivileged target user (netsec).  Requires rootless Docker.
# It never uses sudo, never starts a host Apache, and never touches
# /var/run/docker.sock.  Only the named kit container and its pool directory
# are created.
set -euo pipefail
umask 022

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KIT_ID=$(tr -d '\r\n' < "$ROOT/KIT_ID")
DEFAULT_IMAGE="php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a"
EXPECTED_IMAGE_ID="sha256:46b195b6378e712d1a65cd3f853242bebd7f3cb4cafe137fd592b365909d2c17"
EXPECTED_LIBPHP_SHA256="51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c"
EXPECTED_PHP_INI_SHA256="8d6fcbbcff186958a3609e277f8db249122a89d01e8401b1861f5bd4283f148a"
EXPECTED_WP_SHA256="eb58a90ed55147f90f7bd55d0d3334960a69b7e8a4cc142c8ddfea8965218227"
WP_URL="https://wordpress.org/wordpress-7.1.3.zip"
WP_VERSION="7.1.3"

PORT=18080
NAME=""
POOL_DIR=""
IMAGE="$DEFAULT_IMAGE"
FORCE=0
STOP=0
NO_PULL=0

die() { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARN: $*" >&2; }
info() { echo "==> $*"; }

usage() {
    cat <<EOF
Usage: ./setup.sh [options]

  --port N          loopback port (default 18080); container name defaults to p8426_N
  --name NAME       explicit container name (default p8426_<port>)
  --pool-dir DIR    host dir for logs/ and proof/ (default ./pools/<name>)
  --image REF       image reference (default the pinned php@sha256:6011... digest)
  --force           remove and recreate the named kit container (pool data kept)
  --stop            stop the named kit container and exit
  --no-pull         fail instead of pulling the image if it is absent
  --help            this text

Stock target: php:8.4.26-apache, PHP 8.4.26 NTS, Apache 2.4.69 (Debian 13),
stock prefork (StartServers 5, MaxRequestWorkers 150), unmodified
php.ini-production (post_max_size=8M, display_errors=Off), pristine official
WordPress 7.1.3.  The only config delta is logging: conf/p2s.conf defines a
%P format and conf/000-default.conf adds a SECOND access log (the stock
combined log is retained).  It is not part of the exploit path.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) [[ $# -ge 2 ]] || die "--port needs a value"; PORT=$2; shift 2 ;;
        --name) [[ $# -ge 2 ]] || die "--name needs a value"; NAME=$2; shift 2 ;;
        --pool-dir) [[ $# -ge 2 ]] || die "--pool-dir needs a value"; POOL_DIR=$2; shift 2 ;;
        --image) [[ $# -ge 2 ]] || die "--image needs a value"; IMAGE=$2; shift 2 ;;
        --force) FORCE=1; shift ;;
        --stop) STOP=1; shift ;;
        --no-pull) NO_PULL=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

[[ "$PORT" =~ ^[0-9]+$ ]] || die "--port must be numeric"
(( PORT >= 1 && PORT <= 65535 )) || die "--port out of range"
NAME=${NAME:-p8426_$PORT}
[[ "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || die "invalid container name: $NAME"
POOL_DIR=${POOL_DIR:-$ROOT/pools/$NAME}
mkdir -p "$POOL_DIR"
POOL_DIR=$(CDPATH= cd -- "$POOL_DIR" && pwd)
mkdir -p "$POOL_DIR/logs" "$POOL_DIR/proof" "$ROOT/work/bodies" "$ROOT/vendor" "$ROOT/out"
chmod 777 "$POOL_DIR/proof"

[[ ${EUID:-$(id -u)} -ne 0 ]] || die "refusing to run as root; run as the unprivileged target user (netsec)"
if [[ "$(id -un)" != "netsec" ]]; then
    warn "expected user netsec, running as $(id -un); continuing as unprivileged user"
fi

command -v docker >/dev/null 2>&1 || die "docker not found in PATH"
command -v python3 >/dev/null 2>&1 || die "python3 not found"
command -v curl >/dev/null 2>&1 || die "curl not found"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"

docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon (is rootless Docker running?)"
SECOPTS=$(docker info --format '{{range .SecurityOptions}}{{.}}{{"\n"}}{{end}}' 2>/dev/null || true)
grep -qx 'name=rootless' <<<"$SECOPTS" || die "Docker is not rootless (security options: ${SECOPTS//$'\n'/ })"
ENDPOINT=$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)
case "$ENDPOINT" in
    *'/var/run/docker.sock'*) die "Docker context uses the rootful socket ($ENDPOINT)" ;;
esac
if [[ -S /var/run/docker.sock ]]; then
    warn "/var/run/docker.sock exists on the host; this kit does not use it (context endpoint: ${ENDPOINT:-unknown})"
fi

container_exists() { docker inspect "$NAME" >/dev/null 2>&1; }
container_running() { [[ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || true)" == "true" ]]; }
container_label() { docker inspect -f "{{index .Config.Labels \"$1\"}}" "$NAME" 2>/dev/null || true; }

verify_owned_container() {
    local repro kit
    repro=$(container_label p8426.repro)
    kit=$(container_label p8426.kit)
    [[ "$repro" == "1" ]] || die "container $NAME exists but is not labeled p8426.repro=1; refusing to touch it"
    [[ "$kit" == "$KIT_ID" ]] || die "container $NAME belongs to kit '$kit' (this kit is '$KIT_ID'); refusing to touch it"
}

if [[ $STOP -eq 1 ]]; then
    if ! container_exists; then
        info "container $NAME does not exist; nothing to stop"
        exit 0
    fi
    verify_owned_container
    docker stop "$NAME" >/dev/null
    info "stopped $NAME (pool data kept under $POOL_DIR)"
    exit 0
fi

# ---- WordPress -------------------------------------------------------------
ensure_wp() {
    local zip="$ROOT/vendor/wordpress-$WP_VERSION.zip"
    local wp="$ROOT/work/wordpress"
    local expected_index="bd48c24ce4500e60d2524571756787283f0d3fbfa50b116331309c09773f0cd1"
    if [[ -f "$zip" ]]; then
        local actual
        actual=$(sha256sum "$zip" | awk '{print $1}')
        if [[ "$actual" != "$EXPECTED_WP_SHA256" ]]; then
            warn "existing WordPress zip hash mismatch ($actual); re-downloading"
            rm -f "$zip"
        fi
    fi
    if [[ ! -f "$zip" ]]; then
        info "downloading WordPress $WP_VERSION from $WP_URL"
        local tmp="$zip.tmp.$$"
        curl -fL --retry 3 --connect-timeout 15 --max-time 600 -o "$tmp" "$WP_URL"
        local actual
        actual=$(sha256sum "$tmp" | awk '{print $1}')
        [[ "$actual" == "$EXPECTED_WP_SHA256" ]] || { rm -f "$tmp"; die "WordPress zip hash mismatch: $actual"; }
        mv "$tmp" "$zip"
    fi
    local actual
    actual=$(sha256sum "$zip" | awk '{print $1}')
    [[ "$actual" == "$EXPECTED_WP_SHA256" ]] || die "WordPress zip hash mismatch: $actual"

    if [[ -f "$wp/wp-content/index.php" ]] && \
       [[ "$(sha256sum "$wp/wp-content/index.php" | awk '{print $1}')" == "$expected_index" ]] && \
       [[ "$(stat -c %s "$wp/wp-content/index.php")" == "28" ]]; then
        info "pristine WordPress $WP_VERSION tree already extracted"
        return 0
    fi
    info "extracting pristine WordPress $WP_VERSION into work/wordpress"
    rm -rf "$wp"
    python3 - "$zip" "$ROOT/work" <<'PY'
import sys, zipfile
zip_path, dest = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zip_path) as zf:
    zf.extractall(dest)
PY
    [[ -f "$wp/wp-content/index.php" ]] || die "WordPress extraction did not produce wp-content/index.php"
    [[ "$(sha256sum "$wp/wp-content/index.php" | awk '{print $1}')" == "$expected_index" ]] || die "wp-content/index.php hash mismatch"
    [[ "$(stat -c %s "$wp/wp-content/index.php")" == "28" ]] || die "wp-content/index.php size mismatch"
    info "WordPress docroot ready: $(find "$wp" -type f | wc -l) files, $(du -sb "$wp" | awk '{print $1}') bytes"
}

# ---- bodies and config -----------------------------------------------------
ensure_config() {
    local ini="$ROOT/conf/php.ini-production"
    [[ -f "$ini" ]] || die "missing conf/php.ini-production"
    local actual
    actual=$(sha256sum "$ini" | awk '{print $1}')
    [[ "$actual" == "$EXPECTED_PHP_INI_SHA256" ]] || die "php.ini-production hash mismatch: $actual"
    grep -Eq '^post_max_size[[:space:]]*=[[:space:]]*8M[[:space:]]*$' "$ini" || die "php.ini-production lacks post_max_size=8M"
    grep -Eq '^display_errors[[:space:]]*=[[:space:]]*Off[[:space:]]*$' "$ini" || die "php.ini-production lacks display_errors=Off"
    grep -Eq '^memory_limit[[:space:]]*=[[:space:]]*128M[[:space:]]*$' "$ini" || die "php.ini-production lacks memory_limit=128M"
    [[ -f "$ROOT/conf/p2s.conf" ]] || die "missing conf/p2s.conf"
}

ensure_bodies() {
    python3 - "$ROOT" <<'PY'
import os, sys
root = sys.argv[1]
sys.path.insert(0, os.path.join(root, "lib"))
import chain8426  # noqa: E402
bodies, records = chain8426.load_bodies(root)
for name in ("a1_shrink_7150_only", "b1_stock", "a2_upstream_115"):
    rec = records[name]
    print("body %-22s %9d bytes  sha256 %s" % (name, rec["bytes"], rec["sha256"]))
PY
}

# ---- image and container ---------------------------------------------------
ensure_image() {
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        [[ $NO_PULL -eq 0 ]] || die "image $IMAGE is absent and --no-pull was given"
        info "pulling pinned image $IMAGE"
        docker pull "$IMAGE" >/dev/null
    fi
    IMG_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE")
    IMG_ARCH=$(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$IMAGE")
    [[ "$IMG_ARCH" == "linux/amd64" ]] || die "image architecture is $IMG_ARCH; the offsets are linux/amd64 only"
    if [[ "$IMAGE" == "$DEFAULT_IMAGE" && "$IMG_ID" != "$EXPECTED_IMAGE_ID" ]]; then
        warn "image ID $IMG_ID differs from the measured $EXPECTED_IMAGE_ID; the libphp hash check below is authoritative"
    fi
    info "image $IMAGE -> $IMG_ID ($IMG_ARCH)"
}

check_mounts() {
    local mounts
    mounts=$(docker inspect -f '{{range .Mounts}}{{.Source}}|{{.Destination}}|{{.RW}}{{"\n"}}{{end}}' "$NAME")
    local line
    for line in \
        "$ROOT/work/wordpress|/var/www/html|false" \
        "$ROOT/conf/php.ini-production|/usr/local/etc/php/php.ini|false" \
        "$ROOT/conf/000-default.conf|/etc/apache2/sites-enabled/000-default.conf|false" \
        "$ROOT/conf/p2s.conf|/etc/apache2/conf-enabled/p2s.conf|false" \
        "$POOL_DIR/logs|/var/log/apache2|true" \
        "$POOL_DIR/proof|/out|true"
    do
        grep -Fqx "$line" <<<"$mounts" || die "existing container $NAME has a different mount set (missing: $line); use --force"
    done
}

check_port_mapping() {
    local mapped
    mapped=$(docker port "$NAME" 80/tcp 2>/dev/null | head -n1 || true)
    [[ "$mapped" == "127.0.0.1:$PORT" ]] || die "existing container $NAME publishes '$mapped', expected 127.0.0.1:$PORT; use --force"
}

wait_http() {
    local code="" i
    for i in $(seq 1 120); do
        code=$(curl -sS --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 3 \
            "http://127.0.0.1:$PORT/wp-content/index.php" 2>/dev/null || true)
        [[ "$code" == "200" ]] && break
        sleep 0.25
    done
    [[ "$code" == "200" ]] || die "target did not become ready on port $PORT (last HTTP code: ${code:-none})"
}

wait_children() {
    local i out parent count
    for i in $(seq 1 60); do
        out=$(docker exec "$NAME" sh -c 'p=$(cat /var/run/apache2/apache2.pid 2>/dev/null); echo parent=$p; ps -o pid=,ppid= -C apache2 2>/dev/null' 2>/dev/null || true)
        parent=$(printf '%s\n' "$out" | awk -F= '/^parent=/{print $2; exit}')
        [[ -n "$parent" ]] || parent=1
        count=$(printf '%s\n' "$out" | awk -v p="$parent" 'NF==2 && $2==p{c++} END{print c+0}')
        if (( count >= 5 )); then
            echo "$count"
            return 0
        fi
        sleep 0.25
    done
    return 1
}

check_container() {
    local phpv apachev libsha inisha mods mpm count

    phpv=$(docker exec "$NAME" php -r 'echo PHP_VERSION;' 2>/dev/null || true)
    [[ "$phpv" == "8.4.26" ]] || die "container PHP version is '${phpv:-unknown}', expected 8.4.26"

    apachev=$(docker exec "$NAME" apache2 -v 2>/dev/null | head -n1 || true)
    grep -q 'Apache/2.4.69' <<<"$apachev" || die "container Apache version is '${apachev:-unknown}', expected 2.4.69"

    libsha=$(docker exec "$NAME" sha256sum /usr/lib/apache2/modules/libphp.so 2>/dev/null | awk '{print $1}')
    [[ "$libsha" == "$EXPECTED_LIBPHP_SHA256" ]] || die "libphp.so hash mismatch: ${libsha:-missing}"

    inisha=$(docker exec "$NAME" sha256sum /usr/local/etc/php/php.ini 2>/dev/null | awk '{print $1}')
    [[ "$inisha" == "$EXPECTED_PHP_INI_SHA256" ]] || die "php.ini hash mismatch: ${inisha:-missing}"

    for pattern in \
        '^post_max_size[[:space:]]*=[[:space:]]*8M[[:space:]]*$' \
        '^display_errors[[:space:]]*=[[:space:]]*Off[[:space:]]*$' \
        '^memory_limit[[:space:]]*=[[:space:]]*128M[[:space:]]*$'
    do
        docker exec "$NAME" grep -Eq "$pattern" /usr/local/etc/php/php.ini || die "php.ini missing pattern: $pattern"
    done

    mods=$(docker exec "$NAME" apache2ctl -M 2>/dev/null || true)
    grep -q 'mpm_prefork_module' <<<"$mods" || die "mpm_prefork_module is not loaded"
    grep -q 'php_module' <<<"$mods" || die "php_module is not loaded"
    docker exec "$NAME" apache2ctl -t >/dev/null 2>&1 || die "Apache config test failed"

    mpm=$(docker exec "$NAME" sh -c 'cat /etc/apache2/mods-enabled/mpm_prefork.conf 2>/dev/null' || true)
    grep -Eq '^[[:space:]]*StartServers[[:space:]]+5[[:space:]]*$' <<<"$mpm" || die "StartServers is not stock 5"
    grep -Eq '^[[:space:]]*MinSpareServers[[:space:]]+5[[:space:]]*$' <<<"$mpm" || die "MinSpareServers is not stock 5"
    grep -Eq '^[[:space:]]*MaxSpareServers[[:space:]]+10[[:space:]]*$' <<<"$mpm" || die "MaxSpareServers is not stock 10"
    grep -Eq '^[[:space:]]*MaxRequestWorkers[[:space:]]+150[[:space:]]*$' <<<"$mpm" || die "MaxRequestWorkers is not stock 150"
    grep -Eq '^[[:space:]]*MaxConnectionsPerChild[[:space:]]+0[[:space:]]*$' <<<"$mpm" || die "MaxConnectionsPerChild is not stock 0"

    wait_http
    local p2s="$POOL_DIR/logs/p2s-access.log" i
    for i in $(seq 1 40); do
        if [[ -s "$p2s" ]] && grep -Eq '^[0-9]+ ' "$p2s"; then
            break
        fi
        sleep 0.1
    done
    [[ -s "$p2s" ]] || die "p2s-access.log is empty; %P logging is not active"
    grep -Eq '^[0-9]+ ' "$p2s" || die "p2s-access.log has no child-PID lines"
    count=$(wait_children) || die "did not observe at least 5 prefork children"
    if [[ "$count" != "5" ]]; then
        warn "observed $count children (stock starts 5; extra children can be crash respawns)"
    fi
    info "PHP $phpv, Apache 2.4.69, prefork children=$count, libphp=$libsha"
}

write_pool_json() {
    python3 - "$POOL_DIR/pool.json" "$KIT_ID" "$ROOT" "$NAME" "$PORT" "$POOL_DIR" \
        "$IMAGE" "$IMG_ID" "$IMG_ARCH" "$EXPECTED_LIBPHP_SHA256" "$EXPECTED_PHP_INI_SHA256" \
        "$EXPECTED_WP_SHA256" "$WP_VERSION" <<'PY'
import json, os, sys, time
(path, kit_id, root, name, port, pool_dir, image, image_id, arch,
 libsha, inisha, wpsha, wpver) = sys.argv[1:]
obj = {
    "kit_id": kit_id,
    "kit_root": root,
    "name": name,
    "container": name,
    "port": int(port),
    "url": "http://127.0.0.1:%s/wp-content/index.php" % port,
    "pool_dir": pool_dir,
    "log_dir": os.path.join(pool_dir, "logs"),
    "proof_dir": os.path.join(pool_dir, "proof"),
    "image": image,
    "image_id": image_id,
    "arch": arch,
    "php": "8.4.26",
    "apache": "2.4.69",
    "libphp_sha256": libsha,
    "php_ini_sha256": inisha,
    "wordpress_zip_sha256": wpsha,
    "wordpress_version": wpver,
    "offsets": {"S": "0xf8398", "zif_system": "0x465370",
                "zval_ptr_dtor": "0x65eb60", "main_bucket": 87},
    "stock": {
        "mpm": "prefork", "StartServers": 5, "MaxRequestWorkers": 150,
        "post_max_size": "8M", "display_errors": "Off", "memory_limit": "128M",
    },
    "instrumentation": "conf/p2s.conf defines %P; conf/000-default.conf adds a second access log (stock combined log retained); /out is a 0777 proof sink",
    "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
tmp = path + ".tmp"
with open(tmp, "w") as fh:
    json.dump(obj, fh, indent=1, sort_keys=True)
    fh.write("\n")
os.replace(tmp, path)
PY
}

# ---- main ------------------------------------------------------------------
ensure_wp
ensure_config
ensure_bodies
ensure_image

if container_exists; then
    verify_owned_container
    if [[ $FORCE -eq 1 ]]; then
        info "removing existing kit container $NAME (pool data kept)"
        docker rm -f "$NAME" >/dev/null
    else
        check_mounts
        check_port_mapping
        if ! container_running; then
            info "starting existing kit container $NAME"
            docker start "$NAME" >/dev/null
        else
            info "existing kit container $NAME is already running"
        fi
        check_container
        write_pool_json
        info "READY (idempotent no-op)"
        info "URL=http://127.0.0.1:$PORT/wp-content/index.php"
        info "POOL_DIR=$POOL_DIR"
        exit 0
    fi
fi

# Port is only checked for a new container; an owned existing container was
# handled above and its mapping was already verified.
if ! python3 - "$PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", port))
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
then
    die "127.0.0.1:$PORT is already in use; choose another --port"
fi

info "creating stock target container $NAME on 127.0.0.1:$PORT"
docker run -d --name "$NAME" \
    --label p8426.repro=1 \
    --label "p8426.kit=$KIT_ID" \
    --label "p8426.port=$PORT" \
    --stop-timeout 5 \
    -p "127.0.0.1:$PORT:80" \
    -v "$ROOT/work/wordpress:/var/www/html:ro" \
    -v "$ROOT/conf/php.ini-production:/usr/local/etc/php/php.ini:ro" \
    -v "$ROOT/conf/000-default.conf:/etc/apache2/sites-enabled/000-default.conf:ro" \
    -v "$ROOT/conf/p2s.conf:/etc/apache2/conf-enabled/p2s.conf:ro" \
    -v "$POOL_DIR/logs:/var/log/apache2" \
    -v "$POOL_DIR/proof:/out" \
    "$IMAGE" >/dev/null

if ! check_container; then
    echo "---- docker logs (tail) ----" >&2
    docker logs --tail 80 "$NAME" >&2 || true
    die "container $NAME failed readiness checks (left in place for inspection)"
fi
write_pool_json

info "READY"
info "URL=http://127.0.0.1:$PORT/wp-content/index.php"
info "POOL_DIR=$POOL_DIR"
info "container=$NAME  logs=$POOL_DIR/logs  proof=$POOL_DIR/proof"
echo
echo "Next:"
echo "  ./run_pool.sh --url http://127.0.0.1:$PORT/wp-content/index.php \\"
echo "      --marker KIT001 --pool-dir $POOL_DIR --output $ROOT/out/one"

#!/usr/bin/env bash
# =============================================================================
# setup.sh - target-side reproduction of the proven stock cell:
#   Debian 13.7 + Apache 2.4.69-1~deb13u1 (prefork, stock 5/150) +
#   libapache2-mod-php8.4 8.4.24-1~deb13u1 (mod_php) +
#   official WordPress 7.1.3 docroot at /var/www/html
#
# Runs entirely as the invoking user against rootless Docker.
# No sudo, no host Apache, no rootful Docker socket, no host service changes.
#
# THIS IS A SETUP SCRIPT ONLY. It sends no exploit traffic and does not claim
# that the RCE reproduces. It builds/started the target and prints readiness
# checks; a chain runner must be executed separately.
#
# Usage:
#   ./setup.sh up        # build if needed, (re)create container, run checks (default)
#   ./setup.sh check     # re-run readiness checks against the running container
#   ./setup.sh status    # docker ps + HTTP status summary
#   ./setup.sh logs      # container + Apache error log tail
#   ./setup.sh down      # stop and remove the container
#   ./setup.sh shell     # interactive shell in the container
#
# Environment overrides (all optional):
#   NAME=wp8424-repro  PORT=8080  IMAGE=wp8424-repro:8.4.24-deb13u1
#   RUN_DIR=<dir of this script>  BASE_IMAGE=debian@sha256:4c252754...
#   WITH_DIAG=1  WITH_P2S=1  FORCE_BUILD=0
# =============================================================================
set -Eeuo pipefail

SELF_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

RUN_DIR=${RUN_DIR:-$SELF_DIR}
NAME=${NAME:-wp8424-repro}
PORT=${PORT:-8080}
IMAGE=${IMAGE:-wp8424-repro:8.4.24-deb13u1}
BUILD_NAME=${BUILD_NAME:-wp8424-repro-build}
# debian:trixie as built by debuerreotype for 13.7 (resolved 2026-10-23)
BASE_IMAGE=${BASE_IMAGE:-debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308}
BASE_FALLBACK=debian:trixie

WP_URL=${WP_URL:-https://wordpress.org/wordpress-7.1.3.zip}
WP_SHA256=eb58a90ed55147f90f7bd55d0d3334960a69b7e8a4cc142c8ddfea8965218227
WP_ZIP=wordpress-7.1.3.zip

TARGET_SHA256=bd48c24ce4500e60d2524571756787283f0d3fbfa50b116331309c09773f0cd1
TARGET_MD5=67442c5615eba73d105c0715c6620850
WPCONFIG_SHA256=b2b3f3fe6dbf560b38db952a868df3120fff14bb39ba96ea34e2f26b5c2892f8
DOCROOT_FILES=3735
DOCROOT_BYTES=109646539

APACHE_VER=2.4.69-1~deb13u1
PHP_VER=8.4.24-1~deb13u1
LIBPHP_SHA256=7da07d207d2ba2c28b55e11f5754a1a50523e35a5f29b624b22588fe162db70f
PHPINI_MD5=1db700325ee9fd60dc7b291a8865ca15

WITH_DIAG=${WITH_DIAG:-1}
WITH_P2S=${WITH_P2S:-1}
FORCE_BUILD=${FORCE_BUILD:-0}

# snapshot.debian.org fallback for the exact PHP 8.4.24 binary packages
SNAP_TS=20260804T000000Z
SNAP_BASE="https://snapshot.debian.org/archive/debian/${SNAP_TS}/pool/main/p/php8.4"
SNAP_DEBS=(
  "libapache2-mod-php8.4_8.4.24-1~deb13u1_amd64.deb f2ea506c7b26f4d52f74733233c503445c188bb052fbaaff58c9266c6fe052d7"
  "php8.4-cli_8.4.24-1~deb13u1_amd64.deb 8205f927545c28a03fdcc1bd1fc83c1aa9615d2ee1f7cec4cd5c86e59716782f"
  "php8.4-common_8.4.24-1~deb13u1_amd64.deb fe81bee8ec155ed0ba14a2d1330f52f5ad3da2e7446ab74858f61c9e36202052"
  "php8.4-opcache_8.4.24-1~deb13u1_amd64.deb 0ed0c6ae703c5545155cc74905f4d3aad2efadb5c234f77f90e208d5f84f2ace"
  "php8.4-readline_8.4.24-1~deb13u1_amd64.deb 0b61ee28ce6c983c1bd3f7c851ff3f7c9124b3d3ffc52c8285a87d83c84ecc51"
)

DOC_DIR=$RUN_DIR/docroot
ART_DIR=$RUN_DIR/artifacts
LOG_DIR=$RUN_DIR/logs
OUT_DIR=$RUN_DIR/out
CONF_DIR=$RUN_DIR/conf
DIAG_DIR=$RUN_DIR/diag
EVID_DIR=$RUN_DIR/evidence
EVID=$EVID_DIR/setup-checks.txt

C_RESET=$'\033[0m'; C_OK=$'\033[32m'; C_BAD=$'\033[31m'; C_WARN=$'\033[33m'; C_INFO=$'\033[36m'
if [ ! -t 1 ]; then C_RESET=; C_OK=; C_BAD=; C_WARN=; C_INFO=; fi

note() { printf '%s[info]%s %s\n' "$C_INFO" "$C_RESET" "$*" >&2; }
warn() { printf '%s[warn]%s %s\n' "$C_WARN" "$C_RESET" "$*" >&2; }
die()  { printf '%s[FAIL]%s %s\n' "$C_BAD" "$C_RESET" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() { sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
preflight() {
  have docker || die "docker CLI not found; rootless Docker must be installed for $(id -un)"
  have curl   || die "curl not found"
  have sha256sum || die "sha256sum not found (coreutils)"
  docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon as $(id -un). Configure rootless Docker for this user (no sudo)."
  if [ "$(id -u)" -eq 0 ]; then
    warn "running as uid 0; the proven setup is rootless Docker as the normal user 'netsec'"
  fi
  local sec
  sec=$(docker info -f '{{json .SecurityOptions}}' 2>/dev/null || echo '[]')
  case "$sec" in
    *rootless*) : ;;
    *) warn "docker reports no rootless security option ($sec); the proven setup is rootless" ;;
  esac
  mkdir -p "$ART_DIR" "$LOG_DIR" "$OUT_DIR" "$CONF_DIR" "$DIAG_DIR" "$EVID_DIR"
  chmod 0777 "$OUT_DIR" "$LOG_DIR"   # /out must be writable by container uid 33 (www-data)
}

say() { printf '%s\n' "$*"; printf '%s\n' "$*" >> "$EVID"; }
ok()  { say "  ${C_OK}[ OK ]${C_RESET} $1"; }
bad() { say "  ${C_BAD}[FAIL]${C_RESET} $1"; }
inf() { say "  ${C_INFO}[info]${C_RESET} $1"; }

# ---------------------------------------------------------------------------
# artifacts
# ---------------------------------------------------------------------------
ensure_wp_zip() {
  local zip=$ART_DIR/$WP_ZIP
  if [ -f "$zip" ] && [ "$(sha256sum "$zip" | awk '{print $1}')" = "$WP_SHA256" ]; then
    note "artifact present: $zip"
    return
  fi
  note "downloading $WP_URL"
  local tmp=$zip.part
  rm -f "$tmp"
  curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 900 \
       -o "$tmp" "$WP_URL" || die "download failed: $WP_URL"
  if [ "$(sha256sum "$tmp" | awk '{print $1}')" != "$WP_SHA256" ]; then
    rm -f "$tmp"
    die "sha256 mismatch for $WP_URL (expected $WP_SHA256); refusing to use it"
  fi
  mv "$tmp" "$zip"
  note "verified $zip"
}

# ---------------------------------------------------------------------------
# image
# ---------------------------------------------------------------------------
image_ok() {
  docker image inspect "$IMAGE" >/dev/null 2>&1 || return 1
  local out
  out=$(docker run --rm --entrypoint sh "$IMAGE" -c '
    v=$(dpkg-query -W libapache2-mod-php8.4 2>/dev/null | awk "{print \$2}")
    [ "$v" = "'"$PHP_VER"'" ] || exit 1
    sha256sum /usr/lib/apache2/modules/libphp8.4.so | awk "{print \$1}"
  ' 2>/dev/null) || return 1
  [ "$out" = "$LIBPHP_SHA256" ]
}

verify_build() {
  local hash ver apache
  hash=$(docker exec "$BUILD_NAME" sha256sum /usr/lib/apache2/modules/libphp8.4.so | awk '{print $1}')
  ver=$(docker exec "$BUILD_NAME" sh -c 'dpkg-query -W libapache2-mod-php8.4 | awk "{print \$2}"')
  apache=$(docker exec "$BUILD_NAME" sh -c 'dpkg-query -W apache2 | awk "{print \$2}"')
  [ "$hash" = "$LIBPHP_SHA256" ] || die "built module sha256 $hash != $LIBPHP_SHA256"
  [ "$ver" = "$PHP_VER" ] || die "built libapache2-mod-php8.4 $ver != $PHP_VER"
  note "module sha256 verified: $hash"
  note "apache2 package: $apache"
  if [ "$apache" != "$APACHE_VER" ]; then
    warn "apache2 is $apache, proven build used $APACHE_VER (PHP/mod_php identity is unaffected)"
  fi
}

apt_in_build() {
  docker exec -e DEBIAN_FRONTEND=noninteractive "$BUILD_NAME" sh -c '
    apt-get "$@" >/tmp/apt.log 2>&1 || { echo "apt-get failed:" >&2; tail -n 80 /tmp/apt.log >&2; exit 1; }
  ' sh "$@"
}

install_pinned() {
  note "apt-get update (Debian 13 suites)"
  apt_in_build update -qq || return 1
  note "installing pinned apache2=$APACHE_VER php=$PHP_VER"
  if apt_in_build install -y -qq --no-install-recommends \
         "apache2=$APACHE_VER" \
         "libapache2-mod-php8.4=$PHP_VER" \
         "php8.4-cli=$PHP_VER" \
         "php8.4-common=$PHP_VER" \
         "php8.4-opcache=$PHP_VER" \
         "php8.4-readline=$PHP_VER" \
         curl ca-certificates procps unzip; then
    return 0
  fi
  return 1
}

install_snapshot_fallback() {
  warn "exact pins unavailable from the live suites; using snapshot.debian.org debs"
  local debs=$ART_DIR/debs
  mkdir -p "$debs"
  local spec file sha tmp
  for spec in "${SNAP_DEBS[@]}"; do
    file=${spec%% *}; sha=${spec##* }
    tmp=$debs/$file.part
    if [ ! -f "$debs/$file" ] || [ "$(sha256sum "$debs/$file" | awk '{print $1}')" != "$sha" ]; then
      note "downloading $SNAP_BASE/$file"
      rm -f "$tmp"
      curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 600 \
           -o "$tmp" "$SNAP_BASE/$file" \
        || die "missing artifact: $SNAP_BASE/$file (download failed; no substitute used)"
      if [ "$(sha256sum "$tmp" | awk '{print $1}')" != "$sha" ]; then
        rm -f "$tmp"
        die "missing artifact: $SNAP_BASE/$file (sha256 mismatch, expected $sha)"
      fi
      mv "$tmp" "$debs/$file"
    fi
  done
  docker exec "$BUILD_NAME" env DEBIAN_FRONTEND=noninteractive \
    apt-get update -qq || true
  apt_in_build install -y -qq --no-install-recommends apache2 curl ca-certificates procps unzip
  docker exec "$BUILD_NAME" mkdir -p /debs
  docker cp "$debs/." "$BUILD_NAME:/debs/"
  apt_in_build install -y -qq --no-install-recommends --allow-downgrades /debs/*.deb
}

ensure_image() {
  if [ "$FORCE_BUILD" != "1" ] && image_ok; then
    note "image $IMAGE present and verified"
    return
  fi
  local base=$BASE_IMAGE
  if ! docker image inspect "$base" >/dev/null 2>&1; then
    docker pull "$base" >/dev/null 2>&1 || {
      warn "cannot pull $base; falling back to $BASE_FALLBACK (point release may differ)"
      base=$BASE_FALLBACK
      docker pull "$base" >/dev/null
    }
  fi
  note "building $IMAGE from $base (one-time, needs network)"
  docker rm -f "$BUILD_NAME" >/dev/null 2>&1 || true
  docker run -d --name "$BUILD_NAME" "$base" sleep infinity >/dev/null

  if ! install_pinned; then
    docker exec "$BUILD_NAME" env DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
    install_snapshot_fallback
  fi
  verify_build
  docker commit \
    --change 'CMD ["apache2ctl","-D","FOREGROUND"]' \
    --change 'EXPOSE 80' \
    --change 'LABEL org.php2slop.repro="wp7.1.3-apache2.4.69-modphp8.4.24-deb13u1"' \
    "$BUILD_NAME" "$IMAGE" >/dev/null
  docker rm -f "$BUILD_NAME" >/dev/null
  note "built $IMAGE"
}

# ---------------------------------------------------------------------------
# docroot
# ---------------------------------------------------------------------------
docroot_counts() {
  local dir=$1
  local files bytes
  files=$(find "$dir" -type f | wc -l | tr -d ' ')
  bytes=$(find "$dir" -type f -printf '%s\n' | awk '{s+=$1} END{print s+0}')
  printf '%s %s\n' "$files" "$bytes"
}

docroot_valid() {
  [ -f "$DOC_DIR/wp-includes/version.php" ] || return 1
  [ -f "$DOC_DIR/wp-content/index.php" ] || return 1
  [ "$(sha256sum "$DOC_DIR/wp-content/index.php" | awk '{print $1}')" = "$TARGET_SHA256" ] || return 1
  local counts; counts=$(docroot_counts "$DOC_DIR")
  [ "$counts" = "$DOCROOT_FILES $DOCROOT_BYTES" ]
}

ensure_docroot() {
  if docroot_valid; then
    note "docroot present and byte-verified ($DOCROOT_FILES files, $DOCROOT_BYTES B)"
    return
  fi
  note "materialising WordPress 7.1.3 docroot"
  docker rm -f "$NAME" >/dev/null 2>&1 || true   # release the old ro mount
  rm -rf "$DOC_DIR.new"; mkdir -p "$DOC_DIR.new"
  docker run --rm --entrypoint sh \
    -v "$ART_DIR:/a:ro" -v "$DOC_DIR.new:/w" "$IMAGE" -c \
    'cd /w && unzip -q /a/'"$WP_ZIP"' && cp -a wordpress/. . && rm -rf wordpress' \
    || die "docroot extraction failed"
  # exact proven tree: official ZIP minus 48 inactive bundled files, plus
  # wp-config.php byte-identical to wp-config-sample.php
  rm -rf "$DOC_DIR.new/wp-content/plugins/akismet" "$DOC_DIR.new/wp-content/plugins/hello.php"
  cp "$DOC_DIR.new/wp-config-sample.php" "$DOC_DIR.new/wp-config.php"
  find "$DOC_DIR.new" -type d -exec chmod 755 {} +
  find "$DOC_DIR.new" -type f -exec chmod 644 {} +

  [ "$(sha256sum "$DOC_DIR.new/wp-content/index.php" | awk '{print $1}')" = "$TARGET_SHA256" ] \
    || die "target endpoint sha256 mismatch after extraction"
  [ "$(sha256sum "$DOC_DIR.new/wp-config.php" | awk '{print $1}')" = "$WPCONFIG_SHA256" ] \
    || die "wp-config.php sha256 mismatch after extraction"
  local counts; counts=$(docroot_counts "$DOC_DIR.new")
  [ "$counts" = "$DOCROOT_FILES $DOCROOT_BYTES" ] \
    || die "docroot shape $counts != '$DOCROOT_FILES $DOCROOT_BYTES'"
  rm -rf "$DOC_DIR"
  mv "$DOC_DIR.new" "$DOC_DIR"
  note "docroot verified: $counts files/bytes, endpoint $TARGET_SHA256"
}

# ---------------------------------------------------------------------------
# config (instrumentation only; outside the docroot)
# ---------------------------------------------------------------------------
write_configs() {
  if [ "$WITH_DIAG" = "1" ]; then
    cat > "$DIAG_DIR/phpversion.php" <<'PHP'
<?php
header('Content-Type: text/plain');
echo 'php=' . PHP_VERSION . "\n";
echo 'sapi=' . php_sapi_name() . "\n";
foreach (['post_max_size','memory_limit','display_errors','output_buffering',
          'upload_max_filesize','expose_php','session.upload_progress.enabled',
          'max_input_vars'] as $k) {
    echo $k . '=[' . ini_get($k) . "]\n";
}
PHP
    chmod 644 "$DIAG_DIR/phpversion.php"
    cat > "$CONF_DIR/zz-repro-diag.conf" <<'CONF'
# Lab instrumentation for readiness checks only: endpoint outside the docroot.
Alias /__repro/phpversion.php /opt/repro/phpversion.php
<Directory /opt/repro>
    Require all granted
</Directory>
CONF
  fi

  if [ "$WITH_P2S" = "1" ]; then
    # The proven container carried one logging-only delta: a p2s LogFormat
    # (%P child pid) and a CustomLog for it. Reproduce it exactly, generated
    # from the stock file shipped in this image.
    docker run --rm --entrypoint cat "$IMAGE" /etc/apache2/sites-available/000-default.conf \
      > "$CONF_DIR/000-default-p2s.conf"
    awk '{print} /CustomLog .*access\.log combined/ {print "\tCustomLog ${APACHE_LOG_DIR}/p2s-access.log p2s"}' \
      "$CONF_DIR/000-default-p2s.conf" > "$CONF_DIR/000-default-p2s.conf.new"
    mv "$CONF_DIR/000-default-p2s.conf.new" "$CONF_DIR/000-default-p2s.conf"
    grep -q 'p2s-access.log' "$CONF_DIR/000-default-p2s.conf" \
      || die "failed to add p2s CustomLog to 000-default.conf"
    cat > "$CONF_DIR/p2s.conf" <<'CONF'
LogFormat "%P %{%s}t.%{usec_frac}t %m %U %>s %b %D" p2s
CONF
  fi
}

# ---------------------------------------------------------------------------
# container lifecycle
# ---------------------------------------------------------------------------
start_container() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if curl -s -o /dev/null -m 1 "http://127.0.0.1:$PORT/" 2>/dev/null; then
    die "127.0.0.1:$PORT is already serving something else; set PORT=<free port>"
  fi
  local args=(run -d --name "$NAME" --restart=no
    -p "127.0.0.1:$PORT:80"
    -v "$DOC_DIR:/var/www/html:ro"
    -v "$LOG_DIR:/var/log/apache2"
    -v "$OUT_DIR:/out")
  if [ "$WITH_DIAG" = "1" ]; then
    args+=(-v "$DIAG_DIR:/opt/repro:ro"
           -v "$CONF_DIR/zz-repro-diag.conf:/etc/apache2/conf-enabled/zz-repro-diag.conf:ro")
  fi
  if [ "$WITH_P2S" = "1" ]; then
    args+=(-v "$CONF_DIR/000-default-p2s.conf:/etc/apache2/sites-enabled/000-default.conf:ro"
           -v "$CONF_DIR/p2s.conf:/etc/apache2/conf-enabled/p2s.conf:ro")
  fi
  docker "${args[@]}" "$IMAGE" apache2ctl -D FOREGROUND >/dev/null
  sleep 0.5
  if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || echo false)" != "true" ]; then
    docker logs "$NAME" 2>&1 | tail -40 || true
    die "container $NAME exited during startup"
  fi
}

wait_ready() {
  local probe="http://127.0.0.1:$PORT/wp-content/index.php"
  [ "$WITH_DIAG" = "1" ] && probe="http://127.0.0.1:$PORT/__repro/phpversion.php"
  local i
  for i in $(seq 1 60); do
    if curl -fsS -m 2 "$probe" >/dev/null 2>&1; then return 0; fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || echo false)" != "true" ]; then
      docker logs "$NAME" 2>&1 | tail -40 || true
      die "container $NAME exited while waiting for readiness"
    fi
    sleep 0.5
  done
  die "target did not become ready on 127.0.0.1:$PORT"
}

# ---------------------------------------------------------------------------
# readiness checks
# ---------------------------------------------------------------------------
run_checks() {
  : > "$EVID"
  say "=== target repro readiness $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
  say ""

  local running portmap
  running=$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || echo false)
  portmap=$(docker port "$NAME" 80/tcp 2>/dev/null | head -1 || true)
  [ "$running" = "true" ] && ok "container running: $NAME" || bad "container $NAME not running"
  [ "$portmap" = "127.0.0.1:$PORT" ] && ok "port mapping: $portmap" || bad "port mapping: '$portmap' (expected 127.0.0.1:$PORT)"

  local osver
  osver=$(docker run --rm --entrypoint cat "$IMAGE" /etc/debian_version 2>/dev/null || echo unknown)
  [ "$osver" = "13.7" ] && ok "base OS: Debian $osver" || inf "base OS: Debian $osver (proven: 13.7)"

  local pkg apkg
  pkg=$(docker exec "$NAME" sh -c 'dpkg-query -W libapache2-mod-php8.4 | awk "{print \$2}"' 2>/dev/null || echo missing)
  apkg=$(docker exec "$NAME" sh -c 'dpkg-query -W apache2 | awk "{print \$2}"' 2>/dev/null || echo missing)
  [ "$pkg" = "$PHP_VER" ] && ok "libapache2-mod-php8.4: $pkg" || bad "libapache2-mod-php8.4: $pkg (expected $PHP_VER)"
  [ "$apkg" = "$APACHE_VER" ] && ok "apache2: $apkg" || inf "apache2: $apkg (proven: $APACHE_VER)"

  local modhash
  modhash=$(docker exec "$NAME" sha256sum /usr/lib/apache2/modules/libphp8.4.so 2>/dev/null | awk '{print $1}')
  [ "$modhash" = "$LIBPHP_SHA256" ] \
    && ok "libphp8.4.so sha256: $modhash" \
    || bad "libphp8.4.so sha256: $modhash (expected $LIBPHP_SHA256)"

  local inimd5
  inimd5=$(docker exec "$NAME" md5sum /etc/php/8.4/apache2/php.ini 2>/dev/null | awk '{print $1}')
  [ "$inimd5" = "$PHPINI_MD5" ] \
    && ok "php.ini md5: $inimd5 (stock package conffile)" \
    || bad "php.ini md5: $inimd5 (expected $PHPINI_MD5)"

  local mpm
  mpm=$(docker exec "$NAME" sh -c 'apache2ctl -V 2>/dev/null | sed -n "s/^Server MPM: *//p"' | head -1)
  [ "$mpm" = "prefork" ] && ok "Apache MPM: $mpm" || bad "Apache MPM: '$mpm' (expected prefork)"

  local mods
  mods=$(docker exec "$NAME" sh -c 'apache2ctl -M 2>/dev/null' || true)
  if printf '%s' "$mods" | grep -q 'mpm_prefork_module' && printf '%s' "$mods" | grep -q 'php_module'; then
    ok "modules: mpm_prefork_module + php_module"
  else
    bad "modules: mpm_prefork_module/php_module missing"
  fi

  local mpmconf
  mpmconf=$(docker exec "$NAME" sh -c 'grep -hE "^(StartServers|MinSpareServers|MaxSpareServers|MaxRequestWorkers|MaxConnectionsPerChild)" /etc/apache2/mods-available/mpm_prefork.conf' 2>/dev/null | tr -s ' ' | tr '\n' ';' || true)
  ok "prefork MPM config: $mpmconf"

  local workers
  workers=$(docker exec "$NAME" sh -c 'ps -o pid= -C apache2 2>/dev/null | wc -l' || echo 0)
  inf "apache2 processes (parent+children): $(echo "$workers" | tr -d ' ')"

  if [ "$WITH_DIAG" = "1" ]; then
    local diag
    diag=$(curl -fsS -m 5 "http://127.0.0.1:$PORT/__repro/phpversion.php" 2>/dev/null || true)
    local phpver sapi post mem de ob up exp
    phpver=$(printf '%s\n' "$diag" | sed -n 's/^php=\[\(.*\)\]$/\1/p; s/^php=\(.*\)$/\1/p' | head -1)
    sapi=$(printf '%s\n' "$diag" | sed -n 's/^sapi=\(.*\)$/\1/p' | head -1)
    getv() { printf '%s\n' "$diag" | sed -n "s/^$1=\[\(.*\)\]\$/\1/p" | head -1; }
    post=$(getv post_max_size); mem=$(getv memory_limit); de=$(getv display_errors)
    ob=$(getv output_buffering); up=$(getv upload_max_filesize); exp=$(getv expose_php)
    [ "$phpver" = "8.4.24" ] && ok "PHP version (apache2handler): $phpver" || bad "PHP version: '$phpver' (expected 8.4.24)"
    [ "$sapi" = "apache2handler" ] && ok "SAPI: $sapi" || bad "SAPI: '$sapi' (expected apache2handler)"
    [ "$post" = "8M" ] && ok "post_max_size: $post" || bad "post_max_size: '$post' (expected 8M)"
    [ "$mem" = "128M" ] && ok "memory_limit: $mem" || bad "memory_limit: '$mem' (expected 128M)"
    [ -z "$de" ] && ok "display_errors: Off" || bad "display_errors: '$de' (expected Off/empty)"
    [ "$ob" = "4096" ] && ok "output_buffering: $ob" || bad "output_buffering: '$ob' (expected 4096)"
    [ "$up" = "2M" ] && ok "upload_max_filesize: $up" || bad "upload_max_filesize: '$up' (expected 2M)"
    [ -z "$exp" ] && ok "expose_php: Off" || inf "expose_php: '$exp' (expected Off)"
  else
    inf "diagnostic endpoint disabled (WITH_DIAG=0); effective ini not sampled"
  fi

  local counts files bytes
  counts=$(docroot_counts "$DOC_DIR"); files=${counts%% *}; bytes=${counts##* }
  [ "$files" = "$DOCROOT_FILES" ] && ok "docroot files: $files" || bad "docroot files: $files (expected $DOCROOT_FILES)"
  [ "$bytes" = "$DOCROOT_BYTES" ] && ok "docroot bytes: $bytes" || bad "docroot bytes: $bytes (expected $DOCROOT_BYTES)"
  local tsha tmd5
  tsha=$(sha256sum "$DOC_DIR/wp-content/index.php" | awk '{print $1}')
  tmd5=$(md5sum "$DOC_DIR/wp-content/index.php" | awk '{print $1}')
  [ "$tsha" = "$TARGET_SHA256" ] && ok "endpoint sha256: $tsha" || bad "endpoint sha256: $tsha"
  [ "$tmd5" = "$TARGET_MD5" ] && ok "endpoint md5: $tmd5" || bad "endpoint md5: $tmd5"
  [ "$(sha256sum "$DOC_DIR/wp-config.php" | awk '{print $1}')" = "$WPCONFIG_SHA256" ] \
    && ok "wp-config.php == wp-config-sample.php (sha256 verified)" \
    || bad "wp-config.php does not match wp-config-sample.php"

  local code size
  read -r code size < <(curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -m 10 "http://127.0.0.1:$PORT/wp-content/index.php")
  [ "$code" = "200" ] && [ "$size" = "0" ] \
    && ok "GET /wp-content/index.php: $code, $size bytes (silence file)" \
    || bad "GET /wp-content/index.php: $code, $size bytes (expected 200/0)"

  local fcode
  fcode=$(curl -s -o "$EVID_DIR/frontpage.html" -w '%{http_code}' -m 10 "http://127.0.0.1:$PORT/" || echo 000)
  if [ "$fcode" = "200" ]; then
    ok "GET / (WordPress front page): 200"
  elif [ "$fcode" = "500" ] && grep -qE 'missing the MySQL extension|Error establishing a database connection' "$EVID_DIR/frontpage.html"; then
    ok "GET / (WordPress front page): 500, reached WordPress requirements/DB bootstrap"
    inf "  audited cell has no DB and no mysqli -> 500 is the expected front-page state"
    inf "  $(grep -oE 'missing the MySQL extension[^<]*|Error establishing a database connection' "$EVID_DIR/frontpage.html" | head -1)"
  else
    bad "GET / (WordPress front page): $fcode (unexpected)"
  fi

  if docker exec -u 33 "$NAME" sh -c 'touch /out/.write_probe && rm -f /out/.write_probe' >/dev/null 2>&1; then
    ok "/out writable by container uid 33 (www-data)"
  else
    bad "/out not writable by container uid 33; B2 proof writes would fail"
  fi

  if docker exec "$NAME" sh -c 'touch /var/www/html/.ro_probe' >/dev/null 2>&1; then
    docker exec "$NAME" rm -f /var/www/html/.ro_probe >/dev/null 2>&1 || true
    bad "docroot is writable inside the container (expected read-only mount)"
  else
    ok "docroot mounted read-only"
  fi

  local aslr
  aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo unknown)
  [ "$aslr" = "2" ] && ok "host ASLR randomize_va_space: $aslr" || warn "host ASLR randomize_va_space: $aslr (proven: 2)"

  say ""
  say "--- container ---"
  docker ps --filter "name=^/${NAME}$" --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' | sed 's/^/  /' | tee -a "$EVID" >/dev/null
  docker ps --filter "name=^/${NAME}$" --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
  say ""
  say "--- target ---"
  say "  URL:      http://127.0.0.1:$PORT/"
  say "  endpoint: http://127.0.0.1:$PORT/wp-content/index.php"
  say "  docroot:  $DOC_DIR (ro mount at /var/www/html)"
  say "  proofs:   $OUT_DIR (rw mount at /out, mode 0777)"
  say "  logs:     $LOG_DIR (rw mount at /var/log/apache2)"
  say "  stop:     $SELF_DIR/setup.sh down"
  say ""
  if grep -q '^  .*\[FAIL\]' "$EVID"; then
    say "RESULT: FAILED checks present (see above)"
    return 2
  fi
  say "RESULT: setup ready (setup only; no exploit traffic was sent)"
  return 0
}

# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------
cmd_up() {
  preflight
  ensure_wp_zip
  ensure_image
  ensure_docroot
  write_configs
  start_container
  wait_ready
  run_checks
}

cmd_check() {
  preflight
  [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || echo false)" = "true" ] \
    || die "container $NAME is not running; run ./setup.sh up"
  run_checks
}

cmd_status() {
  preflight
  docker ps -a --filter "name=^/${NAME}$" \
    --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
  printf 'front page: %s\n' "$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://127.0.0.1:$PORT/" || echo unreachable)"
  printf 'endpoint:   %s\n' "$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://127.0.0.1:$PORT/wp-content/index.php" || echo unreachable)"
}

cmd_logs() {
  docker logs --tail 40 "$NAME" 2>&1 || true
  echo "--- $LOG_DIR/error.log (tail) ---"
  tail -n 40 "$LOG_DIR/error.log" 2>/dev/null || true
}

cmd_down() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  echo "stopped and removed container: $NAME"
}

cmd_shell() {
  docker exec -it "$NAME" bash || docker exec -it "$NAME" sh
}

case "${1:-up}" in
  up)     cmd_up ;;
  check)  cmd_check ;;
  status) cmd_status ;;
  logs)   cmd_logs ;;
  down)   cmd_down ;;
  shell)  cmd_shell ;;
  -h|--help|help) usage ;;
  *) usage; exit 2 ;;
esac

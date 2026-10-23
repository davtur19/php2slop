# Fetch and run: WordPress 8.4.24 positive-control target

Temporary branch: **`research/wp8424-setup`** (not merged to `master`).
Content: setup-only kit. No exploit traffic, no RCE claim.

## Target prerequisites (Debian 13, user `netsec`)

- Rootless Docker already configured for `netsec`; `docker info` succeeds without sudo.
- `bash`, `curl`, `sha256sum` (coreutils), `git`, `docker` CLI.
- Outbound HTTPS to `wordpress.org`, `registry-1.docker.io`, and `deb.debian.org`
  (or `snapshot.debian.org` for the pinned PHP fallback).
- ~1.5 GB free disk; a free local TCP port (default `8080`).
- No host Apache, no rootful Docker socket, no `sudo`.

## Fetch into a worktree

```bash
cd /home/netsec/php2slop            # any existing clone of the repo
git fetch origin research/wp8424-setup
git worktree add /home/netsec/wp8424-setup FETCH_HEAD
cd /home/netsec/wp8424-setup/research_target/wp8424
```

`FETCH_HEAD` gives a detached worktree at the published commit. To update later:
`git fetch origin research/wp8424-setup` and re-add a fresh worktree.

## Run

Use a runtime directory outside the checkout so the 37 MB ZIP and 110 MB docroot
do not land in the worktree (they are git-ignored either way):

```bash
mkdir -p /home/netsec/wp8424-run
RUN_DIR=/home/netsec/wp8424-run ./setup.sh up
RUN_DIR=/home/netsec/wp8424-run ./setup.sh check
RUN_DIR=/home/netsec/wp8424-run ./setup.sh status
```

If `8080` is taken:

```bash
RUN_DIR=/home/netsec/wp8424-run PORT=28081 ./setup.sh up
```

Stop:

```bash
RUN_DIR=/home/netsec/wp8424-run ./setup.sh down
# or: docker rm -f wp8424-repro
```

`RUN_DIR` holds `artifacts/`, `docroot/`, `conf/`, `diag/`, `logs/`, `out/`,
`evidence/`; only `setup.sh` creates them. `conf/` and `diag/` are generated at
runtime and are intentionally not committed.

## What the first `up` does

1. Downloads `https://wordpress.org/wordpress-7.1.3.zip` (37,226,383 B) and
   verifies sha256 `eb58a90e…218227`; aborts on mismatch.
2. Pulls `debian@sha256:4c252754…44b308` (13.7) and installs the pinned
   `apache2=2.4.69-1~deb13u1` + `libapache2-mod-php8.4=8.4.24-1~deb13u1`
   set (snapshot.debian.org fallback with exact hashes if the live suite moved on).
3. Verifies `libphp8.4.so` sha256 `7da07d20…2db70f` before committing the image.
4. Extracts WordPress to `RUN_DIR/docroot` (3,735 files / 109,646,539 B) and
   verifies the endpoint and `wp-config.php` hashes.
5. Starts the container on `127.0.0.1:$PORT` and runs 28 readiness checks.

Expected healthy result: **28 `[ OK ]`, 0 `[FAIL]`, `RESULT: setup ready`**.
`GET /` returns **500** ("missing the MySQL extension") by design — the audited
cell has no database and no `mysqli`. `GET /wp-content/index.php` returns
**200 / 0 bytes**.

If a download or hash fails, `setup.sh` stops with an explicit `[FAIL]` or
`missing artifact` message; it never substitutes a different version.

## Validation evidence (source host, 2026-10-23)

- Clean copy containing only `setup.sh` + `README.md` (no `artifacts/`, no
  `docroot/`), fresh `FORCE_BUILD=1` image, free port 28083:
  - downloaded and hash-verified WordPress 7.1.3 from wordpress.org;
  - built `apache2 2.4.69-1~deb13u1` + PHP `8.4.24-1~deb13u1` from the pinned
    suites; module sha256 and php.ini md5 matched;
  - 28 `[ OK ]`, 0 `[FAIL]`, exit 0.
- `./setup.sh check` on that container: exit 0, 28 `[ OK ]`.
- Second `./setup.sh up` without `FORCE_BUILD`: reused the verified image and
  byte-verified docroot, exit 0.
- `./setup.sh status`: front page 500, endpoint 200.
- No change to `setup.sh` was required for artifact-free operation.

## Scope

Setup only. This kit sends no exploit request and makes no RCE claim. It builds
and verifies a stock WordPress 7.1.3 + Apache 2.4.69 prefork + mod_php 8.4.24
(Debian 13.7) positive-control environment.

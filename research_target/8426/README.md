# PHP 8.4.26 stock multi-worker replication kit

Self-contained package for the blind A1 → B1 → A2 → B2 WordPress 7.1.3 chain
on the official `php:8.4.26-apache` image with stock prefork mod_php.

This kit is target-ready. It was **not** run on the target host. It was
syntax-checked and exercised locally against the same pinned image as a
packaging validation; see “Validation status” below.

## What it builds

| Item | Exact value |
|---|---|
| Image | `php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` |
| Image ID (linux/amd64) | `sha256:46b195b6378e712d1a65cd3f853242bebd7f3cb4cafe137fd592b365909d2c17` |
| PHP | 8.4.26 NTS (built 2026-10-21 00:31:19), Zend 4.4.26 |
| Apache | 2.4.69 (Debian 13), `mpm_prefork_module` + `php_module` |
| MPM | stock prefork: `StartServers 5`, `MinSpareServers 5`, `MaxSpareServers 10`, `MaxRequestWorkers 150`, `MaxConnectionsPerChild 0` |
| INI | image’s `php.ini-production`, unmodified: `post_max_size=8M`, `display_errors=Off`, `memory_limit=128M` |
| WordPress | official 7.1.3, `https://wordpress.org/wordpress-7.1.3.zip`, sha256 `eb58a90ed55147f90f7bd55d0d3334960a69b7e8a4cc142c8ddfea8965218227` |
| Endpoint | `/wp-content/index.php` (28 B, sha256 `bd48c24c…f0cd1`) |
| libphp.so | 21,241,016 B, sha256 `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c` |
| Offsets | `S = main + 0xF8398`, `zif_system = lib + 0x465370`, `zval_ptr_dtor = lib + 0x65EB60`, main bucket 87 |
| Bodies | A1 993,911 B; B1 33,128,677 B; A2 279,369 B; B2 451,384 B (built per leak) |

The WordPress ZIP is **not** committed (37 MB). `setup.sh` downloads the
pinned official ZIP into `vendor/` and verifies the pinned SHA-256 before
extracting; a pre-downloaded ZIP at `vendor/wordpress-7.1.3.zip` is accepted
only if it matches. The image and that ZIP are the only external downloads.

## Prerequisites

- Debian 13 (or compatible) host, unprivileged user `netsec` (root is refused).
- **Rootless** Docker. `docker info` must contain `name=rootless`; the kit
  refuses a context whose endpoint is `/var/run/docker.sock`. No sudo, no host
  Apache, no systemd unit is used.
- `python3` >= 3.10, `curl`, `sha256sum`, `docker` in `PATH`.
- ~1 GB free disk (kit checkout ~200 KB, WordPress ZIP ~37 MB, extracted
  WordPress ~110 MB, logs/proofs).
- Ports `18080..18099` free on `127.0.0.1` for the 20-pool run.
- Network access to Docker Hub for the pinned image, unless it is pre-pulled.

The target host is described as 96 CPUs / 251 GiB RAM; 20 pools × 5 children
(100 Apache children, 150-worker cap per pool) fits comfortably.

## Get the kit and run one pool

The kit lives on branch `research/8426-kit` under `research_target/8426/`.
From any clone of the repository that has `origin` configured:

```bash
git fetch origin research/8426-kit
git worktree add /home/netsec/8426-kit FETCH_HEAD
cd /home/netsec/8426-kit/research_target/8426
```

`git worktree add` creates the directory and refuses to reuse one that
already exists (choose another path in that case). `FETCH_HEAD` is the branch
head fetched by the preceding command.

Then:

```bash
./setup.sh --port 18080
./run_pool.sh \
  --url http://127.0.0.1:18080/wp-content/index.php \
  --marker KIT001 \
  --pool-dir ./pools/p8426_18080 \
  --output ./out/one
```

`setup.sh` is idempotent: it verifies the existing container’s labels, mounts,
port, image and PHP/MPM/INI state instead of recreating it. Use `--force` to
recreate the named container (pool data is kept). `--stop` stops only that
container.

`run_pool.sh` sends 10 benign GETs (the same warm-up used in the measured
run), then one A1 → B1 → A2 → B2 attempt by default.  If `--pool-dir` is
omitted for a default `p8426_<port>` pool, the runner discovers
`pools/p8426_<port>/pool.json` from the URL port automatically. It exits **0 only when a
target-written proof file contains `uid=33(www-data)` and the marker**; it
exits 1 otherwise.

## Twenty independent fresh pools

```bash
./run_parallel.sh --n 20 --base-port 18080 --output ./out/parallel
```

This creates `p8426_18080` … `p8426_18099`, each a fresh 5-child stock prefork
pool, then runs one attempt per pool (`KIT18080` … `KIT18099`) and writes:

- `out/parallel/summary.tsv` — one row per pool: port, marker, result, A1 PID,
  first B1 PID, leak PID/bytes, A2 PIDs, proof child/bytes, abort/SEGV counts,
  proof path.
- `out/parallel/summary.json` — full rows plus totals.
- `out/parallel/pool_<port>/result.json` — full per-attempt evidence,
  including every request status/PID and the exact B2 body hash.
- `out/parallel/pool_<port>.log` and `setup_<port>.log` — raw stdout/stderr.

Default is one attempt per pool because the first attempt on a fresh pool is
the observed precondition. To reproduce the blind 20-attempts-per-pool
protocol, add `--attempts 20`; that is expected to produce about 1 success per
pool (measured 3/60 = 5.0%), not 20.

## Stop and clean up

```bash
# Stop the single setup pool (container only; logs/proofs kept)
./setup.sh --stop --port 18080

# Stop all pools from this kit
./run_parallel.sh --stop

# Remove all pools from this kit (requires --yes; logs/proofs kept)
./run_parallel.sh --cleanup --yes
```

Containers are selected by the labels `p8426.repro=1`, `p8426.kit=<kit-id>`
and the name pattern `p8426_<digits>`. The scripts never stop, remove or
inspect unrelated containers, images or volumes. `docker rm -f` is used only
after those checks.

## Expected proof

A successful B2 writes `/out/p1_<marker>` inside the container, which is the
host’s `pools/p8426_<port>/proof/p1_<marker>`:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
KIT001
```

Under rootless Docker the host owner is normally `100032:100032` (the subuid
mapping of container uid 33); `run_pool.sh` records the file hash and content,
not the owner. A callback (`--callback`, with `--callback-log`) is recorded as
supplementary evidence but does **not** count as a proof unless
`--allow-callback-as-proof` is explicitly given.

## Expected sequence and failure modes

Normal fresh-pool success:

1. A1: `500` / 211-byte response, OOM in the request cleanup.
2. B1: the first four children normally return `200` / 256 B; the B1 that
   returns to the A1 child leaks a 1.65–1.69 MB `Set-Cookie` (decoded
   819,208 B).  It is usually B1 #5, but can be #6 if Apache has just forked
   an extra child (the measured lab and local runs both showed this); the
   runner allows up to 10 and stops the sweep on the leak.
3. A2: five `500` / 211 responses.
4. B2: the first request may hit a non-A2 child and return `200` / 256; a
   retry hits the proof child, writes the proof, and the child then dies with
   `Segmentation fault (11)` (client sees status 0).

Expected failure modes, all recorded in `result.json`:

- `zend_mm_heap corrupted` followed by `child pid N exit signal Abort (6)`:
  a B1 reached a child that had already processed a B1.  This was the
  measured post-first outcome in 57/57 blind failures; a post-first attempt
  can also simply return `200` / 256 B for all ten B1s with no leak.  Both
  are failures; only a uid proof is success.
- B1 responses of `200` / 256 B are normal non-leak responses.
- An A1 `500` / 211 with a zero-byte body is expected (`display_errors=Off`).
- A declared-length B1 is blocked by the stock 8 MiB `post_max_size`; the kit
  uses chunked B1 and does not change the INI.
- A wrong or missing proof file means no success, regardless of leak size or
  HTTP status.

### Caveat on rate

The **first attempt on a fresh pool** is the observed precondition. Measured
on this exact build: first attempt 3/3 blind (4/4 including an extra stock-A1
pool, not a blind rate); blind 20-attempts-per-pool 3/60 = 5.0% (Wilson
1.7–13.7%); post-first 0/57. Do not quote the fresh-pool 4/4 as a blind rate.
Benign GETs alone did not break the chain; the precondition is heap freshness
with respect to B1 (an inference from the PID/outcome correlation, not an
allocator measurement).

## Stockness and instrumentation

- Stock image, stock prefork MPM, stock vhost plus one logging-only second
  `CustomLog`, unmodified image-shipped
  `php.ini-production`. No `MaxRequestWorkers=1`, no worker pinning, no
  `mod_unique_id`, no manual kill/restart, no host Apache.
- Only observation deltas: `conf/p2s.conf` defines the `%P` child-PID format
  and `conf/000-default.conf` adds it as a **second** access log (the stock
  `access.log combined` is retained).  This is logging only and is not
  loaded by the exploit.  `/out` is a 0777 proof sink.  The docroot, INI,
  vhost and p2s config are mounted read-only.
- No application LFI, no plugin, no third-party write. The only
  attacker-controlled write outside PHP’s normal session handling is the
  same-chain proof file; normal PHP session files also appear in the
  container’s `/tmp`.
- No IDA, no source-host files, no repo path, no sudo and no rootful socket
  are required. Everything executable is under this directory.

## File map

```
setup.sh                 idempotent target setup / readiness / stop
run_pool.sh              shell wrapper for the chain runner
run_parallel.sh          N fresh pools + aggregation + safe stop/cleanup
README.md                this file
KIT_ID                   kit identity used in Docker labels
lib/chain8426.py         HTTP sequence, leak parser, B2 builder, evidence
bodies/manifest.json     uncompressed sizes + SHA-256 for all bodies
bodies/*.bin.gz          exact A1 / B1 / A2 request bodies (gzip)
conf/php.ini-production  exact mounted INI (hash pinned)
conf/000-default.conf    stock vhost + a second %P access log (logging only)
conf/p2s.conf            defines the %P log format
.gitignore               ignores work/, pools/, out/, vendor/ and caches
MANIFEST.sha256          SHA-256 of every committed kit file
work/                    extracted WordPress + decompressed bodies (created)
pools/                   per-pool logs/proofs/pool.json (created)
out/                     runner output (created)
vendor/                  downloaded WordPress ZIP (created, not committed)
```

## Validation status

**Source-side end-to-end validation passed; there has been no target run
yet.** The kit was exercised locally on fresh pools against the same pinned
image (rootless Docker), but the target host has not been touched and no
target-side result exists.

The WordPress ZIP is downloaded by `setup.sh` and hash-verified against the
pinned SHA-256; no vendor ZIP is committed to this branch.

Checks run on the packaging host:

```bash
bash -n setup.sh run_pool.sh run_parallel.sh
python3 -c 'import ast; ast.parse(open("lib/chain8426.py").read())'
./run_pool.sh --dry-run --url http://127.0.0.1:18080/wp-content/index.php
```

The kit was then exercised end-to-end locally on fresh pools: a single
`setup.sh` + `run_pool.sh` run, a 2-pool `run_parallel.sh` run (2/2
target-written uid proofs), and a post-first attempt that failed without a
leak (including the `zend_mm_heap corrupted` / `Abort (6)` path in a
2-attempt run).  The target host has **not** been touched.  Any target run
must be performed by the operator as `netsec`, against operator-owned
infrastructure.

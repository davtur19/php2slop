# WordPress 7.1.3 on `php:8.4.26-apache` — target-written `uid` proof (copied)

**Status: target-written proof.** Produced on 2026-10-23 against a pristine WordPress 7.1.3 tree at `/wp-content/index.php`; copied byte-for-byte and hash-verified, not re-executed during the 2026-10-26 rerun.

| item | value |
|---|---|
| target | pristine WordPress 7.1.3, read-only docroot |
| endpoint | `/wp-content/index.php` (28-byte core silence file, md5 `67442c5615eba73d105c0715c6620850`) |
| image | `php:8.4.26-apache` |
| offset set | `zval_ptr_dtor=0x65eb60`, `zif_system=0x465370`, `S=main+0xF8398` |
| A1 / A2 | 500 / 500 |
| B1 | 200, 819,208 B decoded, 87 hits (i=4) |
| B2 | 451384 B body, hit i=4, response 0 B |
| marker | `WP713` |

Proof `proofs/p1_conc_WP713`: 60 bytes, sha256 `badd7249d344c463fe1cd890b257bc5519568573f0a5b293a247d3eae64ccc71`, content `uid=33(www-data) gid=33(www-data) groups=33(www-data)\nWP713\n`.

Evidence: `evidence/result.json` (original per-stage record), `report.md` (verbatim matrix report, sha256 `bfdca47ec217b4fc2c35430becd27371d03208ccccc78ca2435b346810b491f7`).

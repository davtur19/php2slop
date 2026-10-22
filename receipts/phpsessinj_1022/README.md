# PHP-level session injection + POP chains — stock-config assessment

Receipt: `/tmp/opencode/research/phpsessinj_1792633613`
Date: 2026-10-22
Scope: `session.upload_progress` write format, request-init decode timing, PHPGGC chain inventory and a stock PoC outline.

## Verdict

1. **Raw serialized-object injection via `PHP_SESSION_UPLOAD_PROGRESS` is impossible in any single-handler stock config.** The attacker controls the session key (`upload_progress_` + POST value, `session.c:3318`), but the `php` serializer refuses any key containing `|` (`session.c:1112`) and the write degrades to a **0-byte** session file (`session.c:532–547`, verified). Attacker strings that land in the *value* (upload filename and so on) are length-prefixed by `serialize()`, so `|`, newlines and quotes inside them are inert (verified).
2. **The real primitive is a serializer mismatch** — the class documented in PHP bug #71101. Two variants reached `__destruct`: `php_serialize` → `php`, and `php` → `php_binary`.
3. **At upload-progress auto-start, decode runs pre-RINIT with no application autoloader** (`session.c:3229`), so only internal classes and `opcache.preload` classes are reachable. Since the 2026-10-21 release (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) the decode additionally runs in `incomplete_classes_only` mode (`session.c:970–985`): no class lookup at all. A/B verified: 8.2.32 fires a preloaded `__wakeup` and `unserialize_callback_func`; 8.4.27 does neither, even with the class preloaded. No core internal class has `__destruct`, and the internal `__wakeup` set has no dangerous gadget, so there is **no native/internal-only POP chain**.
4. **PHPGGC (f8aebde, 2025-09-29): 170 chains — Laravel 23, Symfony 19, WordPress 18, Drupal 11, Joomla 1, Magento 4, native/PHP-internal 0.** WordPress/RCE2 is a one-class gadget (`WP_HTML_Token::__destruct` → `call_user_func`), but WordPress core never calls `session_start()` for native files. Laravel uses its own file handler; Symfony and Joomla may call `session_start()` but only if their runtime save path matches the ini.
5. **A complete PHP-level chain exists only at deployment level.** Verified end-to-end on patched 8.4.27 with default `cleanup=1`: slow multipart upload to a `php_serialize` pool sharing `save_path` → mid-upload file `a:1:{s:52:"upload_progress_x|O:4:"Evil":…` → concurrent GET to a `php`-handler app whose autoloader is registered before `session_start()` → object injection → `Evil::__destruct` (`cmd=id`, `POP_FIRED`). Prerequisites: serializer mismatch, attacker-chosen SID accepted (`use_strict_mode=0`), a SID set through a body field (works even with `use_only_cookies=On`), the cleanup race or `cleanup=0`, and an app sink that really calls `session_start()`.

## Layout

| path | content |
|---|---|
| `REPORT.md` | full assessment: write format, decode timing, PHPGGC reachability, verified deployment chain, citations, limitations |
| `labfpm/` | two-pool race lab: `wwwA` (`php_serialize` writer), `wwwB` (default `php` reader with `Evil`), FPM/nginx configs, preload, clients, session captures, `TRANSCRIPT.md`, `POP_FIRED.txt` |
| `phpggc_full.txt` | captured `phpggc -l` inventory at `f8aebde` (170 chains) |
| `session_php-8.2.35.c`, `-8.4.26.c`, `-8.4.27.c`, `-8.5.11.c` | PHP session sources used for the line citations |
| `var_unserializer_84.re` | `var_unserializer.re` at 8.4 for the decode-state references |

The chain inventory is duplicated as a standalone `pop_inventory_1022/` receipt because the counts are cited independently of this lab work.

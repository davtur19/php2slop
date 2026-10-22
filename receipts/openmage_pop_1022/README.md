# Receipt — OpenMage session injection + stock ZF1 POP chain (NP and PIE PHP 8.5.10)

This receipt proves, on a private loopback lab, the chain:

```
PHP_SESSION_UPLOAD_PROGRESS (slow multipart upload)
  -> php_serialize writer on the shared session.save_path writes
     a:1:{s:<n>:"upload_progress_x|<serialized gadget>";a:5:{...}}
  -> stock OpenMage app (php serializer) session_start()
       splits at '|', unserializes the gadget, fails on trailing bytes
  -> php_session_cancel_decode()/php_session_destroy() destroys the session
  -> Zend_Memory_Manager::__destruct -> Zend_Cache_Backend_Apc::clean
     -> _log -> Zend_Log::log -> Zend_CodeGenerator_Php_File::write
     -> file_put_contents(<webroot>/pop_*.php, <PHP code>)
  -> HTTP GET of the written PHP -> marker (RCE)
```

The same payload bytes (no addresses, no leak, no ROP) work on both the NP and the PIE
`php-fpm` 8.5.10 binaries.

**Important caveat:** a *single* stock `php`-serializer writer cannot inject the key — the
encoder rejects `|` (`Data contains invalid key ...`). The lab therefore uses a second pool
(`writer_*`) configured with `session.serialize_handler=php_serialize` and the same
`session.save_path`; this is the cross-serializer deployment assumption, documented in
`REPORT.md` §5. The victim app pools are stock (no session overrides).

## Layout

```
conf/        fpm.np.conf, fpm.pie.conf, nginx.np.conf, nginx.pie.conf
scripts/     setup.sh, mkpay.py, upload_probe.py, get_app.py, t2_retry.sh, pie_e2e.sh, gg_controls.sh
phase/       payloads, upload logs, live-session snapshots, PHPGGC controls, var/report copies
req/         reader request headers/bodies
markers/     TestClass wakeup/destruct logs and POP markers
log/         FPM/nginx/php logs (worker PIDs, warnings, fatals)
www/         copy of the stock OpenMage tree + lab-only TestClass and pop_* artifacts
run/         sockets, pid files, nginx temp dirs
```

## Lab

| | NP | PIE |
|---|---|---|
| FPM master | 1707330 (`install_realapps_np/sbin/php-fpm`, md5 `4ee099...`) | 1707337 (`install_realapps/sbin/php-fpm`, md5 `26e4c7...`, ELF PIE) |
| nginx | 28896 | 28897 |
| app pool | `app_np` (stock, `php`) | `app_pie` (stock, `php`) |
| writer pool | `writer_np` (`php_serialize`, shared save_path) | `writer_pie` |
| control pool | `writer_stock_np` (`php`) | — |

The old shared lab (`28895`, PIDs 1663851/1682840), WP labs and the MediaWiki lab were not
touched. `www/` is a copy of `stock_20261022T013022Z/www`.

## Re-run

```bash
R=/tmp/opencode/research/openmage_pop_20261022T021222Z
$R/scripts/setup.sh                       # configs + start (idempotent-ish; ports 28896/28897)
$R/scripts/t2_retry.sh                    # injection + autoload markers
$R/scripts/pie_e2e.sh                     # PIE upload -> app -> POP
python3 $R/scripts/get_app.py 28897 pietest3 /pop_pie_e2e.php $R/req/pie_exec
```

Key facts to preserve when re-running:

* session IDs must match `[A-Za-z0-9,-]+` (underscores are rejected by PHP);
* `upload_progress.cleanup=On` (default) means the window is **mid-upload** — pause the body
  after the prefix (the probe uses `--mode slow --pause-at 262144`);
* the app's failed decode deletes the session file (that is expected);
* phpggc payloads need `truncate -s -1` (phpggc appends a newline);
* the POP payload contains NUL bytes in mangled property names; the rfc1867 key builder is
  length-based, so NULs survive.

## Verdict

See `REPORT.md` §0 and §5. Proven: injection, app autoload, stock POP chain, arbitrary PHP
file write, RCE marker, on both NP and PIE 8.5.10. Not proven/blocked: single-handler stock
writer, complete/aborted uploads under cleanup=On, PHPGGC Magento/FW1 (missing
`Varien_Cache_Backend_Eaccelerator`), PHPGGC ZendFramework/RCE1 (`/e` removed).

## Repository curation note (this copy)

The source receipt's `www/` was a **190 MB** copy of the stock OpenMage 20.10.0 tree plus
generated POP artefacts. The public copy keeps only the lab harness and the artefacts the
report cites: `www/pop_*.php`, `www/lab_upload_*.php`, `www/pop_shared.php` and
`www/lib/TestClass.php`. The vendored OpenMage tree, the generated PHP files it produced,
nginx temp directories, sockets and the rest of `run/` are environment and are not included.
The four `run/*.pid` files are kept because they identify the masters quoted in the report.

`SHA256SUMS` was regenerated for the curated set (every file here except itself), so
`sha256sum -c SHA256SUMS` passes; the source receipt's manifest covers the fuller tree. Its
only delta against this copy is this README (the note below was added during curation). No
credentials are present: the lab has no application config with secrets, and the only
"sensitive" strings are session ids and local paths.

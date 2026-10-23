#!/usr/bin/env python3
import json, datetime

OUT = "/tmp/opencode/research/gap_plan_20261023T202856Z/plan.json"

gaps = [
    # id, priority, lane, cell, disposition, task, evidence, reason
    ("G01","P0","Distro","Debian 12 8.2.32 + mod_php (other 8.2.x untested)","covered","","R/distro_gap_20261023T153629Z/report.md §4","A1/A2 500 parse-OOM, 0/13 B1 (34 B); 8.2.35 fixed"),
    ("G02","P0","Distro","Debian 12 8.2.x + FPM","covered","","R/distro_gap_20261023T153629Z/report.md §5","8.2.32 FPM A1/A2 502, 2 exit-70, no B1; 8.2.35 fixed"),
    ("G03","P1","Distro","Debian 13 8.4.24-1~deb13u1 + FPM","assigned","T04","","mod_php tested; FPM not run"),
    ("G04","P2","Distro","Ubuntu 20.04 7.4.3 + mod_php","assigned","T05","","upstream 7.4.33 only"),
    ("G05","P2","Distro","Ubuntu 20.04 7.4.3 + FPM","assigned","T05","","upstream 7.4.33 only"),
    ("G06","P0","Distro","Ubuntu 22.04 pre-update 8.1.2 + mod_php","covered","","R/distro_gap_20261023T153629Z/report.md §4","A1/A2 500, 0/13 B1; .28 fixed 200"),
    ("G07","P0","Distro","Ubuntu 22.04 8.1.2 + FPM","covered","","R/distro_gap_20261023T153629Z/report.md §5","A1/A2 502, 2 exit-70, no B1; .28 fixed"),
    ("G08","P1","Distro","Rocky 9.3 8.0.30-8.el9_8.1 FPM only","covered","","R/distro_rest_20261023T163207Z/report.md §5.5","no mod_php, B1 8M-gated, no primitive"),
    ("G09","P1","Distro","FPM B1 on Debian 11/13.7, Rocky 9.3, Amazon 2023.12, Fedora 44, Alma 9.8","blocked","","","33,128,677 B B1 exceeds stock post_max_size=8M; B1 needs 16x2 MB parts, so a sub-8M B1 does not exist; declared length is rejected before session code"),
    ("G10","P0","Distro","PHP 7.4/8.0 B1 negatives (Debian 11, Rocky 9.3)","covered","","R/distro_rest_20261023T163207Z §4.1; R/fpm_pre8_chain_20261023T091239Z","1,020-part cap truncates the 8.4 A1; prior B1 negatives are invalid; 974-part body 200/no OOM"),
    ("G11","P1","Distro","Debian 11 7.4.33 sub-1,020-part A1 tuning","blocked","","","974-part body 200/no OOM; direct 7.4 mod_php has no B1 primitive in the tested geometry; no valid 7.4 A1 constructor exists without a new groom"),
    ("G12","P2","Distro","Arch Linux rolling 8.5.12-1 / php-legacy 8.3.36-1","assigned","T12","","metadata only; no native package run"),
    ("G13","P3","Distro","Alpine edge","blocked","","","fixed metadata only (8.4.27/8.5.12/8.3.36); all shipped lines fixed, no vulnerable package"),
    ("G14","P1","Distro","Amazon 2023.12 8.4.26 A1 exact onset","covered","","R/distro_meta_20261023T171143Z/report.md §3.5","onset between 860 and 870 big-value parts; a1_p880 500/OOM"),
    ("G15","P1","Distro","Amazon 2023.12 8.4.26 B1 build-tuned read spec","assigned","T06","","0/5 stock and 0/5 single-child is the 8.4-derived geometry; no per-build filler sweep"),
    ("G16","P1","Distro","Amazon 2023.12 8.4.26 A2/B2","assigned","T06","","A2 sent on FPM only; B2 unreachable without B1"),
    ("G17","P1","Distro","Amazon 2023.12 8.4.26 109618 S2 band","covered","","R/distro_meta_20261023T171143Z/report.md §3.6","S1 at H=427343; 38 H points, 33 below S1; no S2, 0 SIGSEGV"),
    ("G18","P3","Distro","Amazon 2023.12 8.3.36 / 8.5.12 live","blocked","","","both are fixed builds; only metadata, no vulnerable package"),
    ("G19","P3","Distro","Fedora 44 php-fpm 8.5.12-1.fc44 109618 producer","blocked","","","fixed build, FPM-only, no mod_php; no vulnerable artifact"),
    ("G20","P1","Distro","B2 on any distro package","blocked","","","requires a B1 leak plus per-build offsets; no distro B1 leak exists in any measured lane"),
    ("G21","P0","Build","FPM 8.2.35 fixed control","covered","","R/distro_gap_20261023T153629Z/report.md §5","A1/A2 200, 0 exit-70, no RCE"),
    ("G22","P1","Build","FPM 8.4.27 fixed control","covered","","R/apps_gap_20261023T163831Z/report.md","A1/A2/B1/B2 200, no OOM, no exit-70"),
    ("G23","P1","Build","mod_php 8.4.9","assigned","T01","","only patch between the measured 8.4.1-8.4.8 block and 8.4.10 RCE"),
    ("G24","P2","Build","mod_php 8.4.0","assigned","T02","","no measurement before 8.4.1"),
    ("G25","P2","Build","mod_php 8.1.34","covered","","R/php81_83_modphp_20261023T191948Z (active worker)","active worker; do not duplicate"),
    ("G26","P3","Build","5.6.0 / 7.0.0 / 7.1.0 runtime","blocked","","","official schema1 images unavailable; README row is tips-only"),
    ("G27","P2","SAPI/OS","nginx+mod_php 8.4.10","covered","","R/modphp_warm_20261023T131308Z (4/4); R/nginx_modphp_20261023T132940Z","warm chain + proxy invariance; exact combined cell not re-run"),
    ("G28","P2","SAPI/OS","nginx+mod_php 8.4.20","covered","","R/modphp_warm_20261023T131308Z (17/17); R/nginx_modphp_20261023T132940Z","warm chain + proxy invariance"),
    ("G29","P2","SAPI/OS","nginx+mod_php 8.5.11","blocked","","","direct 8.5.11 mod_php is leak-only (53 pointers, no zval_ptr_dtor, no 87-bucket); nginx adds only the transport gate"),
    ("G30","P3","SAPI/OS","direct FastCGI full chain 8.4.26 / 8.5.11","covered","","R/fastcgi_smuggle_20261023T131351Z/report.md","config-injection full chain on both; the A1/B1 body path is post_max_size-gated"),
    ("G31","P2","SAPI/OS","FreeBSD 13/14 + Apache + mod_php (ports)","blocked","","","no FreeBSD host or VM available"),
    ("G32","P2","SAPI/OS","FreeBSD 13/14 + nginx + FPM (ports)","blocked","","","no FreeBSD host or VM available"),
    ("G33","P2","SAPI/OS","Windows Server + IIS 10 + FastCGI (8.3/8.4/8.5 NTS)","blocked","","","no Windows host; no FPM on Windows"),
    ("G34","P3","SAPI/OS","Windows + Apache + mod_php","blocked","","","no Windows host"),
    ("G35","P1","App","WordPress 7.1.3 installed with mysqli/DB","covered","","R/apps_modphp_20261023T164153Z/report.md §1","WP dev/prod installed on MariaDB; front controller A1 SIGABRT, no chain; /wp-content/index.php is the engine-level success"),
    ("G36","P1","App","WordPress 7.1.3 nginx+FPM full chain","covered","","R/oom109618_wp_20261022T101958Z; R/apps_gap_20261023T163831Z","stock nginx 1 MiB and FPM post_max_size=8M gate B1; A1 is OOM/exit-70 only, no state; app layer adds no primitive"),
    ("G37","P2","App","WordPress 7.1.3 mod_php 8.3.35 / 8.5.11","assigned","T13","","only 8.4.24/8.4.26 tested"),
    ("G38","P1","App","Drupal 11.4.11 stock DB sessions","covered","","R/apps_gap_20261023T163831Z; R/apps_modphp_20261023T164153Z","64M A1 exit-70, B1 no leak"),
    ("G39","P1","App","Joomla 5.4.10 stock DB sessions","assigned","T09","","lab file-session only"),
    ("G40","P2","App","Joomla 6.2.0","covered","","R/apps_frameworks_20261023T154615Z/report.md","FPM 8.4.26 OOM/502, no RCE"),
    ("G41","P2","App","MediaWiki 1.46.2 mod_php / other FPM","assigned","T10","","FPM OOM only; mod_php untested"),
    ("G42","P1","App","Laravel 13","covered","","R/apps_modphp_20261023T164153Z; R/apps_frameworks_20261023T154615Z","mod_php static /assets/index.php RCE + front-controller no; FPM negative"),
    ("G43","P1","App","Symfony 8.1","covered","","R/apps_modphp_20261023T164153Z; R/apps_frameworks_20261023T154615Z","mod_php static RCE, front-controller/FPM negative"),
    ("G44","P0","App","Roundcube 1.7.4","assigned","T08","","1.7.5 tested; 1.7.4 not run"),
    ("G45","P1","App","Nextcloud 35","covered","","R/apps_roundcube_nextcloud_20261023T153529Z/report.md","35.0.2 512M no OOM, 128M exit-70, no leak"),
    ("G46","P2","App","phpMyAdmin 5.2.3","assigned","T11","","none under mod_php"),
    ("G47","P3","App","Magento 2.4.9","blocked","","","optional; heavy stack, no engine discriminator, no artifact path"),
    ("G48","P3","App","OpenCart 4.x","blocked","","","optional; version unverified"),
    ("G49","P3","App","Laravel 12 / Symfony 7.x/6.4 / Nextcloud 34/33","blocked","","","secondary versions; same PHP engines, no new engine delta"),
    ("G50","P1","SAPI/OS","OpenLiteSpeed 1.9.3 + lsphp 8.5.11 (LSAPI)","assigned","T03","","only 8.4.26/8.4.27 measured; 8.5.11 binary absent"),
    ("G51","P1","App","WordPress 7.1.3 + upstream php:8.4.26-apache stock multi-worker","covered","","R/php8426_multiw_20261023T191822Z/report.md","3 blind + 1 extra target-written proof"),
]

gap_objs = []
for gid, pri, lane, cell, disp, task, ev, reason in gaps:
    gap_objs.append({
        "id": gid, "priority": pri, "lane": lane, "cell": cell,
        "disposition": disp, "task": task or None,
        "evidence": ev or None, "reason": reason or None,
    })

unnumbered = [
    {"id":"U01","row":"Roundcube 1.7.5 + 8.4.27 FPM (Applications table —)","disposition":"assigned","task":"T08","reason":"README says not rebuilt on 8.4.27; T08 supplies the control"},
    {"id":"U02","row":"lighttpd 1.4.79 + FPM 8.4.26 chain","disposition":"assigned","task":"T07","reason":"R/alt_sapi measured body limits only; no A1→B2 chain"},
    {"id":"U03","row":"Apache 2.4 + mod_proxy_fcgi + Debian 13 8.4.24 FPM","disposition":"assigned","task":"T04","reason":"G03 only says FPM not run; Apache+FPM is a separate transport shape"},
    {"id":"U04","row":"OpenResty 1.31.1.1 + FPM 8.4.26 with raised client_max_body_size","disposition":"covered","task":None,"reason":"stock 1 MiB returns 413 at 1,048,577 B; with override byte-equivalent to nginx+FPM, covered by apps_gap/nginx_modphp"},
]

def c(name, image, port, role):
    return {"name": name, "image": image, "port": port, "role": role}

tasks = [
    {
        "id":"T01","gap_ids":["G23"],"priority":"P1","batch":1,
        "title":"PHP 8.4.9 mod_php source build",
        "image":"php:8.4.8-apache@sha256:432ae092a1aafd4b8c7817070edfc47b620a6ceac8ac1829cf6d2c699e3c988f",
        "images":["php:8.4.8-apache@sha256:432ae092a1aafd4b8c7817070edfc47b620a6ceac8ac1829cf6d2c699e3c988f"],
        "packages":["php-8.4.9.tar.gz sha256:1068de4448d77cd44cc15b96984f1f9accf4dbc883b793aea6d02846ef8b1ba1","apache2-dev","libxml2-dev","libsqlite3-dev","libssl-dev","libcurl4-openssl-dev","libonig-dev","libpng-dev","libjpeg62-turbo-dev","libfreetype6-dev","libzip-dev","libargon2-dev","libsodium-dev","libreadline-dev"],
        "build":"exact php:8.4.8-apache Configure Command; make -j; make install; php.ini-production; apache2ctl -k graceful",
        "endpoint":"22-byte /index.php sha256:1b97dc5177b5c4f4a53023a6c72629ce360e466f627d98cdf1d75113450faf23",
        "expected_chain":"8.4.9 is the only untested patch between 8.4.8 (blocked) and 8.4.10 (RCE). Either it stays blocked (A1 parse-OOM no stale PS(id) or clean 200; B1 normal 34/40-B; no A2/B2) or END-cleanup send_cookie OOM appears and B1 > 4096 B becomes possible. Decide empirically; if leak, derive per-build S/zif_system/zval_ptr_dtor and attempt A2/B2.",
        "artifacts":["report.md","bodies/","conf/","evidence/","logs/","out/","proof/ (only if RCE)","scripts/"],
        "acceptance":"php -v reports exactly PHP 8.4.9 and the run ends with either no decoded B1 > 4096 B and no proof, or a per-build leak + target-written proof.",
        "ports":[33100,33101],"network":"p2s-gap1","container_prefix":"p2sg1-",
        "containers":[
            c("p2sg1-php849","php:8.4.8-apache@sha256:432ae092a1aafd4b8c7817070edfc47b620a6ceac8ac1829cf6d2c699e3c988f + PHP 8.4.9 build",33100,"PHP 8.4.9 mod_php"),
            c("p2sg1-php848","php:8.4.8-apache@sha256:432ae092a1aafd4b8c7817070edfc47b620a6ceac8ac1829cf6d2c699e3c988f",33101,"PHP 8.4.8 control")
        ]
    },
    {
        "id":"T02","gap_ids":["G24"],"priority":"P2","batch":3,
        "title":"PHP 8.4.0 mod_php source build",
        "image":"php:8.4.8-apache@sha256:432ae092a1aafd4b8c7817070edfc47b620a6ceac8ac1829cf6d2c699e3c988f",
        "images":["php:8.4.8-apache@sha256:432ae092a1aafd4b8c7817070edfc47b620a6ceac8ac1829cf6d2c699e3c988f"],
        "packages":["php-8.4.0.tar.gz sha256:9597b2054c4698bbfde637389ca1dcba570d5df28d26e3b5674b409c4f857b23","apache2-dev","libxml2-dev","libsqlite3-dev","libssl-dev","libcurl4-openssl-dev","libonig-dev","libpng-dev","libjpeg62-turbo-dev","libfreetype6-dev","libzip-dev","libargon2-dev","libsodium-dev","libreadline-dev"],
        "build":"identical recipe/configure line as T01 with php-8.4.0.tar.gz",
        "endpoint":"22-byte /index.php sha256:1b97dc5177b5c4f4a53023a6c72629ce360e466f627d98cdf1d75113450faf23",
        "expected_chain":"pre-8.4.1: A1 likely 200 (no OOM) or parse abort; no END-cleanup send_cookie OOM; B1 normal cookie; no A2/B2.",
        "artifacts":["report.md","bodies/","conf/","evidence/","logs/","out/","proof/ (only if RCE)","scripts/"],
        "acceptance":"php -v reports PHP 8.4.0, A1 is 200-or-parse-abort and B1 decodes to <= 4096 B with no proof; any leak triggers per-build offsets.",
        "ports":[33140,33141],"network":"p2s-gap3","container_prefix":"p2sg3-",
        "containers":[
            c("p2sg3-php840","php:8.4.8-apache@sha256:432ae092a1aafd4b8c7817070edfc47b620a6ceac8ac1829cf6d2c699e3c988f + PHP 8.4.0 build",33140,"PHP 8.4.0 mod_php"),
            c("p2sg3-php841","php:8.4.1-apache (optional control)",33141,"optional 8.4.1 control")
        ]
    },
    {
        "id":"T03","gap_ids":["G50"],"priority":"P1","batch":2,
        "title":"OpenLiteSpeed 1.9.3 + lsphp 8.5.11 (LSAPI)",
        "image":"debian:13-slim",
        "images":["debian:13-slim","openlitespeed 1.9.3-1+trixie","PHP 8.5.11 source build"],
        "packages":["openlitespeed 1.9.3-1+trixie","build-essential","libxml2-dev","libsqlite3-dev","libssl-dev","libcurl4-openssl-dev","libonig-dev","libzip-dev","pkg-config"],
        "build":"./configure --disable-all --enable-litespeed --enable-session --without-pear --disable-cgi --with-config-file-path=/usr/local/lsws/lsphp8511/etc/php/8.5/litespeed --prefix=/usr/local/lsws/lsphp8511; make -j; make install",
        "endpoint":"22-byte /index.php + /health.php (sapi=litespeed php=8.5.11)",
        "expected_chain":"LSAPI skips php_request_shutdown on startup failure: A1/109618 OOM -> HTTP 500, wait4 WIFEXITED 255, no SIGSEGV/SIGABRT/SIGBUS; OLS respawns, health 200; B1 no leak; no RCE.",
        "artifacts":["report.md","bodies/","conf/","evidence/","logs/","out/","proof/ (only if RCE)","scripts/"],
        "acceptance":"lsphp -i reports PHP 8.5.11 and Server API => LiteSpeed V8.3; OOM is HTTP 500 + exit 255 with zero signal deaths, no >4096-B B1 and no proof.",
        "ports":[33120],"network":"p2s-gap2","container_prefix":"p2sg2-",
        "containers":[c("p2sg2-ols8511","debian:13-slim + OLS 1.9.3 + lsphp 8.5.11",33120,"OLS/LSAPI")]
    },
    {
        "id":"T04","gap_ids":["G03","U03"],"priority":"P1","batch":1,
        "title":"Debian 13 8.4.24 FPM: nginx stock/raised + Apache mod_proxy_fcgi",
        "image":"debian:13-slim",
        "images":["debian:13-slim","nginx 1.26.3-3+deb13u10","apache2 2.4.69-1~deb13u1","php8.4 8.4.24-1~deb13u1"],
        "packages":["php8.4-fpm_8.4.24-1~deb13u1_amd64.deb","php8.4-common_8.4.24-1~deb13u1_amd64.deb","php8.4-cli_8.4.24-1~deb13u1_amd64.deb","php8.4-opcache_8.4.24-1~deb13u1_amd64.deb","php8.4-fpm_8.4.27-1~deb13u1_amd64.deb (control)","nginx 1.26.3-3+deb13u10","apache2 2.4.69-1~deb13u1"],
        "build":"dpkg -i exact .debs + apt-mark hold; stock www.conf; nginx stock 1m and 64m arms; Apache a2enmod proxy_fcgi + SetHandler proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost",
        "endpoint":"22-byte /index.php sha256:1b97dc5177b5c4f4a53023a6c72629ce360e466f627d98cdf1d75113450faf23",
        "expected_chain":"stock nginx: A1 1,060,211 and B1 33,128,677 -> 413 before PHP. Raised nginx: A1 reaches FPM, OOM 4096, exit 70/502. Apache FCGI: A1 reaches FPM, exit 70; B1 declared refused by post_max_size=8M (200/warning); no B1 leak, no A2/B2. 8.4.27: A1/A2 200, no exit 70.",
        "artifacts":["report.md","bodies/","conf/","evidence/","logs/","out/","proof/ (only if RCE)","scripts/"],
        "acceptance":"exact 8.4.24 is installed on at least one arm, A1 reaches FPM and yields exit 70/502, no B1 > 4096 B on any arm, and 8.4.27 control A1/A2 200 with zero exit 70.",
        "ports":[33102,33103,33104,33105],"network":"p2s-gap1","container_prefix":"p2sg1-",
        "containers":[
            c("p2sg1-deb13-ngx-stock","debian:13-slim + php8.4-fpm 8.4.24 + nginx 1.26.3",33102,"stock 1 MiB nginx"),
            c("p2sg1-deb13-ngx-64m","debian:13-slim + php8.4-fpm 8.4.24 + nginx 1.26.3",33103,"64 MiB nginx"),
            c("p2sg1-deb13-apache-fcgi","debian:13-slim + apache2 2.4.69 + php8.4-fpm 8.4.24",33104,"Apache mod_proxy_fcgi"),
            c("p2sg1-deb13-ngx-8427","debian:13-slim + php8.4-fpm 8.4.27 + nginx 1.26.3",33105,"8.4.27 control")
        ]
    },
    {
        "id":"T05","gap_ids":["G04","G05"],"priority":"P2","batch":2,
        "title":"Ubuntu 20.04 7.4.3 mod_php + FPM",
        "image":"ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214",
        "images":["ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214"],
        "packages":["libapache2-mod-php7.4_7.4.3-4ubuntu2.29_amd64.deb","php7.4-fpm_7.4.3-4ubuntu2.29_amd64.deb","php7.4-cli_7.4.3-4ubuntu2.29_amd64.deb","php7.4-opcache_7.4.3-4ubuntu2.29_amd64.deb","nginx 1.18.0"],
        "build":"apt install exact versions; Apache prefork + php7.4_module; nginx stock 1 MiB and 64 MiB arms; stock www.conf",
        "endpoint":"22-byte /index.php sha256:1b97dc5177b5c4f4a53023a6c72629ce360e466f627d98cdf1d75113450faf23",
        "expected_chain":"mod_php: A1 200/parse-OOM, B1 0/5 34-B cookie, A2 200; FPM: A1 OOM/exit 70, B1 33 MB declared refused by post_max_size=8M; 7.4 effective 1,020-part cap; no RCE/OOB leak.",
        "artifacts":["report.md","bodies/","conf/","evidence/","logs/","out/","proof/ (only if RCE)","scripts/"],
        "acceptance":"both SAPIs report PHP 7.4.3-4ubuntu2.29, the 974-part A1/S1 result is recorded with the 1,020-part cap, B1 <= 4096 B or transport-gated, and no proof exists.",
        "ports":[33121,33122],"network":"p2s-gap2","container_prefix":"p2sg2-",
        "containers":[
            c("p2sg2-u2004-modphp","ubuntu:20.04 + libapache2-mod-php7.4 7.4.3-4ubuntu2.29",33121,"7.4.3 mod_php"),
            c("p2sg2-u2004-fpm","ubuntu:20.04 + php7.4-fpm 7.4.3-4ubuntu2.29 + nginx 1.18.0",33122,"7.4.3 FPM")
        ]
    },
    {
        "id":"T06","gap_ids":["G15","G16"],"priority":"P1","batch":1,
        "title":"Amazon Linux 2023.12 8.4.26 B1 build tuning + A2/B2",
        "image":"amazonlinux:2023.12.20261021.0",
        "images":["amazonlinux:2023.12.20261021.0"],
        "packages":["php8.4-modphp-8.4.26-1.amzn2023.0.1","php8.4-fpm-8.4.26-1.amzn2023.0.1","php8.4-common-8.4.26-1.amzn2023.0.1","httpd","php8.4-modphp-8.4.27-1.amzn2023.0.1 (control)"],
        "build":"dnf install exact NEVRA set; switch 00-mpm.conf to prefork for mod_php (declared fixture); stock php.ini; FPM arm stock www.conf",
        "endpoint":"22-byte /index.php sha256:1b97dc5177b5c4f4a53023a6c72629ce360e466f627d98cdf1d75113450faf23",
        "expected_chain":"B1 sweep fillers 100-140, parts 900-1000, stock 5-child and single-child: 0/N leak (normal 34-B cookie); A2 279,432 mod_php OOM 20,480; no B2/RCE; 8.4.27 a1_p880 200.",
        "artifacts":["report.md","bodies/","conf/","evidence/","logs/","out/","proof/ (only if RCE)","scripts/"],
        "acceptance":"every decoded B1 <= 4096 B across the full filler/part sweep and both pool shapes, A2 OOM recorded on mod_php, no proof; if a leak appears, B2 attempted with locally derived offsets.",
        "ports":[33106,33107,33108],"network":"p2s-gap1","container_prefix":"p2sg1-",
        "containers":[
            c("p2sg1-amzn-modphp","amazonlinux:2023.12 + php8.4-modphp 8.4.26",33106,"Amazon mod_php"),
            c("p2sg1-amzn-fpm","amazonlinux:2023.12 + php8.4-fpm 8.4.26",33107,"Amazon FPM"),
            c("p2sg1-amzn-8427","amazonlinux:2023.12 + php8.4-modphp 8.4.27",33108,"8.4.27 control")
        ]
    },
    {
        "id":"T07","gap_ids":["U02"],"priority":"P2","batch":4,
        "title":"lighttpd 1.4.79 + FPM 8.4.26 chain",
        "image":"debian:13-slim",
        "images":["debian:13-slim","php:8.4.26-fpm@sha256:f5431b57bda75455d5271967cc6b67df8f0d0b943832756e0c78eccdc98767dd","php:8.4.27-fpm@sha256:e2d8e787dc775bdbd9d7e0c5e8f2f9ddb41ce5977c8bbaf99a2ba2e7d90fd8ae"],
        "packages":["lighttpd 1.4.79-2","php:8.4.26-fpm","php:8.4.27-fpm (control)"],
        "build":"lighttpd fastcgi.server -> php8426-fpm:9000; stock post_max_size=8M arm and 64M documented delta arm",
        "endpoint":"22-byte /index.php sha256:1b97dc5177b5c4f4a53023a6c72629ce360e466f627d98cdf1d75113450faf23",
        "expected_chain":"stock: A1 reaches PHP, OOM/exit 70 -> 502; B1 33,128,677 forwarded with declared length, refused by post_max_size before session; no leak. 64M: B1 reaches session, record leak status, no RCE. 8.4.27: A1 200, no exit 70.",
        "artifacts":["report.md","bodies/","conf/","evidence/","logs/","out/","proof/ (only if RCE)","scripts/"],
        "acceptance":"lighttpd 1.4.79-2 is the front end, stock A1 produces one exit 70, stock B1 is post_max_size-gated (no >4096-B cookie), raised-INI leak status recorded, no proof.",
        "ports":[33165,33166],"network":"p2s-gap4","container_prefix":"p2sg4-",
        "containers":[
            c("p2sg4-lighttpd","debian:13-slim + lighttpd 1.4.79-2",33165,"lighttpd"),
            c("p2sg4-php8426-fpm","php:8.4.26-fpm@sha256:f5431b57bda75455d5271967cc6b67df8f0d0b943832756e0c78eccdc98767dd",33166,"FPM 8.4.26"),
            c("p2sg4-php8427-fpm","php:8.4.27-fpm@sha256:e2d8e787dc775bdbd9d7e0c5e8f2f9ddb41ce5977c8bbaf99a2ba2e7d90fd8ae",None,"FPM 8.4.27 control")
        ]
    },
    {
        "id":"T08","gap_ids":["G44","U01"],"priority":"P0","batch":1,
        "title":"Roundcube 1.7.4 mod_php/FPM + 1.7.5/8.4.27 control",
        "image":"php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a",
        "images":["php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a","php:8.4.26-fpm@sha256:f5431b57bda75455d5271967cc6b67df8f0d0b943832756e0c78eccdc98767dd","php:8.4.27-fpm@sha256:e2d8e787dc775bdbd9d7e0c5e8f2f9ddb41ce5977c8bbaf99a2ba2e7d90fd8ae","nginx:alpine","mariadb:11.4"],
        "packages":["docker-php-ext-install intl","pdo_sqlite (built-in)","roundcubemail-1.7.4-complete.tar.gz sha256:2c6c878f0093f1bf7fb6086781d2dd9269d652c016b86939c157c5f1729139a2","roundcubemail-1.7.5-complete.tar.gz sha256:93a66c94e3efff7db93187c1c9d7f35546647a3e1e7b9327cc87911564edf9d1"],
        "build":"unpack + config.inc.php; SQLite db_dsnw; Arm A stock session_storage=db + PHPSESSID; Arm B session_storage=php + file sessions; control 1.7.5 + 8.4.27 FPM",
        "endpoint":"/, /?_task=login, /static.php",
        "expected_chain":"A1 OOM/SIGABRT (mod_php) or exit 70 (FPM); B1 normal 5,400-B page, no pointer leak; A2/B2 normal; no auth bypass. 1.7.5/8.4.27 control: A1/A2/B1/B2 200, no OOM/exit 70.",
        "artifacts":["report.md","bodies/","conf/","evidence/","logs/","out/","proof/ (only if RCE)","scripts/"],
        "acceptance":"RCMAIL_VERSION reports 1.7.4 in both arms, valid login works before/after, no decoded B1 > 4096 B, and 1.7.5/8.4.27 control returns 200 for all four stages.",
        "ports":[33109,33110,33111],"network":"p2s-gap1","container_prefix":"p2sg1-",
        "containers":[
            c("p2sg1-rc174-modphp","php:8.4.26-apache + Roundcube 1.7.4",33109,"1.7.4 mod_php"),
            c("p2sg1-rc174-fpm","php:8.4.26-fpm + nginx:alpine + Roundcube 1.7.4",33110,"1.7.4 FPM"),
            c("p2sg1-rc175-fpm","php:8.4.27-fpm + nginx:alpine + Roundcube 1.7.5",33111,"1.7.5/8.4.27 control"),
            c("p2sg1-db","mariadb:11.4",None,"DB")
        ]
    },
    {
        "id":"T09","gap_ids":["G39"],"priority":"P1","batch":2,
        "title":"Joomla 5.4.10 stock DB sessions + mod_php 8.4.26",
        "image":"php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a",
        "images":["php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a","mariadb:11.4"],
        "packages":["docker-php-ext-install intl gd mysqli","Joomla_5-4-10-Stable-Full_Package.tar.gz sha256:aa72c425105cf775312f9610598b9f1c8866c7f3219a729b59d29a56ff7f76c4","mysqli"],
        "build":"CLI install; $session_handler='database'; stock configuration.php otherwise",
        "endpoint":"/index.php, /administrator/index.php",
        "expected_chain":"A1 1,060,211 -> child SIGABRT/500 (pre-app); B1 normal cookie/no leak; A2 OOM; no B2/RCE; #__session table present and populated by a login.",
        "artifacts":["report.md","bodies/","conf/","evidence/","logs/","out/","proof/ (only if RCE)","scripts/"],
        "acceptance":"/administrator/index.php shows Joomla 5.4.10, #__session exists, a login writes a DB session row, and A1->B2 yields no >4096-B B1 and no proof.",
        "ports":[33123,33124],"network":"p2s-gap2","container_prefix":"p2sg2-",
        "containers":[
            c("p2sg2-joomla","php:8.4.26-apache + Joomla 5.4.10",33123,"Joomla mod_php"),
            c("p2sg2-joomla-db","mariadb:11.4",None,"DB")
        ]
    },
    {
        "id":"T10","gap_ids":["G41"],"priority":"P2","batch":3,
        "title":"MediaWiki 1.46.2 + mod_php 8.4.26",
        "image":"php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a",
        "images":["php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a","mariadb:11.4"],
        "packages":["docker-php-ext-install intl mysqli","mediawiki-1.46.2.tar.gz sha256:8f7f937f8bbc1acd4cef1c5362a95f248dcd242020f2588798eb2f73ac2e69ba","mysqli"],
        "build":"maintenance/run.php install --dbtype=mysql; stock LocalSettings.php",
        "endpoint":"/index.php/Main_Page, /api.php",
        "expected_chain":"A1 OOM/500 (mod_php child abort), B1 no leak, A2 200/500; no RCE.",
        "artifacts":["report.md","bodies/","conf/","evidence/","logs/","out/","proof/ (only if RCE)","scripts/"],
        "acceptance":"Special:Version reports MediaWiki 1.46.2, main page 200, A1->B2 has no >4096-B B1 and no proof.",
        "ports":[33142,33143],"network":"p2s-gap3","container_prefix":"p2sg3-",
        "containers":[
            c("p2sg3-mw","php:8.4.26-apache + MediaWiki 1.46.2",33142,"MediaWiki mod_php"),
            c("p2sg3-mw-db","mariadb:11.4",None,"DB")
        ]
    },
    {
        "id":"T11","gap_ids":["G46"],"priority":"P2","batch":3,
        "title":"phpMyAdmin 5.2.3 + mod_php 8.4.26",
        "image":"php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a",
        "images":["php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a","mariadb:11.4","php:8.4.27-apache@sha256:a0b75cee7023ba2c127138dcad2ecc6ec7e09435534645e70450f29f24ea2a5a"],
        "packages":["docker-php-ext-install intl mysqli zip","phpMyAdmin-5.2.3-all-languages.tar.gz sha256:12ba1c425fa4071abbd4e7668c9ebdeac0b0755a467a6d6d5026122bb47c102b","mysqli"],
        "build":"config.inc.php cookie auth + 32-B blowfish_secret + host p2sg3-pma-db; /setup/ left disabled",
        "endpoint":"/index.php",
        "expected_chain":"A1 OOM/child abort, B1 no leak, A2 200; no auth bypass; no RCE.",
        "artifacts":["report.md","bodies/","conf/","evidence/","logs/","out/","proof/ (only if RCE)","scripts/"],
        "acceptance":"login page reports phpMyAdmin 5.2.3, a correct login reaches the DB, A1->B2 yields no >4096-B B1 and no proof.",
        "ports":[33144,33145,33146],"network":"p2s-gap3","container_prefix":"p2sg3-",
        "containers":[
            c("p2sg3-pma","php:8.4.26-apache + phpMyAdmin 5.2.3",33144,"phpMyAdmin mod_php"),
            c("p2sg3-pma-db","mariadb:11.4",None,"DB"),
            c("p2sg3-php8427","php:8.4.27-apache",33146,"optional control")
        ]
    },
    {
        "id":"T12","gap_ids":["G12"],"priority":"P2","batch":4,
        "title":"Arch native php-apache 8.5.12 / php-legacy 8.3.36",
        "image":"archlinux:latest",
        "images":["archlinux:latest"],
        "packages":["apache","php-apache 8.5.12-1","php-legacy-apache 8.3.36-1"],
        "build":"pacman -Syu --noconfirm apache php-apache=8.5.12-1 (container A) and apache php-legacy-apache=8.3.36-1 (container B); if repo moved, record new pkgver and mark metadata-only; load each libphp.so separately",
        "endpoint":"22-byte /index.php sha256:1b97dc5177b5c4f4a53023a6c72629ce360e466f627d98cdf1d75113450faf23",
        "expected_chain":"both packages are fixed: A1/A2 200, normal cookie, B1 <= 4096 B, no OOM/exit 70, no RCE.",
        "artifacts":["report.md","bodies/","conf/","evidence/","logs/","out/","proof/ (only if RCE)","scripts/"],
        "acceptance":"php -v reports 8.5.12 (php-apache) and 8.3.36 (php-legacy-apache), A1 200 no OOM, B1 no >4096-B cookie.",
        "ports":[33160,33161],"network":"p2s-gap4","container_prefix":"p2sg4-",
        "containers":[
            c("p2sg4-arch8512","archlinux:latest + apache + php-apache 8.5.12",33160,"Arch 8.5.12"),
            c("p2sg4-arch8336","archlinux:latest + apache + php-legacy-apache 8.3.36",33161,"Arch 8.3.36")
        ]
    },
    {
        "id":"T13","gap_ids":["G37"],"priority":"P2","batch":4,
        "title":"WordPress 7.1.3 + mod_php 8.3.35 / 8.5.11",
        "image":"php:8.3.35-apache@sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184",
        "images":["php:8.3.35-apache@sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184","php:8.5.11-apache@sha256:47e6d8849049375e0d19e81f1b391ed88828d4653e0d1b00822185b66b564e8b","mariadb:11.4"],
        "packages":["docker-php-ext-install intl gd mysqli","wordpress-7.1.3.zip sha256:eb58a90ed55147f90f7bd55d0d3334960a69b7e8a4cc142c8ddfea8965218227","mysqli"],
        "build":"docker-php-ext-install mysqli; wp-config.php against p2sg4-db; official docroot",
        "endpoint":"/index.php, /wp-content/index.php",
        "expected_chain":"8.3.35: A1 parse-OOM (0/8 family), B1 normal 34-B cookie, no leak. 8.5.11: A1 500/OOM, B1 leak-only (53 pointers, no zval_ptr_dtor, no 87-bucket), no B2/RCE.",
        "artifacts":["report.md","bodies/","conf/","evidence/","logs/","out/","proof/ (only if RCE)","scripts/"],
        "acceptance":"both sites report WordPress 7.1.3 with an installed DB, /index.php 200, neither build yields a proof; 8.5.11 B1 leak recorded but not counted as RCE.",
        "ports":[33162,33163,33164],"network":"p2s-gap4","container_prefix":"p2sg4-",
        "containers":[
            c("p2sg4-wp8335","php:8.3.35-apache + WordPress 7.1.3",33162,"WP 8.3.35"),
            c("p2sg4-wp8511","php:8.5.11-apache + WordPress 7.1.3",33163,"WP 8.5.11"),
            c("p2sg4-db","mariadb:11.4",None,"DB")
        ]
    },
]

batches = [
    {"id":1,"network":"p2s-gap1","subnet":"10.240.1.0/24","ports":"33100-33119","prefix":"p2sg1-","tasks":["T08","T01","T04","T06"]},
    {"id":2,"network":"p2s-gap2","subnet":"10.240.2.0/24","ports":"33120-33139","prefix":"p2sg2-","tasks":["T03","T09","T05"]},
    {"id":3,"network":"p2s-gap3","subnet":"10.240.3.0/24","ports":"33140-33159","prefix":"p2sg3-","tasks":["T02","T10","T11"]},
    {"id":4,"network":"p2s-gap4","subnet":"10.240.4.0/24","ports":"33160-33179","prefix":"p2sg4-","tasks":["T12","T13","T07"]},
]

# integrity checks
ids = [g["id"] for g in gap_objs]
assert len(ids) == 51, len(ids)
assert ids == [f"G{i:02d}" for i in range(1, 52)], ids
counts = {}
for g in gap_objs:
    counts[g["disposition"]] = counts.get(g["disposition"], 0) + 1
assert counts == {"covered": 22, "assigned": 14, "blocked": 15}, counts
assigned_tasks = sorted({g["task"] for g in gap_objs if g["disposition"] == "assigned"} | {"T07"})
assert assigned_tasks == [f"T{i:02d}" for i in range(1, 14)], assigned_tasks
for t in tasks:
    assert t["gap_ids"], t["id"]
    assert t["ports"] and t["network"] and t["container_prefix"]
    for ctr in t["containers"]:
        if ctr["port"] is not None:
            assert ctr["port"] in t["ports"], (t["id"], ctr)
all_ports = [p for t in tasks for p in t["ports"]]
assert len(all_ports) == len(set(all_ports)), "port collision"
all_names = [ctr["name"] for t in tasks for ctr in t["containers"]]
assert len(all_names) == len(set(all_names)), "container collision"

doc = {
    "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "plan_id": "gap_plan_20261023T202856Z",
    "repository": {
        "root": "/home/davide/ailocal/php2slop",
        "readme_commit": "6bf1d184c99a2567e58c1c72f38e63e4a3dfbe36",
        "readme_short": "6bf1d18",
        "readme_sha256": "8ee5188060455b745063d979b953bfd5532bbd17692c76debc8e05433194bfe1",
    },
    "research_root": "/tmp/opencode/research",
    "constraints": {
        "environment": "Debian 13 rootless Docker",
        "docker_host": "unix:///run/user/1000/docker.sock",
        "no_sudo": True,
        "no_windows": True,
        "no_freebsd": True,
        "no_app_lfi": True,
        "local_traffic_only": True,
        "port_range": "33100-33179",
        "excluded_active_workers": [
            "php81_83_modphp_20261023T191948Z",
            "php81_83_leak_20261023T174709Z",
            "wp_stock_multi_20261023T175947Z",
            "local_run_8424_20261023T160013Z",
        ],
    },
    "body_hashes": {
        "endpoint_22B": "1b97dc5177b5c4f4a53023a6c72629ce360e466f627d98cdf1d75113450faf23",
        "A1": {"bytes": 1060211, "sha256": "8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6"},
        "B1": {"bytes": 33128677, "sha256": "b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2"},
        "A2_upstream": {"bytes": 279369, "sha256": "7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236"},
        "A2_debian": {"bytes": 279432, "sha256": "7d3e674eed2cad578362a9177c93d67d37b02781a32878be7ea599a3c13ad3c6"},
        "B2": {"bytes": 451384, "sha256": "address-dependent"},
    },
    "disposition_summary": counts,
    "gaps": gap_objs,
    "unnumbered_rows": unnumbered,
    "tasks": tasks,
    "batches": batches,
}

with open(OUT, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print("wrote", OUT, "gaps", len(gap_objs), "tasks", len(tasks), "counts", counts)

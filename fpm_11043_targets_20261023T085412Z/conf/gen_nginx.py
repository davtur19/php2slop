#!/usr/bin/env python3
"""Generate the lab nginx vhosts from the real packaged/app config texts.

Every server block below is a verbatim copy of the cited upstream config with
only these deviations (all plumbing, none security-relevant):
  * listen <lab port>            (lab isolation)
  * fastcgi_pass <upstream>      (container DNS name instead of 127.0.0.1:9000)
  * root <lab docroot>           (where the stock app was unpacked)
"""
import os

OUT = "/tmp/opencode/research/fpm_11043_targets_20261023T085412Z/conf/nginx/t11043.conf"

VERS = [
    ("739",  "7.3.9",  "t11043-fpm739",  0),
    ("7310", "7.3.10", "t11043-fpm7310", 1),
    ("7311", "7.3.11", "t11043-fpm7311", 2),
    ("7223", "7.2.23", "t11043-fpm7223", 3),
    ("7224", "7.2.24", "t11043-fpm7224", 4),
    ("8426", "8.4.26", "t11043-fpm8426", 5),
]

def port(i, slot):
    return 8000 + i * 10 + slot

def upstream(u):
    return f"upstream {u} {{ server {u}:9000; }}\n"

def stock_snippet(u, listen, root):
    return f"""
# ---- packaged Debian 10 default site, PHP location uncommented verbatim ----
# source: /etc/nginx/sites-available/default (nginx-common 1.14.2-2+deb10u4)
server {{
    listen {listen};
    root {root};
    index index.html index.htm index.nginx-debian.html;
    server_name _;
    location / {{
        try_files $uri $uri/ =404;
    }}
    location ~ \\.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass {u};
    }}
}}
"""

def stock_no_php(listen, root):
    return f"""
# ---- packaged Debian 10 default site, PHP block left commented out ----
server {{
    listen {listen};
    root {root};
    index index.html index.htm index.nginx-debian.html;
    server_name _;
    location / {{
        try_files $uri $uri/ =404;
    }}
}}
"""

def wp_recommended(u, listen, extra_pathinfo=False):
    pathinfo = ""
    if extra_pathinfo:
        pathinfo = "\n        # NON-STOCK DELTA: PATH_INFO forwarding added for the controlled experiment\n        fastcgi_param PATH_INFO $fastcgi_path_info;\n        fastcgi_split_path_info ^(.+?\\.php)(/.*)$;"
    return f"""
# ---- WordPress recommended nginx config (developer.wordpress.org) ----
server {{
    listen {listen};
    server_name _;
    root /var/www/wordpress;
    index index.php;

    location = /favicon.ico {{
        log_not_found off;
        access_log off;
    }}

    location = /robots.txt {{
        allow all;
        log_not_found off;
        access_log off;
    }}

    location / {{
        try_files $uri $uri/ /index.php?$args;
    }}

    location ~ \\.php$ {{
        include fastcgi.conf;
        fastcgi_intercept_errors on;
        fastcgi_pass {u};{pathinfo}
    }}

    location ~* \\.(js|css|png|jpg|jpeg|gif|ico)$ {{
        expires max;
        log_not_found off;
    }}
}}
"""

def mw_recommended(u, listen):
    return f"""
# ---- MediaWiki recommended nginx config (mediawiki.org Manual:Short URL/Nginx) ----
server {{
    listen {listen};
    server_name _;
    root /var/www;

    location ~ ^/w/(mw-config/)?(index|load|api|thumb|opensearch_desc|rest|img_auth)\\.php$ {{
        include /etc/nginx/fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass {u};
    }}

    location /w/images {{
        add_header X-Content-Type-Options "nosniff";
        types {{ text/plain html htm shtml phtml; }}
    }}
    location /w/images/deleted {{
        deny all;
    }}
    location ~ ^/w/resources/(assets|lib|src) {{
        try_files $uri =404;
        add_header Cache-Control "public";
        expires 7d;
    }}
    location ~ ^/w/(skins|extensions)/.+\\.(css|js|gif|jpg|jpeg|png|svg|wasm|ttf|woff|woff2)$ {{
        try_files $uri =404;
        add_header Cache-Control "public";
        expires 7d;
    }}
    location = /favicon.ico {{
        alias /w/images/6/64/Favicon.ico;
        add_header Cache-Control "public";
        expires 7d;
    }}
    location ~ ^/w/(COPYING|CREDITS)$ {{
        default_type text/plain;
    }}
    location /w/rest.php/ {{
        try_files $uri $uri/ /w/rest.php?$query_string;
    }}
    location /wiki/ {{
        rewrite ^/wiki/(?<pagename>.*)$ /w/index.php;
    }}
    location = /robots.txt {{
    }}
    location = / {{
        return 301 /wiki/Main_Page;
    }}
    location / {{
        return 404;
    }}
}}
"""

def fpm_docs_pattern(u, listen, root):
    return f"""
# ---- canonical nginx+PHP-FPM example (no try_files), PHP docs / CVE reproducer ----
server {{
    listen {listen};
    server_name _;
    root {root};
    index index.php;
    location ~ [^/]\\.php(/|$) {{
        fastcgi_split_path_info ^(.+?\\.php)(/.*)$;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_param PATH_TRANSLATED $document_root$fastcgi_path_info;
        fastcgi_pass {u};
        fastcgi_index index.php;
    }}
}}
"""

def stock_snippet_no_tryfiles(u, listen, root):
    return f"""
# ---- DELTA: packaged snippet with its `try_files $fastcgi_script_name =404` removed ----
server {{
    listen {listen};
    root {root};
    index index.php;
    server_name _;
    location ~ \\.php$ {{
        fastcgi_split_path_info ^(.+?\\.php)(/.*)$;
        set $path_info $fastcgi_path_info;
        fastcgi_param PATH_INFO $path_info;
        fastcgi_index index.php;
        include fastcgi.conf;
        fastcgi_pass {u};
    }}
}}
"""

def mw_recommended_pathinfo(u, listen):
    return f"""
# ---- DELTA: MediaWiki recommended config + PATH_INFO forwarding (non-stock) ----
server {{
    listen {listen};
    server_name _;
    root /var/www;
    location ~ ^/w/(mw-config/)?(index|load|api|thumb|opensearch_desc|rest|img_auth)\\.php$ {{
        include /etc/nginx/fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_split_path_info ^(.+?\\.php)(/.*)$;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_pass {u};
    }}
    location /w/images {{ types {{ text/plain html htm shtml phtml; }} add_header X-Content-Type-Options "nosniff"; }}
    location /wiki/ {{ rewrite ^/wiki/(?<pagename>.*)$ /w/index.php; }}
    location = / {{ return 301 /wiki/Main_Page; }}
    location / {{ return 404; }}
}}
"""

def fpm_docs_nofix(u, listen, root):
    return f"""
# ---- canonical pattern, PHP 7.3.9 with cgi.fix_pathinfo=0 (delta) ----
server {{
    listen {listen};
    server_name _;
    root {root};
    index index.php;
    location ~ [^/]\\.php(/|$) {{
        fastcgi_split_path_info ^(.+?\\.php)(/.*)$;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_pass {u};
        fastcgi_index index.php;
    }}
}}
"""

def stock_reordered(u, listen, root):
    # packaged snippet order changed: PATH_INFO moved AFTER include fastcgi.conf
    return f"""
# ---- DELTA: stock snippet without try_files, PATH_INFO after fastcgi.conf ----
server {{
    listen {listen};
    root {root};
    index index.php;
    server_name _;
    location ~ \\.php$ {{
        fastcgi_split_path_info ^(.+?\\.php)(/.*)$;
        include fastcgi.conf;
        set $path_info $fastcgi_path_info;
        fastcgi_param PATH_INFO $path_info;
        fastcgi_pass {u};
    }}
}}
"""

def stock_reordered_with_tryfiles(u, listen, root):
    return f"""
# ---- DELTA: stock snippet WITH try_files, PATH_INFO after fastcgi.conf ----
server {{
    listen {listen};
    root {root};
    index index.php;
    server_name _;
    location ~ \\.php$ {{
        fastcgi_split_path_info ^(.+?\\.php)(/.*)$;
        try_files $fastcgi_script_name =404;
        include fastcgi.conf;
        set $path_info $fastcgi_path_info;
        fastcgi_param PATH_INFO $path_info;
        fastcgi_pass {u};
    }}
}}
"""

def control(listen):
    return f"""
# ---- 8.x control endpoint (explicitly NOT an app: app code is PHP-8-incompatible) ----
server {{
    listen {listen};
    root /var/www/ctrl;
    index index.php;
    server_name _;
    location / {{ try_files $uri $uri/ =404; }}
    location ~ \\.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass t11043-fpm8426;
    }}
}}
"""

def main():
    parts = ["# generated by gen_nginx.py - do not edit by hand\n"]
    for _tag, _ver, u, i in VERS:
        parts.append(upstream(u))
    urls = []
    parts.append(upstream("t11043-fpm739-nofix"))
    for tag, ver, u, i in VERS:
        parts.append(stock_snippet(u, port(i, 1), "/var/www/html"))
        parts.append(wp_recommended(u, port(i, 2)))
        parts.append(mw_recommended(u, port(i, 3)))
        parts.append(stock_snippet(u, port(i, 4), "/var/www/w"))
        parts.append(wp_recommended(u, port(i, 5), extra_pathinfo=True))
        parts.append(fpm_docs_pattern(u, port(i, 7), "/var/www/wordpress"))
        parts.append(fpm_docs_pattern(u, port(i, 8), "/var/www/w"))
        urls += [
            (f"{ver}", "stock-snippet(WP docroot)", port(i, 1), "stock distro"),
            (f"{ver}", "wordpress-recommended", port(i, 2), "common app config"),
            (f"{ver}", "mediawiki-recommended", port(i, 3), "common app config"),
            (f"{ver}", "stock-snippet(MW docroot)", port(i, 4), "stock distro"),
            (f"{ver}", "wordpress-recommended+PATH_INFO", port(i, 5), "non-stock"),
            (f"{ver}", "fpm-docs-pattern(WP docroot)", port(i, 7), "common config"),
            (f"{ver}", "fpm-docs-pattern(MW docroot)", port(i, 8), "common config"),
        ]
    parts.append(stock_snippet_no_tryfiles(VERS[0][2], port(0, 9), "/var/www/html"))
    parts.append(mw_recommended_pathinfo(VERS[0][2], port(0, 10)))
    parts.append(stock_snippet_no_tryfiles(VERS[2][2], port(2, 9), "/var/www/html"))
    parts.append(mw_recommended_pathinfo(VERS[2][2], port(2, 10)))
    parts.append(fpm_docs_nofix("t11043-fpm739-nofix", 8071, "/var/www/wordpress"))
    parts.append(stock_reordered(VERS[0][2], 8072, "/var/www/html"))
    parts.append(stock_reordered_with_tryfiles(VERS[0][2], 8073, "/var/www/html"))
    parts.append(stock_reordered(VERS[2][2], 8074, "/var/www/html"))
    parts.append(stock_reordered_with_tryfiles(VERS[2][2], 8075, "/var/www/html"))
    parts.append(stock_no_php(port(0, 6), "/var/www/html"))
    urls.append(("7.3.9", "stock-default-no-php", port(0, 6), "stock distro"))
    urls.append(("7.3.9", "stock-snippet-minus-tryfiles", port(0, 9), "non-stock delta"))
    urls.append(("7.3.9", "mediawiki-recommended+PATH_INFO", port(0, 10), "non-stock delta"))
    urls.append(("7.3.11", "stock-snippet-minus-tryfiles", port(2, 9), "non-stock delta"))
    urls.append(("7.3.11", "mediawiki-recommended+PATH_INFO", port(2, 10), "non-stock delta"))
    urls.append(("7.3.9", "fpm-docs fix_pathinfo=0", 8071, "non-stock delta"))
    urls.append(("7.3.9", "stock-no-tryfiles-reordered", 8072, "non-stock delta"))
    urls.append(("7.3.9", "stock-reordered-with-tryfiles", 8073, "non-stock delta"))
    urls.append(("7.3.11", "stock-no-tryfiles-reordered", 8074, "non-stock delta"))
    urls.append(("7.3.11", "stock-reordered-with-tryfiles", 8075, "non-stock delta"))
    parts.append(control(port(5, 6)))
    urls.append(("8.4.26", "control-endpoint", port(5, 6), "control"))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    open(OUT, "w").write("\n".join(parts))
    print(OUT)
    for ver, name, p, cls in urls:
        print(f"{ver:8s} {name:38s} {p}  host={p+11100}  {cls}")

if __name__ == "__main__":
    main()

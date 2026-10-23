#!/usr/bin/env python3
"""Lab harness: start/stop one PHP-FPM build (container or host binary) + host nginx.

Usage:
  lab.py up --ver 8.0.30 --image mirror.gcr.io/library/php:8.0.30-fpm \
            --port-base 1981 --mode stock|diag
  lab.py up --ver 8.2.34 --fpm-bin /path/php-fpm --port-base 1982 --mode diag
  lab.py down --ver 8.0.30
  lab.py get --port 19811 --path /probe.php
"""
import argparse, os, shutil, subprocess, sys, time, socket, json

D = os.path.dirname(os.path.abspath(__file__))
D = os.path.dirname(D)  # run root
NGINX = "/opt/nginx-1.30.1/sbin/nginx"
WWW = os.path.join(D, "www")
LOGS = os.path.join(D, "logs")

FASTCGI_PARAMS = """fastcgi_param  QUERY_STRING       $query_string;
fastcgi_param  REQUEST_METHOD     $request_method;
fastcgi_param  CONTENT_TYPE       $content_type;
fastcgi_param  CONTENT_LENGTH     $content_length;
fastcgi_param  SCRIPT_NAME        $fastcgi_script_name;
fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;
fastcgi_param  REQUEST_URI        $request_uri;
fastcgi_param  DOCUMENT_URI       $document_uri;
fastcgi_param  DOCUMENT_ROOT      $document_root;
fastcgi_param  SERVER_PROTOCOL    $server_protocol;
fastcgi_param  REQUEST_SCHEME     $scheme;
fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;
fastcgi_param  REMOTE_ADDR        $remote_addr;
fastcgi_param  SERVER_ADDR        $server_addr;
fastcgi_param  SERVER_PORT        $server_port;
fastcgi_param  SERVER_NAME        $server_name;
fastcgi_param  REDIRECT_STATUS    200;
"""

def run(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)

def wait_port(port, timeout=30):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            s.close(); return True
        except OSError:
            time.sleep(0.15)
    return False

def nginx_conf(port_base, mode, fpm_port):
    nb = os.path.join(D, "nginx", str(port_base))
    os.makedirs(nb, exist_ok=True)
    for sub in ("client_temp", "fastcgi_temp", "proxy_temp"):
        os.makedirs(os.path.join(nb, sub), exist_ok=True)
    open(os.path.join(nb, "fastcgi_params"), "w").write(FASTCGI_PARAMS)
    extra = "            client_max_body_size 64m;\n" if mode == "diag" else ""
    def server(port, extra_lines):
        return f"""
    server {{
        listen 127.0.0.1:{port};
        server_name _;
        root {WWW};
        index index.php;
        location / {{ try_files $uri $uri/ =404; }}
        location ~ \\.php$ {{
{extra_lines}            include {nb}/fastcgi_params;
            fastcgi_pass 127.0.0.1:{fpm_port};
            fastcgi_read_timeout 300;
        }}
    }}"""
    body = server(port_base+1, extra)
    body += server(port_base+2, "            client_max_body_size 64m;\n")
    body += server(port_base+3, "            client_max_body_size 64m;\n            fastcgi_request_buffering off;\n")
    conf = f"""worker_processes 1;
daemon on;
error_log {nb}/error.log info;
pid {nb}/nginx.pid;
events {{ worker_connections 1024; }}
http {{
    access_log {nb}/access.log;
    client_body_temp_path {nb}/client_temp;
    fastcgi_temp_path {nb}/fastcgi_temp;
    proxy_temp_path {nb}/proxy_temp;
    client_body_buffer_size 128k;
{body}
}}
"""
    path = os.path.join(nb, "nginx.conf")
    open(path, "w").write(conf)
    return path, nb

def up(args):
    port_base = args.port_base
    fpm_port = port_base
    web_port = port_base + 1
    os.makedirs(LOGS, exist_ok=True)
    os.makedirs(os.path.join(LOGS, "fpm-" + args.ver), exist_ok=True)
    conf_path, nb = nginx_conf(port_base, args.mode, fpm_port)
    name = "f80x-" + args.ver.replace(".", "")
    run(["docker", "rm", "-f", name])

    pool = open(os.path.join(D, "conf", "fpm-lab.conf")).read().replace(
        "listen = 127.0.0.1:19810", "listen = 0.0.0.0:9000")
    pool = pool.replace("listen.allowed_clients = 127.0.0.1\n", "")
    pool_path = os.path.join(D, "conf", "fpm-%s.conf" % args.ver)
    open(pool_path, "w").write(pool)
    ini_src = args.ini or os.path.join(D, "conf", "php-lab.ini")

    if args.image:
        fpmdir = os.path.join(LOGS, "fpm-" + args.ver)
        cmd = ["docker", "run", "-d", "--name", name,
               "-p", "127.0.0.1:%d:9000" % fpm_port,
               "-v", WWW + ":" + WWW + ":ro",
               "-v", ini_src + ":/usr/local/etc/php/php.ini:ro",
               "-v", pool_path + ":/usr/local/etc/php-fpm.d/zz-lab.conf:ro",
               "-v", fpmdir + ":/var/log/fpm",
               args.image,
               "php-fpm", "-F", "-O"]
    else:
        # host binary: run as current user, no user/group directives
        hostpool = pool.replace("user = www-data\n", "").replace("group = www-data\n", "")
        hostpool = hostpool.replace("/var/log/fpm", os.path.join(LOGS, "fpm-" + args.ver))
        hostpool = hostpool.replace("listen = 127.0.0.1:%d" % fpm_port,
                                    "listen = 127.0.0.1:%d" % fpm_port)
        hostpool_path = os.path.join(D, "conf", "fpm-host-%s.conf" % args.ver)
        open(hostpool_path, "w").write(hostpool)
        cmd = [args.fpm_bin, "-F", "-y", hostpool_path, "-c", ini_src,
               "--fpm-config", hostpool_path]
        # php-fpm -y is the fpm config; -c php.ini
        cmd = [args.fpm_bin, "-F", "-y", hostpool_path, "-c", ini_src]
        log = open(os.path.join(LOGS, "fpm-" + args.ver, "stdout.log"), "ab")
        p = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                             env=dict(os.environ, PHP_INI_SCAN_DIR=""))
        open(os.path.join(D, "logs", "hostfpm-%s.pid" % args.ver), "w").write(str(p.pid))
    if args.image:
        r = run(cmd)
        if r.returncode != 0:
            print("docker run failed:", r.stderr); return 1
    ok = wait_port(fpm_port, 30)
    print("fpm port %d up=%s" % (fpm_port, ok))
    r = run([NGINX, "-p", nb, "-c", conf_path])
    if r.returncode != 0:
        print("nginx failed:", r.stderr); return 1
    ok2 = wait_port(web_port, 10)
    print("web port %d up=%s" % (web_port, ok2))
    json.dump({"ver": args.ver, "port_base": port_base, "fpm_port": fpm_port,
               "web_port": web_port, "image": args.image or "", "mode": args.mode,
               "fpm_bin": args.fpm_bin or "", "nginx_prefix": nb,
               "container": name if args.image else "",
               "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
              open(os.path.join(LOGS, "lab-%s.json" % args.ver), "w"), indent=1)
    return 0

def down(args):
    name = "f80x-" + args.ver.replace(".", "")
    run(["docker", "rm", "-f", name])
    nb = os.path.join(D, "nginx", str(args.port_base))
    if os.path.exists(os.path.join(nb, "nginx.pid")):
        run([NGINX, "-p", nb, "-c", os.path.join(nb, "nginx.conf"), "-s", "stop"])
    pf = os.path.join(D, "logs", "hostfpm-%s.pid" % args.ver)
    if os.path.exists(pf):
        try:
            os.kill(int(open(pf).read().strip()), 15)
        except OSError:
            pass
    print("down", args.ver)
    return 0

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("up")
    u.add_argument("--ver", required=True)
    u.add_argument("--image", default="")
    u.add_argument("--fpm-bin", default="")
    u.add_argument("--ini", default="")
    u.add_argument("--port-base", type=int, required=True)
    u.add_argument("--mode", default="stock", choices=["stock", "diag"])
    d = sub.add_parser("down")
    d.add_argument("--ver", required=True)
    d.add_argument("--port-base", type=int, required=True)
    args = ap.parse_args()
    return up(args) if args.cmd == "up" else down(args)

if __name__ == "__main__":
    sys.exit(main())

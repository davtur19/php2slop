#!/usr/bin/env python3
"""run_lanes.py - drive the whole mitigation matrix against private stacks.

Lanes (see findings.md):
  A  28980 FPM 8.5.10 control (8M, upload_progress on)          -> nginx :28990
  B  28981 FPM 8.5.10 + M1+M2+M3 (128M, upload_progress off)    -> nginx :28991
  C  28983 FPM 8.5.10 + M1 only (8M, upload_progress off)       -> nginx :28992
  B2 28984 FPM 8.5.10 oversize probe (12M, post 16M)            -> nginx :28993
  B3 28985 FPM 8.5.10 oversize probe (128M, post 16M)           -> nginx :28994
  D  28982 httpd + mod_php 8.5.10 admin scope mitigations (direct HTTP)
  E  effective-INI probe collected in every lane
"""
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

BASE = "/tmp/opencode/mitigation_1021"
LANES = BASE + "/lanes"
RESULTS = BASE + "/results"
HTDOCS = BASE + "/htdocs"
FPM = "/home/davide/ailocal/php/zerodays_1020/install/sbin/php-fpm"
HTTPD = "/tmp/opencode/apache/bin/httpd"
NGINX = "/opt/nginx-1.30.1/sbin/nginx"
NGINX_CONF = BASE + "/nginx/nginx.conf"
SEED_4M = "/tmp/opencode/vulntest8512_2127/records/8512asan_nomm_seed.sess"

sys.path.insert(0, BASE + "/scripts")
import http_arm  # noqa: E402

LOG = None


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    if LOG:
        LOG.write(line + "\n")
        LOG.flush()


def sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def session_state(d):
    out = []
    if not os.path.isdir(d):
        return out
    for name in sorted(os.listdir(d)):
        p = os.path.join(d, name)
        if not os.path.isfile(p):
            continue
        data = open(p, "rb").read(200)
        out.append({"name": name, "size": os.path.getsize(p),
                    "sha256": sha_file(p), "head_repr": repr(data[:160]),
                    "head_hex": data[:160].hex()})
    return out


def wait_port(port, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


class Lane:
    def __init__(self, name, port, front_port=None, kind="fpm"):
        self.name, self.port, self.front, self.kind = name, port, front_port, kind
        self.dir = os.path.join(LANES, name)
        self.res = os.path.join(RESULTS, name)
        self.proc = None
        self.master_pid = None
        os.makedirs(self.res, exist_ok=True)

    def reset(self):
        for sub in ("logs", "sessions", "tmp", "run"):
            d = os.path.join(self.dir, sub)
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d, exist_ok=True)
        # fpm.conf / mitmD.conf already generated
        self.res = os.path.join(RESULTS, self.name)
        shutil.rmtree(self.res, ignore_errors=True)
        os.makedirs(self.res, exist_ok=True)

    def start(self):
        if self.kind == "fpm":
            env = os.environ.copy()
            env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1:allocator_may_return_null=1"
            env["USE_ZEND_ALLOC"] = "1"
            out = open(os.path.join(self.dir, "logs", "stdout.log"), "ab")
            self.proc = subprocess.Popen(
                [FPM, "-n", "-y", os.path.join(self.dir, "fpm.conf")],
                stdout=out, stderr=subprocess.STDOUT, env=env,
                start_new_session=True, cwd=self.dir)
            ok = wait_port(self.port)
            pf = os.path.join(self.dir, "run", "fpm.pid")
            for _ in range(50):
                if os.path.exists(pf):
                    break
                time.sleep(0.05)
            self.master_pid = int(open(pf).read().strip())
            log(f"{self.name}: FPM master {self.master_pid} listening={ok}")
            if not ok:
                raise SystemExit(f"{self.name}: FPM did not listen")
        else:
            conf = os.path.join(self.dir, "mitmD.conf")
            self.proc = subprocess.Popen([HTTPD, "-f", conf, "-k", "start"],
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
            ok = wait_port(self.port)
            pf = os.path.join(self.dir, "run", "httpd.pid")
            for _ in range(50):
                if os.path.exists(pf):
                    break
                time.sleep(0.05)
            self.master_pid = int(open(pf).read().strip())
            log(f"{self.name}: httpd master {self.master_pid} listening={ok}")
            if not ok:
                raise SystemExit(f"{self.name}: httpd did not listen")

    def stop(self):
        if self.kind == "fpm":
            pf = os.path.join(self.dir, "run", "fpm.pid")
            pid = int(open(pf).read().strip()) if os.path.exists(pf) else self.master_pid
            if pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                for _ in range(100):
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.05)
                log(f"{self.name}: FPM master {pid} stopped")
            self.master_pid = None
        else:
            conf = os.path.join(self.dir, "mitmD.conf")
            subprocess.run([HTTPD, "-f", conf, "-k", "stop"], check=False)
            log(f"{self.name}: httpd stop issued (master {self.master_pid})")

    def worker_pids(self):
        p = os.path.join(self.dir, "logs", "access.log")
        pids = []
        if os.path.exists(p):
            for line in open(p):
                parts = line.split("|")
                if len(parts) > 6:
                    pids.append(parts[0])
                elif self.kind == "modphp":
                    pids.append(line.rstrip().split()[-1])
        return pids


class Recorder:
    def __init__(self, lane):
        self.lane = lane
        self.dir = os.path.join(lane.res, "steps")

    def _save(self, tag, meta, body):
        d = os.path.join(self.dir, tag)
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "response.bin"), "wb").write(body)
        open(os.path.join(d, "request.bin"), "wb").write(meta.pop("request_body", b""))
        json.dump(meta, open(os.path.join(d, "meta.json"), "w"), indent=1, sort_keys=True)

    def request(self, tag, path, sid, mode="get", length=None, parts=None, timeout=300):
        port = self.lane.front or self.lane.port
        if mode in ("arm", "big", "consumer"):
            if mode == "arm":
                body = http_arm.arm_body(sid.encode(), 262144, 20)
            elif mode == "big":
                body = http_arm.arm_body(sid.encode(), length, parts)
            else:
                body = http_arm.consumer_body()
            r = http_arm.post(port, path, sid, body, timeout)
        else:
            body = b""
            r = http_arm.get(port, path, sid, timeout)
        raw = r["body"]
        text = raw.decode("latin-1", "replace")
        oom = http_arm.OOM_RE.search(text)
        meta = {
            "tag": tag, "lane": self.lane.name, "port": port, "path": path,
            "sid": sid, "mode": mode, "body_len": len(body),
            "body_sha256": http_arm.sha(body),
            "http_status": r["http_status"], "headers": r["headers"],
            "duration_s": r["duration_s"], "resp_len": len(raw),
            "resp_sha256": http_arm.sha(raw),
            "body_preview": raw[:600].decode("latin-1", "replace"),
            "fatal_lines": http_arm.FATAL_RE.findall(text),
            "warning_lines": http_arm.WARN_RE.findall(text),
            "oom": ({"limit": oom.group(1), "tried": oom.group(2)} if oom else None),
            "request_body": body,
        }
        self._save(tag, dict(meta), raw)
        with open(os.path.join(self.lane.res, "results.jsonl"), "a") as f:
            slim = {k: v for k, v in meta.items() if k != "request_body"}
            f.write(json.dumps(slim, sort_keys=True) + "\n")
        log(f"{self.lane.name}/{tag}: http={r['http_status']} resp_len={len(raw)} "
            f"sha={meta['resp_sha256'][:16]} oom={meta['oom']} "
            f"fatal={bool(meta['fatal_lines'])}")
        return meta, raw


def effective_ini(lane, rec):
    meta, raw = rec.request("effective_ini", "/probe.php", "probesid", "get")
    path = os.path.join(lane.res, "effective_ini.txt")
    with open(path, "w") as f:
        upstream = f"php-fpm {lane.port}" if lane.kind == "fpm" else "mod_php/httpd"
        f.write(f"# lane {lane.name} port {lane.front or lane.port} ({upstream})\n")
        f.write(f"# HTTP {meta['http_status']} fetched {time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n")
        f.write(raw.decode("latin-1"))
    log(f"{lane.name}: effective_ini -> {path}")
    return raw.decode("latin-1")


def plant_record(lane, sid, src=SEED_4M):
    dst = os.path.join(lane.dir, "sessions", "sess_" + sid)
    shutil.copyfile(src, dst)
    st = {"name": os.path.basename(dst), "size": os.path.getsize(dst),
          "sha256": sha_file(dst)}
    log(f"{lane.name}: planted {src} -> {dst} ({st['size']} B {st['sha256'][:16]})")
    return st


def dump_state(lane, tag):
    st = session_state(os.path.join(lane.dir, "sessions"))
    json.dump(st, open(os.path.join(lane.res, f"session_state_{tag}.json"), "w"),
              indent=1, sort_keys=True)
    for s in st:
        log(f"{lane.name}: session[{tag}] {s['name']} size={s['size']} sha={s['sha256'][:16]}")
    if not st:
        log(f"{lane.name}: session[{tag}] (empty)")
    return st


def access_lines(lane):
    p = os.path.join(lane.dir, "logs", "access.log")
    return open(p).read().splitlines() if os.path.exists(p) else []


def fpm_exits(lane):
    p = os.path.join(lane.dir, "logs", "fpm.log")
    if not os.path.exists(p):
        return []
    return [ln for ln in open(p).read().splitlines() if "exited with code" in ln]


def tail_file(path, n=30):
    if not os.path.exists(path):
        return f"(missing {path})"
    return "\n".join(open(path, errors="replace").read().splitlines()[-n:])


def lane_a():
    lane = Lane("A_fpm_control", 28980, 28990)
    lane.reset()
    with open(os.path.join(lane.res, "console.log"), "w") as f:
        global LOG
        LOG = f
        log("=== lane A: FPM 8.5.10 control, 8M, upload_progress=1, cleanup=0")
        lane.start()
        try:
            effective_ini(lane, Recorder(lane))
            base = plant_record(lane, "controlsidA")
            dump_state(lane, "planted")
            pre = json.load(open(os.path.join(lane.dir, "run", "fpm.pid"))) if False else None
            # worker identity before the attack (single static child)
            log("A: pre-attack worker pids in access log: " + str(lane.worker_pids()))
            rec = Recorder(lane)
            rec.request("baseline_consumer_stored", "/index.php", "controlsidA", "get")
            rec.request("producer_arm", "/index.php", "controlsidA", "arm")
            time.sleep(0.3)
            dump_state(lane, "after_producer")
            rec.request("consumer_after", "/index.php", "controlsidA", "get")
            rec.request("consumer_after_2", "/index.php", "controlsidA", "get")
            json.dump({"planted": base, "access_log": access_lines(lane),
                       "fpm_exits": fpm_exits(lane)},
                      open(os.path.join(lane.res, "worker_receipt.json"), "w"), indent=1)
            log("A: access log:\n" + "\n".join(access_lines(lane)))
            log("A: worker exits:\n" + "\n".join(fpm_exits(lane)))
            log("A: php_err tail:\n" + tail_file(os.path.join(lane.dir, "logs", "php_err.log")))
        finally:
            lane.stop()
            LOG = None


def lane_b():
    lane = Lane("B_fpm_mitigated", 28981, 28991)
    lane.reset()
    with open(os.path.join(lane.res, "console.log"), "w") as f:
        global LOG
        LOG = f
        log("=== lane B: FPM 8.5.10 + M1+M2+M3 (128M, post 8M, upload_progress=0, display_errors=0)")
        lane.start()
        try:
            effective_ini(lane, Recorder(lane))
            plant_record(lane, "mitigatedB")
            dump_state(lane, "planted")
            rec = Recorder(lane)
            rec.request("baseline_consumer_stored", "/index.php", "mitigatedB", "get")
            for i in range(5):
                rec.request(f"arm_{i + 1}", "/index.php", "mitigatedB", "arm")
                dump_state(lane, f"after_arm_{i + 1}")
            rec.request("consumer_after_1", "/index.php", "mitigatedB", "get")
            rec.request("consumer_after_2", "/index.php", "mitigatedB", "get")
            # ordinary session state survives the arm (fresh sid)
            rec.request("plant_state", "/plant.php", "bstate", "get")
            rec.request("state_before_arm", "/probe_session.php", "bstate", "get")
            rec.request("arm_on_state", "/index.php", "bstate", "arm")
            rec.request("state_after_arm", "/probe_session.php", "bstate", "get")
            # body larger than post_max_size: PHP must refuse to parse it
            rec.request("oversize_beyond_post_max", "/index.php", "mitigatedB", "big",
                        length=1048576, parts=20)
            json.dump({"access_log": access_lines(lane),
                       "fpm_exits": fpm_exits(lane),
                       "session_state_final": session_state(os.path.join(lane.dir, "sessions"))},
                      open(os.path.join(lane.res, "worker_receipt.json"), "w"), indent=1)
            log("B: access log:\n" + "\n".join(access_lines(lane)))
            log("B: worker exits: " + repr(fpm_exits(lane)))
            log("B: php_err tail:\n" + tail_file(os.path.join(lane.dir, "logs", "php_err.log")))
        finally:
            lane.stop()
            LOG = None


def lane_c():
    lane = Lane("C_fpm_m1_only", 28983, 28992)
    lane.reset()
    with open(os.path.join(lane.res, "console.log"), "w") as f:
        global LOG
        LOG = f
        log("=== lane C: FPM 8.5.10 + M1 only (8M, upload_progress=0)")
        lane.start()
        try:
            effective_ini(lane, Recorder(lane))
            rec = Recorder(lane)
            for i in range(3):
                rec.request(f"arm_{i + 1}", "/index.php", "m1onlyC", "arm")
                time.sleep(0.2)
            dump_state(lane, "after_arms")
            json.dump({"access_log": access_lines(lane), "fpm_exits": fpm_exits(lane)},
                      open(os.path.join(lane.res, "worker_receipt.json"), "w"), indent=1)
            log("C: access log:\n" + "\n".join(access_lines(lane)))
            log("C: worker exits:\n" + "\n".join(fpm_exits(lane)))
            log("C: php_err tail:\n" + tail_file(os.path.join(lane.dir, "logs", "php_err.log")))
        finally:
            lane.stop()
            LOG = None


def lane_oversize(name, port, front):
    lane = Lane(name, port, front)
    lane.reset()
    with open(os.path.join(lane.res, "console.log"), "w") as f:
        global LOG
        LOG = f
        log(f"=== lane {name}: FPM 8.5.10 oversize probe port {port} front {front}")
        lane.start()
        try:
            effective_ini(lane, Recorder(lane))
            rec = Recorder(lane)
            rec.request("oversize_arm", "/index.php", "oversizeSid", "big",
                        length=786432, parts=20)
            time.sleep(0.3)
            dump_state(lane, "after_oversize")
            json.dump({"access_log": access_lines(lane), "fpm_exits": fpm_exits(lane)},
                      open(os.path.join(lane.res, "worker_receipt.json"), "w"), indent=1)
            log(f"{name}: access log:\n" + "\n".join(access_lines(lane)))
            log(f"{name}: worker exits:\n" + "\n".join(fpm_exits(lane)))
            log(f"{name}: php_err tail:\n" + tail_file(os.path.join(lane.dir, "logs", "php_err.log")))
        finally:
            lane.stop()
            LOG = None


def lane_d():
    lane = Lane("D_modphp", 28982, kind="modphp")
    lane.reset()
    with open(os.path.join(lane.res, "console.log"), "w") as f:
        global LOG
        LOG = f
        log("=== lane D: httpd 2.4.66 + mod_php 8.5.10, admin-scope M1+M2+M3")
        lane.start()
        try:
            effective_ini(lane, Recorder(lane))
            plant_record(lane, "modphpD")
            dump_state(lane, "planted")
            rec = Recorder(lane)
            rec.request("baseline_consumer_stored", "/index.php", "modphpD", "get")
            for i in range(3):
                rec.request(f"arm_{i + 1}", "/index.php", "modphpD", "arm")
            rec.request("consumer_after_1", "/index.php", "modphpD", "get")
            rec.request("consumer_after_2", "/index.php", "modphpD", "get")
            dump_state(lane, "after_arms")
            json.dump({"access_log": access_lines(lane),
                       "php_err": tail_file(os.path.join(lane.dir, "logs", "php_err.log"), 10)},
                      open(os.path.join(lane.res, "worker_receipt.json"), "w"), indent=1)
            log("D: access log:\n" + "\n".join(access_lines(lane)))
            log("D: php_err tail:\n" + tail_file(os.path.join(lane.dir, "logs", "php_err.log")))
        finally:
            lane.stop()
            LOG = None


def lane_d0():
    lane = Lane("D0_modphp_control", 28986, kind="modphp")
    lane.reset()
    with open(os.path.join(lane.res, "console.log"), "w") as f:
        global LOG
        LOG = f
        log("=== lane D0: httpd 2.4.66 + mod_php 8.5.10 UNMITIGATED (8M, upload_progress=1)")
        lane.start()
        try:
            effective_ini(lane, Recorder(lane))
            rec = Recorder(lane)
            rec.request("arm_unmitigated", "/index.php", "modphpCtl", "arm")
            rec.request("consumer_after", "/index.php", "modphpCtl", "get")
            dump_state(lane, "after_arm")
            json.dump({"access_log": access_lines(lane),
                       "php_err": tail_file(os.path.join(lane.dir, "logs", "php_err.log"), 10)},
                      open(os.path.join(lane.res, "worker_receipt.json"), "w"), indent=1)
            log("D0: access log:\n" + "\n".join(access_lines(lane)))
            log("D0: php_err tail:\n" + tail_file(os.path.join(lane.dir, "logs", "php_err.log")))
        finally:
            lane.stop()
            LOG = None


def lane_b4():
    lane = Lane("B4_unlimited_mem", 28987, 28995)
    lane.reset()
    with open(os.path.join(lane.res, "console.log"), "w") as f:
        global LOG
        LOG = f
        log("=== lane B4: FPM 8.5.10 + M1+M3 and memory_limit=-1 (Tenable stopgap)")
        lane.start()
        try:
            effective_ini(lane, Recorder(lane))
            rec = Recorder(lane)
            for i in range(2):
                rec.request(f"arm_{i + 1}", "/index.php", "b4sid", "arm")
            rec.request("consumer_after", "/index.php", "b4sid", "get")
            rec.request("oversize_beyond_post_max", "/index.php", "b4sid", "big",
                        length=1048576, parts=20)
            dump_state(lane, "after_arms")
            json.dump({"access_log": access_lines(lane), "fpm_exits": fpm_exits(lane)},
                      open(os.path.join(lane.res, "worker_receipt.json"), "w"), indent=1)
            log("B4: access log:\n" + "\n".join(access_lines(lane)))
            log("B4: worker exits:\n" + "\n".join(fpm_exits(lane)))
            log("B4: php_err tail:\n" + tail_file(os.path.join(lane.dir, "logs", "php_err.log")))
        finally:
            lane.stop()
            LOG = None


def main():
    os.makedirs(RESULTS, exist_ok=True)
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("all", "A"):
        lane_a()
    if which in ("all", "B"):
        lane_b()
    if which in ("all", "C"):
        lane_c()
    if which in ("all", "B2"):
        lane_oversize("B2_oversize_12M", 28984, 28993)
    if which in ("all", "B3"):
        lane_oversize("B3_oversize_128M", 28985, 28994)
    if which in ("all", "D"):
        lane_d()
    if which in ("all", "D0"):
        lane_d0()
    if which in ("all", "B4"):
        lane_b4()


if __name__ == "__main__":
    main()

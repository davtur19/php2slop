# php2shell-exp

从 PHP 官方补丁 [`3584a98bda`](https://github.com/php/php-src/commit/3584a98bda) 反推的 PoC 与 RCE，附带 8.2.34 / 8.2.35 双容器差分环境。

Patch-derived PoC and RCE for the pre-RINIT session decode in PHP's upload-progress handler.

## 这是什么

- `exp/poc_pre_rinit.py` — 证明 upload-progress 在 RINIT 之前解码 session 并执行对象析构器，不执行命令
- `exp/exp_rce.py` — 同一条路径上执行任意命令，输出经 HTTP 回读
- `exp/poc_oom.py` — CVE-2026-109618 的 OOM 触发（仅触发，不是 RCE）
- `lab/` — `php:8.2.34-fpm` 与 `php:8.2.35-fpm`，各带 nginx

这条链在 8.2.34 上稳定打通，在 8.2.35 上被 `incomplete_classes_only` 挡住。它不是零依赖利用：需要目标在 RINIT 之前已经存在一个带危险魔术方法的类，lab 用 `opcache.preload` 模拟。

## 已验证

同一份代码、同一份配置，只换镜像：

| 分支 | 可利用 | 已修复 |
|---|---|---|
| 8.1 | 8.1.34（EOL，无官方修复） | — |
| 8.2 | 8.2.34 | 8.2.35 |
| 8.3 | 8.3.35 | 8.3.36 |
| 8.4 | 8.4.26 | 8.4.27 |
| 8.5 | 8.5.11 | 8.5.12 |

`./verify.sh` 在 8.2 分支上的输出：

```
PoC 8.2.34  (expect 0)   0
PoC 8.2.35  (expect 1)   1
RCE 8.2.34  (expect 0)   0
RCE 8.2.35  (expect 1)   1
[+] differential holds
```

完整输出和调用栈诊断见 [`docs/RESULTS.md`](docs/RESULTS.md)。

## 原理

补丁把 upload-progress 的解码标成“RINIT 之前，不允许用户代码”，并对该阶段启用 `incomplete_classes_only`。打补丁前，这段解码会把 session 记录里的对象按真实类实例化，`__wakeup` / `__unserialize` / `Serializable::unserialize` / `__destruct` 都在目标脚本编译之前运行。

利用分两步，全部走 HTTP：

1. `POST /app/upload.php`。该目录 `.user.ini` 设 `session.serialize_handler=php_serialize`；upload-progress 把 multipart filename 原样写进 session 文件，`x|O:6:"PrePwn":...` 连同竖线一起落盘。
2. `POST /api/pre.php`。该目录用默认 `php` handler，脚本里没有 `session_start()`。请求启动阶段 `php_session_rfc1867_update()` 仍然会解码：`php` 解码器在第一个 `|` 处切开，把后半段交给 `unserialize()`。
3. 8.2.34 上对象按真实类创建，`__destruct()` 执行 `shell_exec($cmd)`，输出写到 webroot 下的随机文件。
4. 8.2.35 上同一段数据被降级为 `__PHP_Incomplete_Class`，没有析构器，也没有文件。

Payload 由 `exp/lib2shell.py::php_object()` 显式拼出，长度前缀按字节计算：

```
x|O:6:"PrePwn":2:{s:3:"cmd";s:12:"id; hostname";s:3:"out";s:33:"/var/www/html/.pwn_xxxxxxxx.txt";}
```

补丁 hunk 与代码的逐条对应见 [`docs/DERIVATION.md`](docs/DERIVATION.md)。

## 快速开始

需要 Docker Compose 和 Python 3.8+（仅标准库）。

```bash
git clone <repo> && cd php2shell-exp
./verify.sh                 # 起容器、跑 PoC/RCE、打印差分矩阵
docker compose -f lab/docker-compose.yml down -v
```

单独使用：

```bash
python3 exp/exp_rce.py --target http://127.0.0.1:18080 --command 'id; uname -a'
python3 exp/poc_pre_rinit.py --target http://127.0.0.1:18080
python3 exp/poc_oom.py --target http://127.0.0.1:18080 --size-mb 24
```

端口：`18080` = 8.2.34（易受攻击），`18081` = 8.2.35（已修复）。

## 利用条件

- 版本低于 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12。5.4.0 起带 `session.upload_progress` 的版本都有同一段 pre-RINIT 解码；5.x、7.x、8.0、8.1 已 EOL，没有官方修复。
- `session.upload_progress.enabled=On`（默认开启）。
- `session.upload_progress.cleanup=Off`（默认是 On）。On 时写请求结束会删掉进度条目；本项目不覆盖这种配置，需要另做竞态。
- 两个目录共享 session 存储，且 `serialize_handler` 不同：`php_serialize` 写、`php` 读。这是配置错误，不是默认值。
- RINIT 之前已存在可利用的类。pre-RINIT 路径只认 `opcache.preload` 或常驻扩展类；普通 `session_start()` 路径（见下）则任何可自动加载的 gadget 都行。

不需要认证、用户交互或应用层漏洞；FPM 和 mod_php 都成立。

## 影响范围

四个条件同时成立的部署不多，所以这条链不能套用“影响 70% 网站”的说法。它更适合按“配置错误放大器”评估。

一旦打通，影响是 Web 用户权限下的任意命令执行：读 `.env` 和数据库口令、写 webshell、连内网、横向。多租户共享 session 目录时可能跨租户。只有 `__wakeup` / `__unserialize` 的类也能造成文件写入、SSRF 一类副作用。

同一个 handler mismatch 还有第二条路：`php` 目录里若存在调用 `session_start()` 的端点，用 GET + Cookie 触发普通解码，8.2.35 上同样执行析构器（已实测）。`incomplete_classes_only` 只作用于 `PS(in_rfc1867_update)`，补丁关掉的是 RINIT 之前的捷径，不是这个配置错误本身。

OOM 触发不需要上述任何条件：单个约 24MB 的 urlencoded 请求就能让一个 FPM worker 退出（`exit 70`），8.2.34 和 8.2.35 都一样。这是这条 CVE 面里最容易规模化的影响，但只是拒绝服务。

## 组合利用

| 配合的漏洞 | 消除/绕过的条件 | 结果 |
|---|---|---|
| 任意文件写、路径穿越、备份恢复 | handler mismatch、upload_progress、cleanup 都不需要 | 直接把 session 文件写进 `save_path`；8.2.35 上照样 RCE（实测） |
| SSRF 打 Redis / Memcached 会话存储 | 同上，且不用落盘 | `SET` 会话键即可 |
| 任意文件上传且能控制文件名 | 自己制造 handler mismatch | 上传 `.user.ini` 设 `session.serialize_handler`（仅 CGI/FPM） |
| 应用里有 `session_start()` 端点 | 版本限制 | 普通解码路径，补丁不影响（实测 8.2.35） |
| LFI | handler mismatch | `include` 会话文件执行 PHP 代码（实测 8.2.35） |
| 会话固定 / SID 可控 | 需要受害者 SID | 配合可写会话 → 账号接管 |
| 共享 `save_path` 的多租户 | 无 | 写入其他 vhost 的会话，跨租户 |
| OOM 触发 | 无 | 每个请求打掉一个 worker，直接 DoS |

最有价值的是第一条：把 `role|s:5:"admin";` 写进 `save_path/sess_<sid>` 就能伪造会话；把序列化对象写进去再访问 `session_start()` 端点就是 RCE。两者都在 8.2.35 上实测成功。

## 项目结构

```
php2shell-exp/
├── exp/
│   ├── lib2shell.py        HTTP / multipart / serialize 原语
│   ├── poc_pre_rinit.py    析构器触发（不执行命令）
│   ├── exp_rce.py          任意命令执行
│   └── poc_oom.py          OOM 触发（仅触发）
├── lab/
│   ├── docker-compose.yml  8.2.34 + 8.2.35，各带 nginx
│   ├── php.ini             共享配置（cleanup=Off，opcache.preload）
│   ├── www.conf / nginx.*.conf
│   └── webroot/
│       ├── preload.php     PrePwn / Probe / WakeProbe
│       ├── app/upload.php  php_serialize 写入点
│       └── api/            php 读取点（pre.php 无 session_start，start.php 有）
├── docs/
│   ├── DERIVATION.md       补丁 hunk → 原语 → 代码
│   └── RESULTS.md          实测输出与版本矩阵
└── verify.sh
```

## 限制

`exp_rce.py` 的命令执行依赖 `PrePwn` 这个 gadget；真实目标要换成 RINIT 前可见的框架 gadget。这不是漏洞本身的限制，而是反序列化利用的常规前提。

项目没有实现 CVE-2026-109618 的零依赖 OOM 利用：那需要 request heap 布局、释放后 chunk 复用和对象存储伪造。补丁只说明哪些指针是脏的，不给布局。`poc_oom.py` 只能证明触发点，不能区分“可被利用”和“已修复”。

## 参考

- 补丁：[`php/php-src@3584a98bda`](https://github.com/php/php-src/commit/3584a98bda)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) / CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) / CVE-2026-109619
- 补丁自带测试：`ext/session/tests/rfc1867_no_user_code.phpt`、`Zend/tests/oom_request_parsing.phpt`

## 授权

仅用于自有环境或获得书面授权的测试。使用者自行承担合规责任。

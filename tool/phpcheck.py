#!/usr/bin/env python3
"""phpcheck - passive PHP version/build vulnerability *candidate* checker.

This tool never sends exploit traffic.  With --url it performs one
unauthenticated GET and reads response headers only (Server, X-Powered-By,
Set-Cookie).  It does not send CVE probes, form bodies, cookies, or payloads.

Statuses are intentionally coarse:

  VULNERABLE-CANDIDATE  version/build is in an affected range, or below a
                        known fixed package revision, and the stated
                        conditions are not verified.  NOT proof.
  FIXED                 version/build is at or above a known fixed upstream
                        release or distro package revision.
  NOT-AFFECTED          version or SAPI is outside the affected scope.
  UNKNOWN               inputs are insufficient, or a distro backport cannot
                        be resolved without the exact package revision.

stdlib only, Python >= 3.10.  Data as of 2026-10-25.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Iterable

TOOL = "phpcheck"
TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = 1
AS_OF = "2026-10-25"

STATUS_CANDIDATE = "VULNERABLE-CANDIDATE"
STATUS_FIXED = "FIXED"
STATUS_NOT_AFFECTED = "NOT-AFFECTED"
STATUS_UNKNOWN = "UNKNOWN"

STATUS_ORDER = (STATUS_CANDIDATE, STATUS_FIXED, STATUS_NOT_AFFECTED, STATUS_UNKNOWN)

SAPI_CHOICES = ("mod_php", "fpm", "apache_fpm", "nginx_fpm", "iis_fastcgi", "cli", "unknown")
SAPI_LABELS = {
    "mod_php": "Apache mod_php",
    "fpm": "PHP-FPM (front end unspecified)",
    "apache_fpm": "Apache mod_proxy_fcgi + PHP-FPM",
    "nginx_fpm": "nginx + PHP-FPM",
    "iis_fastcgi": "IIS FastCGI",
    "cli": "CLI",
    "unknown": "unknown",
}
FPM_SAPIS = frozenset({"fpm", "nginx_fpm", "apache_fpm"})
WEB_SAPIS = frozenset({"mod_php", "fpm", "apache_fpm", "nginx_fpm", "iis_fastcgi"})


class InputError(ValueError):
    """Bad user input; exit 2."""


# ---------------------------------------------------------------------------
# Debian version comparison (dpkg algorithm, enough for package revisions)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DebVersion:
    raw: str
    epoch: int
    upstream: str
    revision: str

    @property
    def full_revision(self) -> str:
        return self.revision


def _deb_order(ch: str) -> int:
    if ch == "~":
        return -1
    if ch.isdigit():
        return 0
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        while ((i < la and not a[i].isdigit())
               or (j < lb and not b[j].isdigit())):
            ac = _deb_order(a[i]) if i < la and not a[i].isdigit() else 0
            bc = _deb_order(b[j]) if j < lb and not b[j].isdigit() else 0
            if ac != bc:
                return -1 if ac < bc else 1
            if i < la and not a[i].isdigit():
                i += 1
            if j < lb and not b[j].isdigit():
                j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        first_diff = 0
        while i < la and j < lb and a[i].isdigit() and b[j].isdigit():
            if first_diff == 0:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i].isdigit():
            return 1
        if j < lb and b[j].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def parse_deb_version(text: str) -> DebVersion:
    raw = text.strip()
    if not raw:
        raise InputError("empty Debian version")
    epoch = 0
    rest = raw
    m = re.match(r"^(\d+):(.*)$", rest)
    if m:
        epoch = int(m.group(1))
        rest = m.group(2)
    if "-" in rest:
        upstream, revision = rest.rsplit("-", 1)
    else:
        upstream, revision = rest, ""
    if not upstream:
        raise InputError(f"bad Debian version {raw!r}")
    return DebVersion(raw=raw, epoch=epoch, upstream=upstream, revision=revision)


def deb_compare(a: str | DebVersion, b: str | DebVersion) -> int:
    da = parse_deb_version(a) if isinstance(a, str) else a
    db = parse_deb_version(b) if isinstance(b, str) else b
    if da.epoch != db.epoch:
        return -1 if da.epoch < db.epoch else 1
    c = _verrevcmp(da.upstream, db.upstream)
    if c:
        return c
    return _verrevcmp(da.revision, db.revision)


# ---------------------------------------------------------------------------
# PHP version parsing
# ---------------------------------------------------------------------------

_PHP_RE = re.compile(
    r"^(?:php[ /]+)?(?P<maj>\d+)\.(?P<min>\d+)"
    r"(?:\.(?P<pat>\d+))?(?P<rest>.*)$",
    re.IGNORECASE,
)
_PRE_RE = re.compile(r"^(?:dev|alpha|beta|rc\d*|pl\d*)$", re.IGNORECASE)


def _pre_rank(pre: str | None) -> int:
    if not pre:
        return 4
    p = pre.lower()
    if p.startswith("dev"):
        return 0
    if p.startswith("alpha"):
        return 1
    if p.startswith("beta"):
        return 2
    if p.startswith("rc"):
        return 3
    return 4


@dataclass(frozen=True)
class PhpVersion:
    major: int
    minor: int
    patch: int | None
    pre: str | None
    raw: str
    deb: DebVersion | None = None

    @property
    def branch(self) -> str:
        return f"{self.major}.{self.minor}"

    @property
    def complete(self) -> bool:
        return self.patch is not None

    @property
    def normalized(self) -> str:
        base = f"{self.major}.{self.minor}"
        if self.patch is not None:
            base += f".{self.patch}"
        if self.pre:
            base += self.pre
        return base

    @property
    def revision(self) -> str | None:
        return self.deb.revision if self.deb is not None else None

    @property
    def exact_input(self) -> str:
        return self.deb.raw if self.deb is not None else self.raw

    def key(self) -> tuple[int, int, int, int]:
        return (self.major, self.minor,
                self.patch if self.patch is not None else -1,
                _pre_rank(self.pre))


def parse_php_version(text: str) -> PhpVersion:
    s = text.strip()
    if not s:
        raise InputError("empty PHP version")
    m = _PHP_RE.match(s)
    if not m:
        raise InputError(f"cannot parse PHP version {text!r}")
    maj = int(m.group("maj"))
    minor = int(m.group("min"))
    pat_s = m.group("pat")
    patch = int(pat_s) if pat_s is not None else None
    rest = m.group("rest") or ""
    pre: str | None = None
    deb: DebVersion | None = None

    if rest:
        # A numeric revision (-1, -1~deb13u1, -0ubuntu1.5) is a package
        # version.  A leading -dev / RC suffix is a PHP pre-release.
        rev_like = rest.startswith(("-", "~", "+")) and (
            len(rest) == 1 or rest[1].isdigit()
        )
        if rev_like:
            deb = parse_deb_version(s)
            # The upstream part of the Debian version must agree with the
            # parsed components.
            up = deb.upstream
            if not re.match(rf"^{maj}\.{minor}(?:\.{patch})?$", up):
                if not up.startswith(f"{maj}.{minor}."):
                    raise InputError(f"inconsistent package version {text!r}")
        else:
            p = rest.lstrip("-~+ ").lower()
            if p and _PRE_RE.match(p):
                pre = p
            else:
                raise InputError(f"trailing text in PHP version {text!r}")

    if patch is None:
        # Allow a package version such as 8.4-1~deb13u1; exact patch is
        # unknown, and the classifier will report UNKNOWN.
        pass
    return PhpVersion(maj, minor, patch, pre, s, deb)


def php_compare(a: PhpVersion, b: PhpVersion) -> int:
    ka, kb = a.key(), b.key()
    return (ka > kb) - (ka < kb)


# ---------------------------------------------------------------------------
# Distro parsing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Distro:
    key: str
    family: str
    release: str
    codename: str

    @property
    def display(self) -> str:
        if self.family == "ubuntu":
            return f"Ubuntu {self.release} ({self.codename})"
        if self.family == "debian":
            return f"Debian {self.release} ({self.codename})"
        return self.key


_DISTRO_TABLE: dict[str, Distro] = {}


def _add_distro(key: str, family: str, release: str, codename: str,
                aliases: Iterable[str]) -> None:
    d = Distro(key, family, release, codename)
    _DISTRO_TABLE[key] = d
    _DISTRO_TABLE[key.replace(".", "")] = d
    for a in aliases:
        _DISTRO_TABLE[a] = d


_add_distro("debian13", "debian", "13", "trixie",
            ("debian-13", "debian:13", "trixie", "debian/trixie", "debian 13"))
_add_distro("debian12", "debian", "12", "bookworm",
            ("debian-12", "debian:12", "bookworm", "debian/bookworm", "debian 12"))
_add_distro("debian11", "debian", "11", "bullseye",
            ("debian-11", "debian:11", "bullseye", "debian/bullseye", "debian 11"))
_add_distro("debian10", "debian", "10", "buster",
            ("debian-10", "debian:10", "buster", "debian/buster", "debian 10"))
_add_distro("ubuntu26.04", "ubuntu", "26.04", "resolute",
            ("ubuntu2604", "ubuntu-26.04", "ubuntu:26.04", "resolute",
             "ubuntu 26.04", "ubuntu/resolute"))
_add_distro("ubuntu26.10", "ubuntu", "26.10", "stonking",
            ("ubuntu2610", "ubuntu-26.10", "ubuntu:26.10", "stonking",
             "ubuntu 26.10", "ubuntu/stonking"))
_add_distro("ubuntu24.04", "ubuntu", "24.04", "noble",
            ("ubuntu2404", "ubuntu-24.04", "ubuntu:24.04", "noble",
             "ubuntu 24.04", "ubuntu/noble"))
_add_distro("ubuntu22.04", "ubuntu", "22.04", "jammy",
            ("ubuntu2204", "ubuntu-22.04", "ubuntu:22.04", "jammy",
             "ubuntu 22.04", "ubuntu/jammy"))
_add_distro("ubuntu20.04", "ubuntu", "20.04", "focal",
            ("ubuntu2004", "ubuntu-20.04", "ubuntu:20.04", "focal",
             "ubuntu 20.04", "ubuntu/focal"))
_add_distro("ubuntu18.04", "ubuntu", "18.04", "bionic",
            ("ubuntu1804", "ubuntu-18.04", "ubuntu:18.04", "bionic",
             "ubuntu 18.04", "ubuntu/bionic"))
_add_distro("ubuntu16.04", "ubuntu", "16.04", "xenial",
            ("ubuntu1604", "ubuntu-16.04", "ubuntu:16.04", "xenial",
             "ubuntu 16.04", "ubuntu/xenial"))


def parse_distro(text: str) -> Distro:
    s = text.strip().lower()
    if s in _DISTRO_TABLE:
        return _DISTRO_TABLE[s]
    compact = re.sub(r"[\s_\-/:]+", "", s)
    for key, d in _DISTRO_TABLE.items():
        if re.sub(r"[\s_\-/:]+", "", key) == compact:
            return d
    known = ", ".join(sorted(set(d.key for d in _DISTRO_TABLE.values())))
    raise InputError(f"unknown distro {text!r}; known: {known}")


def infer_distro_from_revision(revision: str) -> tuple[Distro | None, str | None]:
    """Return (distro, repo) inferred from a package revision, if possible."""
    repo = None
    if "+0~" in revision or "sury" in revision.lower():
        repo = "sury"
    m = re.search(r"~deb(\d+)u\d*", revision)
    if m:
        key = f"debian{m.group(1)}"
        if key in _DISTRO_TABLE:
            return _DISTRO_TABLE[key], repo
        return None, repo
    m = re.search(r"0ubuntu(?:0?\.)?(\d+\.\d+)", revision)
    if m:
        key = f"ubuntu{m.group(1)}"
        if key in _DISTRO_TABLE:
            return _DISTRO_TABLE[key], repo
    if "ubuntu" in revision.lower() or "+esm" in revision.lower():
        # Ubuntu, but the release is not encoded in this revision.
        return None, repo or "ubuntu"
    return None, repo


def revision_family(revision: str | None) -> str:
    if not revision:
        return "none"
    if re.search(r"~deb\d+u\d*", revision):
        return "deb" + re.search(r"~deb(\d+)u", revision).group(1)
    if "ubuntu" in revision.lower():
        return "ubuntu"
    if "+0~" in revision or "sury" in revision.lower():
        return "sury"
    if "+esm" in revision.lower():
        return "ubuntu-esm"
    return "generic"


def revision_looks_like_package(text: str) -> bool:
    return bool(re.match(r"^\d+\.\d+(?:\.\d+)?-", text.strip()))


# ---------------------------------------------------------------------------
# CVE data (encoded from existing evidence; see sources per entry)
# ---------------------------------------------------------------------------

# CVE-2026-109618 / 109619: same fixed releases, different producer/consumer.
SESSION_FIXED: dict[str, str] = {
    "8.2": "8.2.35",
    "8.3": "8.3.36",
    "8.4": "8.4.27",
    "8.5": "8.5.12",
}
# Branches covered by the advisory (affected >= 5.4.0) but with no fixed
# release: EOL lines.  They remain candidates, never FIXED.
SESSION_EOL_BRANCHES = frozenset({
    "5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1",
})

# CVE-2026-6722: SOAP apache:Map UAF.  Fixed in these releases.
SOAP_FIXED: dict[str, str] = {
    "8.2": "8.2.31",
    "8.3": "8.3.31",
    "8.4": "8.4.21",
    "8.5": "8.5.6",
}

# CVE-2019-11043: PHP-FPM PATH_INFO underflow, 7.1.0-7.3.10 only.
PATHINFO_FIXED: dict[str, str] = {
    "7.1": "7.1.33",
    "7.2": "7.2.24",
    "7.3": "7.3.11",
}

# (cve, distro_key, branch) -> (fixed package version, advisory)
# Only exact, evidenced mappings.  A missing entry means "not mapped",
# which the classifier treats as UNKNOWN when the upstream version is below
# the upstream fix (a distro backport may exist).
DISTRO_FIXES: dict[tuple[str, str, str], tuple[str, str]] = {}

def _df(cve: str, distro: str, branch: str, fixed: str, advisory: str) -> None:
    DISTRO_FIXES[(cve, distro, branch)] = (fixed, advisory)

for _cve in ("CVE-2026-109618", "CVE-2026-109619"):
    # Debian (USN/DSA trackers, 2026-10-21/22)
    _df(_cve, "debian13", "8.4", "8.4.27-1~deb13u1", "DSA-6574-1")
    _df(_cve, "debian12", "8.2", "8.2.35-1~deb12u1", "DLA-4848-1")
    # Ubuntu (USN-8948-1/-2)
    _df(_cve, "ubuntu26.10", "8.5", "8.5.9-0ubuntu2.1", "USN-8948-1/-2")
    _df(_cve, "ubuntu26.04", "8.5", "8.5.4-0ubuntu1.5", "USN-8948-1/-2")
    _df(_cve, "ubuntu24.04", "8.3", "8.3.6-0ubuntu0.24.04.13", "USN-8948-1/-2")
    _df(_cve, "ubuntu22.04", "8.1", "8.1.2-1ubuntu2.28", "USN-8948-1/-2")
    _df(_cve, "ubuntu20.04", "7.4", "7.4.3-4ubuntu2.29+esm5", "USN-8948-1/-2 (ESM)")
    _df(_cve, "ubuntu18.04", "7.2", "7.2.24-0ubuntu0.18.04.17+esm14", "USN-8948-1/-2 (ESM)")
    _df(_cve, "ubuntu16.04", "7.0", "7.0.33-0ubuntu0.16.04.16+esm22", "USN-8948-1/-2 (ESM)")


@dataclass(frozen=True)
class CveDef:
    id: str
    title: str
    kind: str
    fixed: dict[str, str]
    min_affected: str
    max_branch: str | None
    sapi_scope: dict[str, str]
    sources: tuple[str, ...]
    data_note: str

    def fixed_for(self, branch: str) -> str | None:
        return self.fixed.get(branch)


_SESSION_SCOPE = {
    "mod_php": "applicable",
    "fpm": "applicable",
    "apache_fpm": "applicable",
    "nginx_fpm": "applicable",
    "iis_fastcgi": "unknown",
    "cli": "not_affected",
    "unknown": "applicable",
}
_PATHINFO_SCOPE = {
    "mod_php": "not_affected",
    "fpm": "applicable",
    "apache_fpm": "unknown",
    "nginx_fpm": "applicable",
    "iis_fastcgi": "unknown",
    "cli": "not_affected",
    "unknown": "applicable",
}
_SOAP_SCOPE = {s: "applicable" for s in SAPI_CHOICES}
_SESSINJ_SCOPE = {
    "mod_php": "applicable",
    "fpm": "applicable",
    "apache_fpm": "applicable",
    "nginx_fpm": "applicable",
    "iis_fastcgi": "applicable",
    "cli": "not_affected",
    "unknown": "applicable",
}

CVES: tuple[CveDef, ...] = (
    CveDef(
        id="CVE-2026-109618",
        title=("Session upload-progress producer: request-owned state survives "
               "an interrupted request (UAF; lab RCE on mod_php 8.4.x; "
               "8.4.1-8.4.7/8.4.10-8.4.26 with php.ini-production mounted)"),
        kind="session",
        fixed=SESSION_FIXED,
        min_affected="5.4.0",
        max_branch=None,
        sapi_scope=_SESSION_SCOPE,
        sources=(
            "php2slop:README.md",
            "private receipt not shipped (parent-session lab evidence)",
            "external:phpshell/modphp_84_matrix_20261023T074116Z/report.md",
            "external:phpshell/build_coverage_20261023T074532Z/report.md",
            "external:phpshell/fpm_80x_chain_20261023T085337Z/report.md",
        ),
        data_note=("mod_php: 8.4.1-8.4.7 and 8.4.10-8.4.26 lab chains mount "
                   "php.ini-production; 8.4.8 uses a separate big78 A1 + Q5 "
                   "shape. Early offsets differ (8.4.1-8.4.7 S=main+0xED398, "
                   "8.4.8 S=main+0xE8398); do not reuse 8.4.10+ offsets. The "
                   "bare image ships no active INI; without the production INI "
                   "the chain is unreachable. 8.4.27 fixed. 8.5.0/5 leak-only; "
                   "8.5.11 A1+B1 leak only (no uid, no libphp pointer, no 8.4-style main-chunk "
                   "bucket); 8.5.12 fixed. mod_php 8.2.34/8.3.35 full lab chain "
                   "with target-written uid; receipt not shipped. FPM: the "
                   "stale-session-id chain is not claimed; 8.4.26 Path C belongs "
                   "to CVE-2026-109619 and needs documented non-default changes; "
                   "8.5.11 single-worker cell is not a completed RCE; not counted."),
    ),
    CveDef(
        id="CVE-2026-109619",
        title=("Session upload-progress consumer: stale decoder state "
               "consumed before RINIT (UAF; lab RCE on mod_php 8.4.x; "
               "8.4.1-8.4.7/8.4.10-8.4.26 with php.ini-production mounted)"),
        kind="session",
        fixed=SESSION_FIXED,
        min_affected="5.4.0",
        max_branch=None,
        sapi_scope=_SESSION_SCOPE,
        sources=(
            "php2slop:README.md",
            "private receipt not shipped (parent-session lab evidence)",
            "external:phpshell/modphp_84_matrix_20261023T074116Z/report.md",
            "external:phpshell/build_coverage_20261023T074532Z/report.md",
            "external:phpshell/fpm_aslr_20261023T073345Z/report.md",
        ),
        data_note=("mod_php: 8.4.1-8.4.7 and 8.4.10-8.4.26 lab chains mount "
                   "php.ini-production; 8.4.8 uses a separate big78 A1 + Q5 "
                   "shape. Early offsets differ (8.4.1-8.4.7 S=main+0xED398, "
                   "8.4.8 S=main+0xE8398); do not reuse 8.4.10+ offsets. The "
                   "bare image ships no active INI; without the production INI "
                   "the chain is unreachable. 8.4.27 fixed. 8.5.0/5 leak-only; "
                   "8.5.11 A1+B1 leak only (no uid, no libphp pointer, no 8.4-style main-chunk "
                   "bucket); 8.5.12 fixed. mod_php 8.2.34/8.3.35 full lab chain "
                   "with target-written uid; receipt not shipped. FPM: 8.4.26 Path C "
                   "RCE only with the documented non-default changes; the "
                   "stale-session-id FPM chain is not claimed; 8.5.11 "
                   "single-worker cell is not a completed RCE; not counted."),
    ),
    CveDef(
        id="CVE-2019-11043",
        title="PHP-FPM PATH_INFO env underflow (nginx config-dependent RCE)",
        kind="pathinfo",
        fixed=PATHINFO_FIXED,
        min_affected="7.1.0",
        max_branch="7.3",
        sapi_scope=_PATHINFO_SCOPE,
        sources=(
            "external:phpshell/fpm_alt_cves_20261023T084756Z/report.md",
            "external:phpshell/fpm_11043_targets_20261023T085412Z/report.md",
            "external:phpshell/web_fpm_defaults_20261023T125235Z/report.md",
        ),
        data_note=("FPM + nginx only; fixed 7.1.33/7.2.24/7.3.11; PHP >= 7.4 "
                   "not affected. Exploitability is configuration-dependent."),
    ),
    CveDef(
        id="CVE-2026-6722",
        title="SOAP apache:Map use-after-free (UAF/crash in lab; advisory claims RCE)",
        kind="soap",
        fixed=SOAP_FIXED,
        min_affected="8.2.0",
        max_branch=None,
        sapi_scope=_SOAP_SCOPE,
        sources=(
            "external:phpshell/fpm_alt_cves_20261023T084756Z/gh_php_advisories.json",
            "external:parent-session lab evidence 2026-10-23 (UAF/crash only)",
        ),
        data_note=("Fixed 8.2.31/8.3.31/8.4.21/8.5.6. Lab evidence reached UAF/"
                   "crash only, not controlled RCE. Requires ext-soap."),
    ),
    CveDef(
        id="CVE-2026-115560",
        title="Session object injection via upload-progress state",
        kind="session_injection",
        fixed={},
        min_affected="5.4.0",
        max_branch=None,
        sapi_scope=_SESSINJ_SCOPE,
        sources=(
            "external:parent-session evidence 2026-10-23 (no fix as of 2026-10-25)",
            "external:phpshell/receipts/phpsessinj_1022/README.md",
        ),
        data_note=("No fix as of 2026-10-25. Stock session.upload_progress."
                   "cleanup=1 blocks the demonstrated path; cleanup=0 is "
                   "required. Serializer/deployment preconditions apply."),
    ),
)


def cve_by_id(cve_id: str) -> CveDef:
    for c in CVES:
        if c.id == cve_id:
            return c
    raise KeyError(cve_id)


# ---------------------------------------------------------------------------
# Target / package parsing
# ---------------------------------------------------------------------------

@dataclass
class Package:
    name: str
    raw: str
    deb: DebVersion
    version: PhpVersion
    arch: str | None = None
    branch_hint: str | None = None
    sapi_hint: str | None = None


@dataclass
class Target:
    version: PhpVersion
    sapi: str = "unknown"
    distro: Distro | None = None
    package: Package | None = None
    repo: str | None = None
    version_source: str = "argument"
    fingerprint: dict[str, Any] | None = None
    warnings: list[str] = field(default_factory=list)


_PKG_BRANCH_RE = re.compile(r"php(\d+)\.(\d+)", re.IGNORECASE)


def _package_sapi_hint(name: str) -> str | None:
    n = name.lower()
    if "libapache2-mod-php" in n or re.match(r"^php\d+\.\d+-apache2$", n):
        return "mod_php"
    if re.match(r"^php\d+\.\d+-fpm$", n):
        return "fpm"
    if re.match(r"^php\d+\.\d+-cli$", n):
        return "cli"
    if re.match(r"^php\d+\.\d+-cgi$", n):
        return None  # CGI/FastCGI depends on the front end
    return None


def parse_package(text: str) -> Package:
    if "=" not in text:
        raise InputError(
            "--package requires NAME=VERSION, e.g. "
            "'libapache2-mod-php8.4=8.4.24-1~deb13u1'"
        )
    name, rawver = text.split("=", 1)
    name = name.strip()
    rawver = rawver.strip()
    if not name or not rawver:
        raise InputError(f"bad --package {text!r}")
    arch = None
    if ":" in name:
        name, arch = name.rsplit(":", 1)
    deb = parse_deb_version(rawver)
    try:
        ver = parse_php_version(deb.upstream)
    except InputError as exc:
        raise InputError(f"--package version {rawver!r}: {exc}") from exc
    hint = None
    m = _PKG_BRANCH_RE.search(name)
    if m:
        hint = f"{int(m.group(1))}.{int(m.group(2))}"
    return Package(
        name=name,
        raw=rawver,
        deb=deb,
        version=ver,
        arch=arch,
        branch_hint=hint,
        sapi_hint=_package_sapi_hint(name),
    )


def _same_upstream(a: PhpVersion, b: PhpVersion) -> bool:
    return (a.major, a.minor, a.patch) == (b.major, b.minor, b.patch)


def _v_lt(a: PhpVersion, b: PhpVersion) -> bool:
    return php_compare(a, b) < 0


def _v_le(a: PhpVersion, b: PhpVersion) -> bool:
    return php_compare(a, b) <= 0


def _v_ge(a: PhpVersion, b: PhpVersion) -> bool:
    return php_compare(a, b) >= 0


def _v_in(a: PhpVersion, lo: str, hi: str) -> bool:
    return _v_ge(a, parse_php_version(lo)) and _v_le(a, parse_php_version(hi))


def _parse_opt_version(text: str | None) -> PhpVersion | None:
    if not text:
        return None
    return parse_php_version(text)


def build_identity(target: Target) -> str:
    if target.package is not None:
        p = target.package
        prefix = target.distro.key + "/" if target.distro is not None else ""
        repo = f" [{target.repo}]" if target.repo else ""
        return f"{prefix}{p.name}={p.raw}{repo}"
    if target.fingerprint and target.fingerprint.get("php_version"):
        return "unknown (fingerprinted from headers; no package/build string)"
    return "unknown (upstream version only; pass --package for a build identity)"


def _distro_fix(cve: CveDef, target: Target) -> tuple[str, str] | None:
    if target.distro is None or target.version.patch is None:
        return None
    if target.repo == "sury":
        return None
    return DISTRO_FIXES.get((cve.id, target.distro.key, target.version.branch))


def _all_distro_fixes(cve: CveDef, branch: str) -> list[tuple[str, str, str]]:
    out = []
    for (cid, distro_key, br), (fixed, advisory) in DISTRO_FIXES.items():
        if cid == cve.id and br == branch:
            out.append((distro_key, fixed, advisory))
    out.sort(key=lambda t: t[0])
    return out


def _fixed_match_for_version(cve: CveDef, target: Target) -> tuple[str, str, str] | None:
    """Exact/family package-revision match when --distro is absent.

    Returns (distro_key, fixed_version, advisory).  We only compare revisions
    from the same packaging family (0ubuntu..., ~deb13u..., etc.) so a Debian
    and an Ubuntu package with the same upstream are never cross-compared.
    """
    if target.version.deb is None:
        return None
    fam = revision_family(target.version.revision)
    if fam in ("none", "generic", "sury"):
        return None
    for distro_key, fixed, advisory in _all_distro_fixes(cve, target.version.branch):
        fd = parse_deb_version(fixed)
        if _verrevcmp(target.version.deb.upstream, fd.upstream) != 0:
            continue
        if revision_family(fd.revision) != fam:
            continue
        return distro_key, fixed, advisory
    return None


# ---------------------------------------------------------------------------
# Verdicts and conditions
# ---------------------------------------------------------------------------

@dataclass
class Verdict:
    cve: CveDef
    status: str
    basis: str
    evidence: str
    evidence_detail: str
    conditions: list[dict[str, str]]
    notes: list[str]
    stock_blocked: bool = False
    distro_basis: str | None = None


def _cond(cid: str, state: str, detail: str) -> dict[str, str]:
    return {"id": cid, "state": state, "detail": detail}


def _is(v: PhpVersion, text: str) -> bool:
    o = parse_php_version(text)
    return (v.major, v.minor, v.patch) == (o.major, o.minor, o.patch)


def _is_any(v: PhpVersion, *texts: str) -> bool:
    return any(_is(v, t) for t in texts)


def _session_conditions(cve: CveDef, target: Target) -> list[dict[str, str]]:
    sapi = target.sapi
    out: list[dict[str, str]] = []
    if sapi == "mod_php":
        out.append(_cond("sapi=mod_php", "required",
                         "Apache prefork/mod_php with a persistent worker"))
        out.append(_cond("session.upload_progress.enabled=1", "required",
                         "compiled default; the upload-progress path is the consumer"))
        out.append(_cond("output_buffering=4096", "required",
                         "measured lab ini on the 8.4.x chain"))
        out.append(_cond("session.upload_progress.cleanup=0", "required",
                         "lab override; stock cleanup=1 removes the progress record early"))
        out.append(_cond("same worker for producer and consumer", "required",
                         "cross-request UAF; the lab pinned pm=static"))
        out.append(_cond("memory_limit tight enough to OOM on the body", "required",
                         "e.g. 128M with the 1.06 MB A1 body"))
        if _v_in(target.version, "8.4.1", "8.4.7"):
            offsets_detail = ("zif_system/zval_ptr_dtor; 8.4.1-8.4.7 use "
                              "S=main+0xED398 with the 5-query-param A1")
        elif _is(target.version, "8.4.8"):
            offsets_detail = ("zif_system/zval_ptr_dtor; 8.4.8 uses "
                              "S=main+0xE8398 with the big78 A1 + Q5")
        else:
            offsets_detail = ("zif_system/zval_ptr_dtor; Debian 8.4.24 uses "
                              "fillers=116 and S=main+0xF7398")
        out.append(_cond("per-build symbol offsets", "required", offsets_detail))
        if (_v_in(target.version, "8.4.1", "8.4.7")
                or _v_in(target.version, "8.4.10", "8.4.26")):
            out.append(_cond("php.ini-production mounted (lab)", "required",
                             "the 8.4.1-8.4.7 and 8.4.10-8.4.26 lab chains mount "
                             "php.ini-production; the bare image ships no active "
                             "INI; without the production INI the chain is "
                             "unreachable, so this is not a bare-default proof"))
    elif sapi in FPM_SAPIS:
        out.append(_cond("sapi in {fpm,nginx_fpm,apache_fpm}", "required",
                         f"reported SAPI is {sapi}; FPM family only"))
        out.append(_cond("app-reachable fatal after successful startup", "required",
                         "FPM terminates a child on startup failure; the producer needs an application-path fatal/OOM"))
        out.append(_cond("same worker for producer and consumer", "required",
                         "per-worker state; dynamic/static pool must reuse the worker"))
        out.append(_cond("session.upload_progress.enabled=1", "required",
                         "compiled default; consumer path"))
        out.append(_cond("session.upload_progress.cleanup=0", "required",
                         "lab override; needed for the stored progress record"))
        out.append(_cond("output_buffering=4096", "default",
                         "measured lab ini; not universal, verify the target"))
        out.append(_cond("nginx body cap admits the producer body", "required",
                         "stock nginx client_max_body_size=1m: the 1,060,211 B A1 gets 413; raise the cap or use a smaller body"))
        out.append(_cond("tight memory_limit / post_max_size", "required",
                         "must reach the parser or END-cleanup OOM"))
        if cve.id == "CVE-2026-109619":
            if _is(target.version, "8.5.11"):
                out.append(_cond("known target address + app trigger", "required",
                                 "the non-default 8.5.11 single-worker cell is not a "
                                 "completed RCE and is not counted as an RCE claim; "
                                 "the default pm=dynamic pool is leak only"))
            elif _is(target.version, "8.4.26"):
                out.append(_cond("Path C non-default changes", "required",
                                 "RCE demonstrated only with cleanup=Off, a lowered "
                                 "memory_limit, a raised max_input_vars, a writable "
                                 "executable docroot, a pre-seeded session, and one "
                                 "worker/pool affinity; the stale-session-id FPM "
                                 "chain is not claimed"))
    else:
        out.append(_cond("persistent worker SAPI", "required",
                         f"SAPI {sapi} was not verified; mod_php/FPM expected"))
        out.append(_cond("session.upload_progress.enabled=1", "required",
                         "compiled default; consumer path"))
        out.append(_cond("session.upload_progress.cleanup=0", "required",
                         "stock cleanup=1 removes the progress record early"))
        out.append(_cond("output_buffering=4096", "default",
                         "measured lab ini; not universal, verify the target"))
        out.append(_cond("same worker for producer and consumer", "required",
                         "cross-request UAF"))
    if cve.id == "CVE-2026-109618":
        out.append(_cond("producer", "required",
                         "an interrupted request (OOM/parse/uncaught error/timeout) after request-owned state is published"))
    else:
        out.append(_cond("consumer", "required",
                         "a later PHP_SESSION_UPLOAD_PROGRESS multipart request on the same worker; no session_start() needed"))
    return out


def _pathinfo_conditions(target: Target) -> list[dict[str, str]]:
    return [
        _cond("sapi=fpm (nginx front end)", "required",
              f"reported SAPI is {target.sapi}; bug is in fpm_main.c PATH_INFO handling"),
        _cond("nginx location ~ [^/]\\.php(/|$)", "required",
              "documented nginx PHP location shape"),
        _cond("fastcgi_split_path_info anchored ^...$", "required",
              "plus fastcgi_param PATH_INFO $fastcgi_path_info"),
        _cond("no script-existence check", "required",
              "no try_files $uri =404 and no if (-f ...) before fastcgi_pass"),
        _cond("cgi.fix_pathinfo=1", "default", "default; the bug needs the PATH_INFO path"),
        _cond("EOL PHP 7.1-7.3", "context",
              "fixed 7.1.33/7.2.24/7.3.11; PHP >= 7.4 is not affected"),
    ]


def _soap_conditions(target: Target) -> list[dict[str, str]]:
    return [
        _cond("ext-soap loaded", "required",
              "the extension must be present in the build"),
        _cond("reachable SoapServer endpoint", "required",
              "an application route that calls SoapServer::handle()"),
        _cond("attacker-controlled SOAP XML", "required",
              "apache:Map with id/href graph, as in the advisory PoC"),
        _cond("UAF/crash only in lab", "observed",
              "lab evidence reached UAF/crash, not controlled RCE; the advisory claims RCE"),
        _cond("no authentication required", "context",
              "the crash primitive needs only the XML body"),
    ]


def _sessinj_conditions(target: Target) -> list[dict[str, str]]:
    return [
        _cond("session.upload_progress.cleanup=0", "required",
              "stock cleanup=1 removes the progress record and blocks the demonstrated path"),
        _cond("session.upload_progress.enabled=1", "required",
              "compiled default; upload-progress writes the record"),
        _cond("serializer mismatch and shared save_path", "required",
              "php_serialize writer pool and php reader pool must share save_path"),
        _cond("attacker-chosen SID accepted", "required",
              "use_strict_mode=0; a SID set through a body field works with use_only_cookies=On"),
        _cond("application session_start() + autoloader", "required",
              "the sink must decode the record with an autoloader registered before session_start()"),
        _cond("stock cleanup=1", "blocking",
              "the stock default blocks this path; cleanup=0 is an explicit misconfiguration/override"),
    ]


def _conditions(cve: CveDef, target: Target) -> list[dict[str, str]]:
    if cve.kind == "session":
        return _session_conditions(cve, target)
    if cve.kind == "pathinfo":
        return _pathinfo_conditions(target)
    if cve.kind == "soap":
        return _soap_conditions(target)
    return _sessinj_conditions(target)


def _session_evidence(cve: CveDef, target: Target) -> tuple[str, str]:
    v = target.version
    if target.sapi == "mod_php":
        if _v_in(v, "8.4.10", "8.4.26"):
            return ("measured-rce",
                    "lab chain measured on upstream mod_php 8.4.10-8.4.26 "
                    "(and Debian 13 8.4.24 package) with php.ini-production "
                    "mounted; the bare image ships no active INI; without the "
                    "production INI the chain is unreachable; per-build offsets "
                    "required")
        if _is(v, "8.5.11"):
            return ("measured-leak-only",
                    "A1+B1 leak only; no uid; no libphp pointer; "
                    "no 8.4-style main-chunk bucket; not a full chain")
        if _is_any(v, "8.5.0", "8.5.5"):
            return ("measured-leak-only",
                    "leak only; no libphp code pointers; "
                    "no controlled destructor/portable chain")
        if _is_any(v, "8.2.34", "8.3.35"):
            return ("measured-lab-chain",
                    "full chain demonstrated in lab on mod_php 8.2.34/8.3.35 "
                    "with target-written uid; 8.2.35/8.3.36 fixed controls are "
                    "clean; public receipt not shipped")
        if v.branch in ("8.0", "8.1", "8.2", "8.3"):
            return ("range-only",
                    "no per-build chain encoded for this exact 8.0-8.3 build; "
                    "see php2slop:README.md for the per-build matrix")
        if _v_in(v, "8.4.1", "8.4.7"):
            return ("measured-rce",
                    "per-build measured, not a range extrapolation: stage-1 A1 "
                    "with 5 query params, S=main+0xED398; target-written "
                    "uid=33(www-data) in three harnesses (diagnostic, default "
                    "prefork 5/150, WordPress); 149-holder pin; "
                    "php.ini-production mounted")
        if _is(v, "8.4.8"):
            return ("measured-rce",
                    "separate official big78 A1 + Q5 shape, S=main+0xE8398; "
                    "target-written uid; direct Apache and pure-HTTP variants; "
                    "per-build measured")
    if target.sapi in FPM_SAPIS:
        if _is(v, "8.5.11"):
            return ("leak-only",
                    "leak only under the default pm=dynamic pool; no uid, no "
                    "libphp pointer; the non-default single-worker known-target "
                    "cell is not a completed RCE and is not counted as an RCE claim")
        if _is_any(v, "8.4.26", "8.5.10"):
            if cve.id == "CVE-2026-109618":
                if _is(v, "8.4.26"):
                    return ("measured-primitive",
                            "no stale-session-id FPM chain; 8.4.26 RCE is not "
                            "claimed on this chain (109619 Path C is separate and "
                            "non-default)")
                return ("range-only",
                        "stale-session-id FPM chain not claimed on this build")
            if _is(v, "8.4.26"):
                return ("path-c-non-default",
                        "Path C RCE demonstrated only with the documented "
                        "non-default changes (cleanup=Off, lowered memory_limit, "
                        "raised max_input_vars, writable executable docroot, "
                        "pre-seeded session, one worker/pool affinity); "
                        "stale-session-id FPM chain not claimed")
            return ("range-only",
                    "Path C inconclusive on this build; no FPM chain claimed")
        if _is_any(v, "8.2.34", "8.3.35"):
            return ("measured-oom-only",
                    "stale-session-id chain: producer OOM / child exit 70, no "
                    "consumer/RCE on that chain (Path C is separate and non-default)")
    return ("range-only",
            "version-range candidate only for this SAPI; no primitive measured here")


def _evidence(cve: CveDef, target: Target, status: str) -> tuple[str, str]:
    if status == STATUS_UNKNOWN:
        return "insufficient-data", "no encoded evidence covers this exact build/scope"
    if status == STATUS_FIXED:
        return "fixed", "version/package revision is at or above a known fixed release"
    if status == STATUS_NOT_AFFECTED:
        return "not-in-scope", "version or SAPI is outside the affected scope"
    if cve.kind == "session":
        return _session_evidence(cve, target)
    if cve.kind == "pathinfo":
        if status == STATUS_CANDIDATE:
            return ("measured-config-dependent",
                    "lab reproduction on PHP 7.3.9 Debian 10; exploitability is nginx-config-dependent")
        return "not-in-scope", "outside the 7.1-7.3 FPM window"
    if cve.kind == "soap":
        if status == STATUS_CANDIDATE:
            return ("measured-crash-only",
                    "lab evidence reached UAF/crash only; controlled RCE was not demonstrated")
        return "not-in-scope", "outside the encoded SOAP fixed ranges"
    if cve.kind == "session_injection":
        return ("range-only-no-fix",
                f"no fixed release as of {AS_OF}; cleanup=0 and deployment preconditions required")
    return "range-only", "version-range candidate only"


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _refine_candidate(cve: CveDef, target: Target,
                      fixed_upstream_s: str) -> tuple[str, str, str | None]:
    """Refine a below-upstream-fix version with distro/package revisions."""
    v = target.version
    fixed_upstream = parse_php_version(fixed_upstream_s)

    dfix = _distro_fix(cve, target)
    if dfix is not None:
        fixed_pkg, advisory = dfix
        fd = parse_deb_version(fixed_pkg)
        fup = parse_php_version(fd.upstream)
        dbasis = f"{target.distro.display} fixed package: {fixed_pkg} ({advisory})"
        if v.deb is not None:
            if _same_upstream(v, fup):
                cmp = deb_compare(v.deb, fixed_pkg)
                if cmp >= 0:
                    return (STATUS_FIXED,
                            f"package {v.deb.raw} >= fixed {fixed_pkg}", dbasis)
                return (STATUS_CANDIDATE,
                        f"package {v.deb.raw} < fixed {fixed_pkg}", dbasis)
            if _v_lt(v, fup):
                return (STATUS_CANDIDATE,
                        f"upstream {v.normalized} < distro-fixed upstream {fup.normalized}",
                        dbasis)
            return (STATUS_UNKNOWN,
                    f"distro fix is mapped to upstream {fup.normalized}; this build is "
                    f"{v.normalized} (verify the distro CVE tracker)", dbasis)
        if _v_lt(v, fup):
            return (STATUS_CANDIDATE,
                    f"upstream {v.normalized} < distro-fixed upstream {fup.normalized}; "
                    "exact package revision not supplied", dbasis)
        if _same_upstream(v, fup):
            return (STATUS_UNKNOWN,
                    "exact package revision required: the distro fixed revision is for "
                    "this upstream version", dbasis)
        return (STATUS_UNKNOWN,
                f"distro fix is mapped to upstream {fup.normalized}", dbasis)

    if target.distro is None:
        match = _fixed_match_for_version(cve, target)
        if match is not None:
            dk, fixed_pkg, advisory = match
            dbasis = f"{dk} fixed package: {fixed_pkg} ({advisory})"
            cmp = deb_compare(v.deb, fixed_pkg) if v.deb is not None else -1
            if cmp >= 0:
                return (STATUS_FIXED,
                        f"package {v.deb.raw} >= fixed {fixed_pkg}", dbasis)
            return (STATUS_CANDIDATE,
                    f"package {v.deb.raw} < fixed {fixed_pkg}", dbasis)
        return (STATUS_CANDIDATE,
                f"upstream {v.normalized} < fixed {fixed_upstream.normalized}", None)

    return (STATUS_UNKNOWN,
            "distro backport not mapped; exact package revision required "
            "(supply --package or a full distro version)", None)


def classify(cve: CveDef, target: Target) -> Verdict:
    v = target.version
    notes: list[str] = [cve.data_note]

    if not v.complete:
        return Verdict(cve, STATUS_UNKNOWN,
                       "exact patch version is required (got a branch-only version)",
                       "insufficient-input", "version has no patch component",
                       [], notes)

    # Version-level hard scope first.
    if cve.kind == "pathinfo":
        if cve.max_branch is not None and v.branch > cve.max_branch:
            return Verdict(cve, STATUS_NOT_AFFECTED,
                           f"PHP {v.branch} is after the 7.3 line; CVE-2019-11043 "
                           "was fixed before 7.4 and is not present",
                           "not-in-scope", "PHP >= 7.4", [], notes)
        if _v_lt(v, parse_php_version(cve.min_affected)):
            return Verdict(cve, STATUS_NOT_AFFECTED,
                           f"PHP {v.normalized} is before the affected 7.1.0 window",
                           "not-in-scope", "PHP < 7.1", [], notes)

    if cve.kind == "session" and _v_lt(v, parse_php_version(cve.min_affected)):
        return Verdict(cve, STATUS_NOT_AFFECTED,
                       f"PHP {v.normalized} is before the advisory's >= {cve.min_affected} range",
                       "not-in-scope", "outside the encoded affected range", [], notes)

    if cve.kind == "session_injection" and _v_lt(v, parse_php_version(cve.min_affected)):
        return Verdict(cve, STATUS_NOT_AFFECTED,
                       f"PHP {v.normalized} predates session upload progress",
                       "not-in-scope", "outside the encoded affected range", [], notes)

    branch = v.branch
    fixed_s = cve.fixed.get(branch)
    distro_basis: str | None = None

    if fixed_s is not None:
        fixed = parse_php_version(fixed_s)
        if _v_ge(v, fixed):
            status = STATUS_FIXED
            basis = f"upstream {v.normalized} >= fixed {fixed_s}"
        else:
            status, basis, distro_basis = _refine_candidate(cve, target, fixed_s)
    elif cve.kind == "session" and branch in SESSION_EOL_BRANCHES:
        status = STATUS_CANDIDATE
        basis = ("affected EOL branch; no fixed release was published for this branch "
                 "(candidate only)")
    elif cve.kind == "session_injection":
        status = STATUS_CANDIDATE
        basis = f"no fix as of {AS_OF}; version-only candidate"
    else:
        status = STATUS_UNKNOWN
        basis = f"branch {branch} is not covered by the encoded fixed-release data"

    # SAPI scope is a hard rule when it can exclude the target.
    scope = cve.sapi_scope.get(target.sapi, "unknown")
    if status == STATUS_CANDIDATE and scope == "not_affected":
        return Verdict(cve, STATUS_NOT_AFFECTED,
                       f"version is in range, but SAPI {target.sapi} is outside the "
                       "affected scope",
                       "not-in-scope", f"SAPI {target.sapi}", [], notes)
    if status == STATUS_CANDIDATE and scope == "unknown":
        return Verdict(cve, STATUS_UNKNOWN,
                       f"version is in range, but SAPI {target.sapi} was not measured "
                       "for this CVE",
                       "insufficient-input", f"SAPI {target.sapi}", [], notes)
    if status == STATUS_UNKNOWN and scope == "not_affected":
        return Verdict(cve, STATUS_NOT_AFFECTED,
                       f"SAPI {target.sapi} is outside the affected scope",
                       "not-in-scope", f"SAPI {target.sapi}", [], notes)

    evidence, evidence_detail = _evidence(cve, target, status)
    conditions = _conditions(cve, target) if status == STATUS_CANDIDATE else []
    stock_blocked = (cve.kind == "session_injection"
                     and status == STATUS_CANDIDATE)
    if stock_blocked and "stock session.upload_progress.cleanup=1" not in cve.data_note.lower():
        notes.append("stock session.upload_progress.cleanup=1 blocks the demonstrated "
                     "path; cleanup=0 is required")
    return Verdict(cve, status, basis, evidence, evidence_detail,
                   conditions, notes, stock_blocked, distro_basis)


def check_target(target: Target) -> list[Verdict]:
    return [classify(c, target) for c in CVES]


# ---------------------------------------------------------------------------
# Passive fingerprinting (one GET, headers only)
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


_PHP_HEADER_RE = re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)


def _redact_url(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
        if parts.username or parts.password:
            host = parts.hostname or ""
            if parts.port:
                host += f":{parts.port}"
            return urllib.parse.urlunsplit(
                (parts.scheme, host, parts.path, parts.query, parts.fragment))
    except ValueError:
        pass
    return url


def fetch_headers(url: str, timeout: float = 5.0) -> dict[str, Any]:
    """One unauthenticated GET; read headers only.  No body, cookies or payload."""
    result: dict[str, Any] = {
        "url": _redact_url(url),
        "requests_sent": 0,
        "method": "GET",
        "spoofable": True,
    }
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": f"{TOOL}/{TOOL_VERSION} (passive version check)",
            "Accept": "*/*",
        },
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        result["requests_sent"] = 1
        with opener.open(req, timeout=timeout) as resp:
            headers = resp.headers
            result["status"] = resp.status
            result["server"] = headers.get("Server")
            result["x_powered_by"] = headers.get("X-Powered-By")
            result["content_type"] = headers.get("Content-Type")
            result["location"] = headers.get("Location")
            result["set_cookie"] = headers.get_all("Set-Cookie") or []
            php = _PHP_HEADER_RE.search(headers.get("X-Powered-By") or "")
            if php:
                result["php_version"] = php.group(1)
    except urllib.error.HTTPError as exc:
        result["requests_sent"] = 1
        result["status"] = exc.code
        result["server"] = exc.headers.get("Server") if exc.headers else None
        result["x_powered_by"] = exc.headers.get("X-Powered-By") if exc.headers else None
        result["location"] = exc.headers.get("Location") if exc.headers else None
        result["set_cookie"] = (exc.headers.get_all("Set-Cookie")
                                if exc.headers else []) or []
        php = _PHP_HEADER_RE.search(result["x_powered_by"] or "")
        if php:
            result["php_version"] = php.group(1)
        result["http_error"] = exc.reason
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        result["error"] = str(exc)

    server = (result.get("server") or "").lower()
    if "nginx" in server:
        result["server_family"] = "nginx"
        result["sapi_hint"] = "nginx_fpm"
    elif "apache" in server:
        result["server_family"] = "apache"
        result["sapi_hint"] = None  # mod_php vs mod_proxy_fcgi is not decidable
    elif "microsoft-iis" in server or "iis" in server:
        result["server_family"] = "iis"
        result["sapi_hint"] = "iis_fastcgi"
    else:
        result["server_family"] = None
        result["sapi_hint"] = None
    return result


# ---------------------------------------------------------------------------
# Target construction
# ---------------------------------------------------------------------------

_UNRELEASED = frozenset({"8.4.0", "8.4.9"})  # never released upstream


def build_target(args: argparse.Namespace) -> Target:
    package = parse_package(args.package) if args.package else None
    explicit = parse_php_version(args.version) if args.version else None

    warnings: list[str] = []

    if explicit is not None and package is not None:
        if (explicit.complete and package.version.complete
                and not _same_upstream(explicit, package.version)):
            raise InputError(
                f"--version {explicit.normalized} conflicts with --package upstream "
                f"{package.version.normalized}")
        if explicit.deb is not None and deb_compare(explicit.deb, package.deb) != 0:
            raise InputError(
                f"--version {explicit.deb.raw} conflicts with --package version "
                f"{package.deb.raw}")
        if explicit.deb is None and package.deb is not None:
            # A bare upstream version is compatible with a package whose
            # upstream matches; the package supplies the revision.
            pass

    # Only touch the network after all local inputs validate.
    fp = fetch_headers(args.url, args.timeout) if args.url else None

    version_source = "argument"
    if explicit is not None:
        version = explicit
    elif package is not None:
        version = replace(package.version, deb=package.deb)
        version_source = "package"
    elif fp is not None and fp.get("php_version"):
        version = parse_php_version(str(fp["php_version"]))
        version_source = "header (spoofable)"
        warnings.append("PHP version came from the X-Powered-By header; headers can be spoofed")
    else:
        raise InputError(
            "no PHP version: supply --version, --package, or --url returning X-Powered-By")

    if explicit is not None and package is not None and version.deb is None:
        # A bare --version plus --package: the package supplies the revision.
        version = replace(version, deb=package.deb)

    if package is not None and package.branch_hint is not None:
        if version.branch != package.branch_hint:
            raise InputError(
                f"package name implies PHP {package.branch_hint}, but version is "
                f"{version.normalized}")

    if fp is not None and fp.get("php_version") and explicit is not None:
        fv = parse_php_version(str(fp["php_version"]))
        if not _same_upstream(fv, explicit):
            warnings.append(
                f"header PHP/{fv.normalized} conflicts with --version {explicit.normalized}; "
                "using the explicit --version")

    # SAPI: explicit wins; otherwise a package name inference is safe.
    sapi = args.sapi
    if sapi == "unknown" and package is not None and package.sapi_hint:
        sapi = package.sapi_hint
        warnings.append(f"SAPI inferred from package name: {sapi}")
    if (args.sapi != "unknown" and package is not None and package.sapi_hint
            and args.sapi != package.sapi_hint):
        raise InputError(
            f"--sapi {args.sapi} conflicts with package-name SAPI hint "
            f"{package.sapi_hint}")

    # Distro: explicit wins, but conflicts are errors.
    inferred: Distro | None = None
    repo: str | None = None
    if package is not None:
        inferred, repo = infer_distro_from_revision(package.deb.revision)
    if version.deb is not None:
        inf2, repo2 = infer_distro_from_revision(version.deb.revision)
        inferred = inferred or inf2
        repo = repo or repo2

    distro: Distro | None
    if args.distro:
        distro = parse_distro(args.distro)
        if inferred is not None and distro.key != inferred.key:
            raise InputError(
                f"--distro {distro.key} conflicts with package revision "
                f"({inferred.key})")
        if repo and repo not in ("sury",) and distro.family != repo:
            raise InputError(
                f"--distro {distro.key} conflicts with revision family {repo}")
    else:
        distro = inferred

    if repo == "sury":
        warnings.append("third-party Sury package; official Debian fixed revisions "
                        "are not applied")

    if version.pre:
        warnings.append(f"pre-release version suffix {version.pre}; below the "
                        "matching final release")
    if version.normalized in _UNRELEASED:
        warnings.append(f"PHP {version.normalized} was never released upstream; "
                        "verify the distro build")
    known_branches = (set(SESSION_FIXED) | set(SOAP_FIXED) | set(PATHINFO_FIXED)
                      | set(SESSION_EOL_BRANCHES))
    if version.branch not in known_branches:
        warnings.append(f"branch {version.branch} is not in the encoded fixed-release data")

    if fp is not None and fp.get("sapi_hint") and sapi == "unknown":
        warnings.append(
            f"passive header hint: {fp['server_family']} front end, "
            f"possible SAPI {fp['sapi_hint']}; rerun with --sapi to make it authoritative")

    return Target(
        version=version,
        sapi=sapi,
        distro=distro,
        package=package,
        repo=repo,
        version_source=version_source,
        fingerprint=fp,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

DISCLAIMER = (
    "A version/build match is a CANDIDATE, not proof. This tool does not "
    "verify a target and sends no exploit traffic (with --url it sends one "
    "unauthenticated GET and reads headers only). VULNERABLE-CANDIDATE means "
    "the version/package revision is in an affected range or below a known "
    "fixed revision and the listed conditions are unverified. FIXED means at "
    "or above a known fixed release/revision, not that the binary is "
    "unmodified. NOT-AFFECTED means the version or SAPI is outside the "
    "affected scope. UNKNOWN means the inputs are insufficient: for distro "
    "builds supply the exact package revision, and for SAPI/config-dependent "
    "bugs supply --sapi and verify the conditions separately."
)


def _counts(verdicts: list[Verdict]) -> dict[str, int]:
    counts = {s: 0 for s in STATUS_ORDER}
    for v in verdicts:
        counts[v.status] = counts.get(v.status, 0) + 1
    return counts


def to_json(target: Target, verdicts: list[Verdict]) -> dict[str, Any]:
    distro = None
    if target.distro is not None:
        distro = {
            "key": target.distro.key,
            "family": target.distro.family,
            "release": target.distro.release,
            "codename": target.distro.codename,
            "display": target.distro.display,
        }
    package = None
    if target.package is not None:
        package = {
            "name": target.package.name,
            "version": target.package.raw,
            "upstream": target.package.deb.upstream,
            "revision": target.package.deb.revision,
            "arch": target.package.arch,
            "branch_hint": target.package.branch_hint,
            "sapi_hint": target.package.sapi_hint,
        }
    fp = None
    if target.fingerprint is not None:
        fp = dict(target.fingerprint)
        fp.pop("set_cookie", None)
        fp["set_cookie_count"] = len(target.fingerprint.get("set_cookie") or [])
    out_verdicts = []
    for v in verdicts:
        out_verdicts.append({
            "cve": v.cve.id,
            "title": v.cve.title,
            "status": v.status,
            "basis": v.basis,
            "evidence": v.evidence,
            "evidence_detail": v.evidence_detail,
            "distro_basis": v.distro_basis,
            "candidate_not_proof": v.status == STATUS_CANDIDATE,
            "stock_blocked": v.stock_blocked,
            "conditions": v.conditions,
            "notes": v.notes,
            "sources": list(v.cve.sources),
        })
    return {
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "as_of": AS_OF,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "passive_only": True,
        "target": {
            "php_version": target.version.normalized,
            "php_version_input": target.version.raw,
            "package_version": target.version.exact_input if target.version.deb else None,
            "branch": target.version.branch,
            "sapi": target.sapi,
            "sapi_label": SAPI_LABELS.get(target.sapi, target.sapi),
            "distro": distro,
            "package": package,
            "repo": target.repo,
            "build_identity": build_identity(target),
            "version_source": target.version_source,
            "fingerprint": fp,
            "warnings": target.warnings,
        },
        "verdicts": out_verdicts,
        "summary": {"total": len(verdicts), **_counts(verdicts)},
        "disclaimer": DISCLAIMER,
    }


def _print_target(target: Target) -> None:
    v = target.version
    print("Target")
    print(f"  PHP version    : {v.normalized}")
    print(f"  Branch         : {v.branch}")
    print(f"  SAPI           : {target.sapi} ({SAPI_LABELS.get(target.sapi, target.sapi)})")
    if target.distro is not None:
        print(f"  Distro         : {target.distro.display}")
    else:
        print("  Distro         : not specified (upstream version only)")
    if target.package is not None:
        print(f"  Package        : {target.package.name}={target.package.raw}")
    print(f"  Build identity : {build_identity(target)}")
    print(f"  Version source : {target.version_source}")
    if target.fingerprint is not None:
        fp = target.fingerprint
        if fp.get("error"):
            print(f"  Fingerprint    : GET {fp.get('url')} failed: {fp['error']}")
        else:
            bits = [f"GET {fp.get('url')} -> {fp.get('status')}"]
            if fp.get("server"):
                bits.append(f"Server: {fp['server']}")
            if fp.get("x_powered_by"):
                bits.append(f"X-Powered-By: {fp['x_powered_by']} (spoofable)")
            print(f"  Fingerprint    : {'; '.join(bits)}")
    else:
        print("  Fingerprint    : not requested")
    for w in target.warnings:
        print(f"  Warning        : {w}")


def _print_verdict(v: Verdict) -> None:
    print()
    print(f"{v.cve.id}  {v.status}")
    print(f"  Basis     : {v.basis}")
    if v.distro_basis:
        print(f"  Distro    : {v.distro_basis}")
    print(f"  Evidence  : {v.evidence} - {v.evidence_detail}")
    if v.stock_blocked:
        print("  Blocked   : stock config blocks this path; cleanup=0 is required")
    if v.conditions:
        print("  Conditions required for the primitive:")
        for c in v.conditions:
            print(f"    [{c['state']}] {c['id']}")
            print(f"             {c['detail']}")
    if v.notes:
        print("  Notes:")
        for n in v.notes:
            print(f"    - {n}")


def print_human(target: Target, verdicts: list[Verdict]) -> None:
    print(f"{TOOL} {TOOL_VERSION}  (data as of {AS_OF})")
    print("PASSIVE VERSION/BUILD CHECK: no exploit traffic; with --url one GET, headers only.")
    print()
    _print_target(target)
    print()
    print("Verdicts")
    for v in verdicts:
        _print_verdict(v)
    counts = _counts(verdicts)
    print()
    print("Summary: " + ", ".join(f"{counts[s]} {s}" for s in STATUS_ORDER))
    if target.version_source in ("argument", "package") and target.distro is None:
        print("Version-only result: every VULNERABLE-CANDIDATE is a lead, not proof; "
              "add --package/--distro for revision evidence.")
    print()
    print("!" * 78)
    for line in _wrap(DISCLAIMER, 78):
        print(line)
    print("!" * 78)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        if not cur:
            cur = w
        elif len(cur) + 1 + len(w) <= width:
            cur += " " + w
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def _list_cves() -> None:
    print(f"{TOOL} {TOOL_VERSION} - encoded CVEs (as of {AS_OF})")
    for c in CVES:
        fixed = ", ".join(f"{k}->{v}" for k, v in sorted(c.fixed.items())) or "no fix"
        print(f"  {c.id}  {c.title}")
        print(f"      fixed: {fixed}")
        print(f"      note : {c.data_note}")


def _list_distros() -> None:
    seen = set()
    print(f"{TOOL} {TOOL_VERSION} - distros")
    for d in sorted(_DISTRO_TABLE.values(), key=lambda x: x.key):
        if d.key in seen:
            continue
        seen.add(d.key)
        print(f"  {d.key:<12} {d.display}")
    print()
    print("Note: package/revision mappings cover Debian and Ubuntu only;")
    print("other distro families are not encoded and remain version-only.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL,
        description=("Passive PHP version/build vulnerability candidate checker. "
                     "No exploit traffic; --url sends one GET for headers only."),
        epilog=("Example: phpcheck.py --version 8.4.24 --distro debian13 "
                "--sapi mod_php --json"),
    )
    p.add_argument("--version", dest="version", metavar="X.Y.Z",
                   help="exact PHP version, e.g. 8.4.24 (a distro version such as "
                        "8.5.4-0ubuntu1.5 is also accepted)")
    p.add_argument("--package", metavar="NAME=VERSION",
                   help="distro package, e.g. "
                        "libapache2-mod-php8.4=8.4.24-1~deb13u1")
    p.add_argument("--distro", metavar="ID",
                   help="debian13, debian12, ubuntu26.04, ubuntu24.04, ...")
    p.add_argument("--sapi", choices=SAPI_CHOICES, default="unknown",
                   help="SAPI (default: unknown; package name may infer it)")
    p.add_argument("--url", metavar="URL",
                   help="optional passive fingerprint: one GET, headers only")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--timeout", type=float, default=5.0,
                   help="fingerprint timeout seconds (default 5)")
    p.add_argument("--fail-on-candidate", action="store_true",
                   help="exit 1 if any VULNERABLE-CANDIDATE is reported")
    p.add_argument("--list-cves", action="store_true", help="list encoded CVEs and exit")
    p.add_argument("--list-distros", action="store_true", help="list distro IDs and exit")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_cves:
        _list_cves()
        return 0
    if args.list_distros:
        _list_distros()
        return 0
    try:
        target = build_target(args)
        verdicts = check_target(target)
    except InputError as exc:
        print(f"{TOOL}: error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        json.dump(to_json(target, verdicts), sys.stdout, indent=2, sort_keys=False)
        print()
    else:
        print_human(target, verdicts)

    if args.fail_on_candidate and any(v.status == STATUS_CANDIDATE for v in verdicts):
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)

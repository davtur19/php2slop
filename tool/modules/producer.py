"""producer.py - 618/619 staged shape builders; not wired into driver steps.

The mod_php producer stage lives in producer_modphp.py; this module is only a
facade over producer_618 and producer_619.
"""


from tool.modules import producer_618
from tool.modules import producer_619


def producer_618_body(sid: str, cmd: bytes, call: int = 0) -> tuple[bytes, bytes]:
    """CVE-2026-109618 producer shape; inert by default (call=0)."""
    return producer_618.build(sid, cmd, call)


def producer_619_body(sid: str, cmd: bytes, call: int = 0) -> tuple[bytes, bytes]:
    """CVE-2026-109619 producer shape; inert by default (call=0)."""
    return producer_619.build(sid, cmd, call)

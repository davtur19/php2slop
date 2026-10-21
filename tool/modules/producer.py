"""Heavy POST / decoder-interrupt producers.

The producers replay the staged multipart shapes that produce the request
fatal exchanges the chain needs (producer -> stale decoder state -> session
upload-progress consumer; see the writeup calif.io/php2shell and the receipts
under docs/):

  * producer_618.build(sid, cmd, call) -> (phase1, tail)
      CVE-2026-109618 OOM / stale machinery shape (boundary B7kQpoc618,
      FILLUNIT fill, >min_freq stall, 149 x t[] reclaim blobs).
  * producer_619.build(sid, cmd, call) -> (phase1, tail)
      CVE-2026-109619 stale global state shape (149 x t[] FIRST, file f,
      stall, c2 -> update(free window), c3 -> both stale stores).

Both builders default to an INERT forge (call=0): byte-exact body shapes with
no forged call target. Full-byte pacing transport for HTTP targets is the
sender's job; the historical lab jigs live in lab/ (sender_fpm.py, feeder_f618.py,
slowfeed.py).

Not implemented (chain stage producer): producers are not wired into the
driver's --step recon/chain yet (tool/php2shell.py).
TODO (missing module): mod_php SAPI producer and modphp target constants
(tool/modules/profiles.py TARGETS["modphp"]).
"""

from tool.modules import producer_618
from tool.modules import producer_619


def producer_618_body(sid: str, cmd: bytes, call: int = 0) -> tuple[bytes, bytes]:
    """CVE-2026-109618 producer shape; inert by default (call=0)."""
    return producer_618.build(sid, cmd, call)


def producer_619_body(sid: str, cmd: bytes, call: int = 0) -> tuple[bytes, bytes]:
    """CVE-2026-109619 producer shape; inert by default (call=0)."""
    return producer_619.build(sid, cmd, call)

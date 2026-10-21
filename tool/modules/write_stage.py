"""Controlled copy stage (negative used_slots -> stage write) — STUB.

Not implemented (chain stage write_stage): the negative used_slots math and
the retry/verification policy for the controlled copy into the stage address
are not implemented as a standalone module.

The live, verified call path for this stage is the driver's attempt loop:
  tool/php2shell.py:attempt() -> final forged multipart built by
  tool/modules/compact-stock-tail.py:COMPACT.probe_body(parts, f1, f2,
  field_len, b1, n2, s1, s2, b2, b3, target, dso_base, stage_delta, ordinal,
  payload) (driver metadata: final_parts=116).

TODO: extract the stage-write parameters into profiles.py per binary profile
(currently they are hardcoded at the call site) and add receipt-level checks
for the copy outcome.
"""


def stage_body(*args, **kwargs):
    """Raised NotImplementedError by design — see module docstring."""
    raise NotImplementedError(
        "Not implemented (chain stage write_stage): use the live path "
        "tool/php2shell.py:attempt() -> tool/modules/compact-stock-tail.py:"
        "COMPACT.probe_body(...), or implement the negative used_slots math "
        "here."
    )

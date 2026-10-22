"""tool.stages: per-step stage helpers used by the driver.

Stage list (tool/php2shell.py:STAGES, in receipt-ladder order):
- recon  -> stages/probe.py (pre-flight fingerprint)
- producer -> tool/modules/producer_fpmwiki.py (+ step "producer";
  sends to the operator-supplied target)
- chain  -> php2shell.py:attempt() (STOCK arm + LEAK probe + COMPACT rearm/final)
"""

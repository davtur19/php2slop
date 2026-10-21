"""tool.stages: per-step stage helpers used by the driver.

Stage list (tool/php2shell.py:STAGES, in receipt-ladder order):
- recon  -> stages/probe.py (pre-flight fingerprint)
- producer -> tool/modules/producer_fpmwiki.py (+ step "producer";
  offline byte-build default, --live gates the send)
- chain  -> php2shell.py:attempt() (STOCK arm + LEAK probe + COMPACT rearm/final)
"""

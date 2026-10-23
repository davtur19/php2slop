#!/bin/bash
# Coverage matrix, group 1: 8.5 branch + fixed control.
cd /tmp/opencode/research/build_coverage_20261023T074532Z
set -x
python3 harness.py --tag 8.5.0  --port 18902 --plans as-is,85
python3 harness.py --tag 8.5.5  --port 18903 --plans as-is,85
python3 harness.py --tag 8.5.12 --port 18904 --plans as-is

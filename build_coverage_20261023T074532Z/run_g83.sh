#!/bin/bash
# Group 2: 8.5.11 calibration + 8.3 branch + fixed control.
cd /tmp/opencode/research/build_coverage_20261023T074532Z
python3 harness.py --tag 8.5.11 --port 18905 --plans 85 --nb1 8
python3 harness.py --tag 8.3.0  --port 18906 --plans as-is,sweep
python3 harness.py --tag 8.3.10 --port 18907 --plans as-is,sweep
python3 harness.py --tag 8.3.20 --port 18908 --plans as-is,sweep
python3 harness.py --tag 8.3.36 --port 18909 --plans as-is

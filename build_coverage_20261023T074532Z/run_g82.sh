#!/bin/bash
# Group 3: 8.2 branch + fixed control.
cd /tmp/opencode/research/build_coverage_20261023T074532Z
python3 harness.py --tag 8.2.0  --port 18910 --plans as-is,sweep
python3 harness.py --tag 8.2.15 --port 18911 --plans as-is,sweep
python3 harness.py --tag 8.2.34 --port 18912 --plans as-is,sweep
python3 harness.py --tag 8.2.35 --port 18913 --plans as-is

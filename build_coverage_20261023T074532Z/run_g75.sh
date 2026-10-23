#!/bin/bash
# Group 4: 7.4 / 7.2 / 7.0 / 5.6 - A1/B1 as-is + 109619 generic producer/consumer.
cd /tmp/opencode/research/build_coverage_20261023T074532Z
python3 harness.py --tag 7.4.0  --port 18914 --plans as-is,pair619
python3 harness.py --tag 7.4.33 --port 18915 --plans as-is,pair619
python3 harness.py --tag 7.2.0  --port 18916 --plans as-is,pair619
python3 harness.py --tag 7.2.34 --port 18917 --plans as-is,pair619
python3 harness.py --tag 7.0.33 --port 18918 --plans as-is,pair619
python3 harness.py --tag 5.6.40 --port 18919 --plans as-is,pair619

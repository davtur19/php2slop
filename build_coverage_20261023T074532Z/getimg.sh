#!/bin/bash
# Serial image puller; logs one line per tag.
cd /tmp/opencode/research/build_coverage_20261023T074532Z
for t in "$@"; do
  if docker image inspect php:$t-apache >/dev/null 2>&1; then
    echo "HAVE $t" >> logs/pull.log; continue
  fi
  echo "START $t $(date -u +%H:%M:%SZ)" >> logs/pull.log
  if timeout 420 docker pull -q php:$t-apache >/dev/null 2>&1; then
    echo "OK $t $(date -u +%H:%M:%SZ)" >> logs/pull.log
  else
    echo "FAIL $t $(date -u +%H:%M:%SZ)" >> logs/pull.log
  fi
done
echo "DONE $(date -u +%H:%M:%SZ)" >> logs/pull.log

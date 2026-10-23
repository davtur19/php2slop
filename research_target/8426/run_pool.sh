#!/usr/bin/env bash
# Thin wrapper: all protocol logic lives in lib/chain8426.py so the same code
# can be audited and dry-run without a shell/quoting layer.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$ROOT/lib/chain8426.py" --kit-root "$ROOT" "$@"

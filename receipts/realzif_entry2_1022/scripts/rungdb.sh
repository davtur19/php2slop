#!/bin/bash
LAB="$(cd "$(dirname "$0")" && pwd)"
CHILD=$(cat "$LAB/run/child.pid")
exec gdb -q -batch -p "$CHILD" -x "$1"

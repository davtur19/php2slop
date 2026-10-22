#!/bin/bash
LAB=/tmp/opencode/research/g6zif_20261021T222434Z
CHILD=$(cat "$LAB/run/child.pid")
exec gdb -q -batch -p "$CHILD" -x "$1"

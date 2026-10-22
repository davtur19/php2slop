#!/bin/bash
v=$1; dir=$2
cd "$dir"
CFLAGS='-g -O1 -fno-omit-frame-pointer -fno-pie' LDFLAGS='-no-pie' ./configure --prefix="$PWD/inst" --disable-all --enable-fpm --enable-session --without-pear > cfg.log 2>&1 || { echo "CFG FAIL $v"; tail -5 cfg.log; exit 1; }
make -j3 > make.log 2>&1 || { echo "MAKE FAIL $v"; tail -20 make.log; exit 1; }
echo "OK $v $(ls -la sapi/fpm/php-fpm 2>/dev/null | awk '{print $5}')"

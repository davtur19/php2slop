#!/bin/bash
# ASAN out-of-tree build of php 8.5.10 (source copied from build_plain tree)
set -e
cd /home/davide/ailocal/php/zerodays_1020/build_asan
CFLAGS='-g -O1 -fno-omit-frame-pointer -fsanitize=address' \
CXXFLAGS='-g -O1 -fno-omit-frame-pointer -fsanitize=address' \
LDFLAGS='-fsanitize=address' \
./configure \
  --prefix=/home/davide/ailocal/php/zerodays_1020/install_asan \
  --disable-all \
  --enable-fpm \
  --enable-cgi \
  --enable-cli \
  --enable-session \
  > /tmp/opencode/realapps/side/configure_asan.log 2>&1
echo "CONFIGURE_OK"
make -j"$(nproc)" > /tmp/opencode/realapps/side/make_asan.log 2>&1
echo "MAKE_OK"
make install > /tmp/opencode/realapps/side/install_asan.log 2>&1
echo "INSTALL_OK"

#!/bin/bash
set -x
SRC=/tmp/opencode/php-8.4.26
BUILD=/tmp/opencode/research/fpm_bg_20261023T021053Z/build/sym8426
mkdir -p "$BUILD"; cd "$BUILD"
CFLAGS="-O0 -g3 -fno-omit-frame-pointer" "$SRC/configure" \
  --prefix="$BUILD/inst" \
  --disable-all --enable-cli --enable-fpm --disable-cgi --disable-phpdbg --without-pear \
  --enable-session --enable-filter --enable-ctype --enable-tokenizer --enable-posix \
  --disable-debug
echo "CONFIGURE_EXIT=$?"
make -j8 sapi/fpm/php-fpm
echo "MAKE_EXIT=$?"

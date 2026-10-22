#!/bin/bash
# V6-shaped non-PIE FPM builds for the version matrix.
# Same recipe as veroff_20261021_215718 / g6zif: -g -O1, -fno-pie, -no-pie,
# --disable-all --enable-fpm --enable-session.
set -u
R=/tmp/opencode/research/vermatrix_20261022T004325Z
VERS="7.0.33 7.1.33 7.2.34 7.3.33 8.0.30 8.2.35 8.3.36"
for v in $VERS; do
  log=$R/log/build-$v.log
  echo "=== $v $(date -u +%H:%M:%S)" >> $R/log/build-all.txt
  d=$R/build/php-$v
  rm -rf "$d"
  mkdir -p "$d"
  tar -xf "$R/src/php-$v.tar.xz" -C "$R/build" || { echo "UNTAR FAIL $v" >> $R/log/build-all.txt; continue; }
  (
    cd "$d" || exit 1
    CFLAGS="-g -O1 -fno-omit-frame-pointer -fno-pie -DCOOKIE_SEEKER_USES_OFF64_T=1" \
    LDFLAGS='-no-pie' ac_cv_what_readdir_r=POSIX \
      ./configure --prefix="$PWD/inst" --disable-all --enable-fpm --enable-session --without-pear > "$R/log/cfg-$v.log" 2>&1
    rc=$?
    if [ $rc -ne 0 ]; then echo "CFG FAIL $v rc=$rc" >> $R/log/build-all.txt; exit 1; fi
    make -j8 > "$R/log/make-$v.log" 2>&1
    rc=$?
    if [ ! -x sapi/fpm/php-fpm ]; then
      make -j8 LDFLAGS='-no-pie' > "$R/log/relink-$v.log" 2>&1
    fi
    if [ ! -x sapi/fpm/php-fpm ]; then echo "MAKE FAIL $v rc=$rc" >> $R/log/build-all.txt; exit 1; fi
    f=sapi/fpm/php-fpm
    echo "OK $v md5=$(md5sum "$f" | cut -d' ' -f1) size=$(stat -c%s "$f") type=$(readelf -h "$f" | awk '/Type:/{print $2}') banner=$("$f" -v 2>/dev/null | head -1)" >> $R/log/build-all.txt
  ) > "$log" 2>&1
done
echo "DONE $(date -u +%H:%M:%S)" >> $R/log/build-all.txt

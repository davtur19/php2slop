FROM debian:buster
ENV DEBIAN_FRONTEND=noninteractive
RUN printf '%s\n' \
      'deb http://archive.debian.org/debian buster main' \
      'deb http://archive.debian.org/debian-security buster/updates main' \
      > /etc/apt/sources.list \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends ca-certificates curl
COPY debs-7.3.11/ /tmp/debs/
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends /tmp/debs/*.deb
COPY php-fpm-overrides.ini /etc/php/7.3/fpm/conf.d/99-t11043.ini
COPY php-cli-overrides.ini /etc/php/7.3/cli/conf.d/99-t11043.ini
RUN sed -i 's|^listen = .*|listen = 9000|; s|^;listen.allowed_clients.*|;listen.allowed_clients (disabled: nginx is a separate container)|' /etc/php/7.3/fpm/pool.d/www.conf \
 && sed -i 's|^user = .*|user = www-data|; s|^group = .*|group = www-data|' /etc/php/7.3/fpm/pool.d/www.conf \
 && rm -rf /var/lib/apt/lists/* /tmp/debs
RUN php -v && php-fpm7.3 -v && grep -E '^(listen|user|group|pm) ' /etc/php/7.3/fpm/pool.d/www.conf
CMD ["php-fpm7.3", "-F"]

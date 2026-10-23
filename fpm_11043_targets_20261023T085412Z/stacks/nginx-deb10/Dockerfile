FROM debian:buster
ENV DEBIAN_FRONTEND=noninteractive
# Debian 10 (buster) is archived; use the official archive, final point release 10.13
RUN printf '%s\n' 'deb http://archive.debian.org/debian buster main' > /etc/apt/sources.list \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends nginx curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN nginx -v 2>&1; dpkg -l nginx nginx-common | tail -3

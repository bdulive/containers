# Copyright Broadcom, Inc. All Rights Reserved.
# SPDX-License-Identifier: APACHE-2.0

FROM docker.io/bitnami/minideb:trixie

ARG DOWNLOADS_URL="https://downloads.bitnami.com/files/stacksmith"
ARG TARGETARCH

LABEL org.opencontainers.image.base.name="docker.io/bitnami/minideb:trixie" \
      org.opencontainers.image.created="2026-09-09T00:00:00Z" \
      org.opencontainers.image.description="Application packaged by Broadcom, Inc." \
      org.opencontainers.image.documentation="https://github.com/bitnami/containers/tree/main/bitnami/redis-cluster/README.md" \
      org.opencontainers.image.source="https://github.com/bitnami/containers/tree/main/bitnami/redis-cluster" \
      org.opencontainers.image.title="redis-cluster" \
      org.opencontainers.image.vendor="Broadcom, Inc." \
      org.opencontainers.image.version="8.10.1"

ENV HOME="/" \
    OS_ARCH="${TARGETARCH:-amd64}" \
    OS_FLAVOUR="debian-13" \
    OS_NAME="linux"

COPY prebuildfs /
SHELL ["/bin/bash", "-o", "errexit", "-o", "nounset", "-o", "pipefail", "-c"]
# Install required system packages and dependencies.
#
# libssl3 is libssl3t64 on Debian 13 (the 64-bit time_t transition renamed the
# package). wget replaces curl for the component download: libcurl4 hard-depends
# on libssh2-1, which carries open heap-corruption advisories with no fix in
# Debian 13, and the debian-12 variant threw curl away again at the end of the
# build anyway.
RUN install_packages ca-certificates libgcc-s1 libgomp1 libssl3t64 libstdc++6 procps wget
RUN --mount=type=secret,id=downloads_url,env=SECRET_DOWNLOADS_URL \
    DOWNLOADS_URL=${SECRET_DOWNLOADS_URL:-${DOWNLOADS_URL}} ; \
    mkdir -p /tmp/bitnami/pkg/cache/ ; cd /tmp/bitnami/pkg/cache/ || exit 1 ; \
    COMPONENTS=( \
      "wait-for-port-1.0.11-1-linux-${OS_ARCH}-debian-12" \
      "redis-8.10.1-0-linux-${OS_ARCH}-debian-12" \
    ) ; \
    for COMPONENT in "${COMPONENTS[@]}"; do \
      if [ ! -f "${COMPONENT}.tar.gz" ]; then \
        wget --no-verbose --tries=3 "${DOWNLOADS_URL}/${COMPONENT}.tar.gz" ; \
      fi ; \
      sha256sum -c "/opt/bitnami/checksums/${COMPONENT}.tar.gz.sha256" ; \
      tar -zxf "${COMPONENT}.tar.gz" -C /opt/bitnami --strip-components=2 --no-same-owner ; \
      rm -rf "${COMPONENT}".tar.gz ; \
    done ; \
    rm -rf /opt/bitnami/checksums ;
RUN apt-get update && apt-get upgrade -y && \
    apt-get clean && rm -rf /var/lib/apt/lists /var/cache/apt/archives
RUN chmod g+rwX /opt/bitnami
RUN find / -perm /6000 -type f -exec chmod a-s {} \; || true

COPY rootfs /
RUN /opt/bitnami/scripts/redis-cluster/postunpack.sh
# Drop Perl. Neither Redis nor the Bitnami scripts use it at runtime, and no
# Debian release currently ships a fix for the outstanding perl advisories, so
# removal is the only available remediation. perl-base is marked Essential (it
# backs debconf), hence the force flags - this has to stay the final dpkg/apt
# operation of the build.
#
# The package set is discovered rather than pinned: Debian versions the module
# and library packages (perl-modules-5.40, libperl5.40), so a hardcoded list
# would silently stop matching after a base bump. dpkg --purge only *warns* on
# a package that is not installed, so a stale list would leave the build green
# with eight CVEs quietly reinstated. The trailing assertions are the real
# guard - they fail the build if anything perl survives.
#
# dpkg-query runs without -f: a '\${Package}' format string in a RUN line is
# mangled by the Dockerfile parser's own \$ handling, which silently yields an
# empty package list. The default 'package\tversion' output plus cut -f1 is
# equivalent and has nothing for the parser to touch.
#
# Note for downstream images: purging Essential perl-base leaves
# /usr/sbin/dpkg-preconfigure missing, so a later install_packages prints a
# harmless "not found" warning. It still succeeds, but installing a package
# whose maintainer scripts need perl will pull perl-base back in and undo this.
RUN PERL_PKGS="$(dpkg-query -W | cut -f1 | grep -E '^(perl|libperl)' || true)" && \
    if [ -n "$PERL_PKGS" ]; then \
      dpkg --purge --force-remove-essential --force-depends $PERL_PKGS ; \
    fi && \
    rm -rf /usr/share/perl /usr/share/perl5 /usr/lib/*/perl /usr/lib/*/perl5 && \
    ! command -v perl && \
    ! dpkg-query -W | cut -f1 | grep -qE '^(perl|libperl)'
ENV APP_VERSION="8.10.1" \
    BITNAMI_APP_NAME="redis-cluster" \
    IMAGE_REVISION="0" \
    PATH="/opt/bitnami/common/bin:/opt/bitnami/redis/bin:$PATH"

EXPOSE 6379

USER 1001
ENTRYPOINT [ "/opt/bitnami/scripts/redis-cluster/entrypoint.sh" ]
CMD [ "/opt/bitnami/scripts/redis-cluster/run.sh" ]

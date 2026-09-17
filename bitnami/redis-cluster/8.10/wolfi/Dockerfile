# Copyright Broadcom, Inc. All Rights Reserved.
# SPDX-License-Identifier: APACHE-2.0

# ---------------------------------------------------------------------------
# Redis Cluster 8.10.1 on Chainguard Wolfi.
#
# Variant of the upstream ../debian-12 image that replaces the minideb base
# with cgr.dev/chainguard/wolfi-base, for the same reason as the rabbitmq wolfi
# variant: Wolfi packages the FIXED acl 2.4.0 and attr 2.6.0 releases, so
# CVE-2026-54369, CVE-2026-54370 and CVE-2026-54371 are genuinely absent
# rather than waived. Debian trixie is pinned to acl 2.3.2 / attr 2.5.2,
# marked no-dsa with the fix landing in unstable first, and on any Debian base
# libacl1 is unavoidable - it arrives via coreutils, passwd, sed and tar.
#
# No perl force-purge is needed either: Wolfi installs no perl in the first
# place, while every Debian base pulls it in through debconf.
#
# Build:
#   docker build --platform linux/amd64,linux/arm64 \
#     -t bitnami-redis-cluster:8.10.1-wolfi-r1 --load .
# ---------------------------------------------------------------------------

ARG WOLFI_BASE="cgr.dev/chainguard/wolfi-base:latest"

# ---------------------------------------------------------------------------
# Stage 1 - fetch and verify the prebuilt Bitnami components.
#
# Kept in its own stage so wget and its gnutls/idn2/nettle/psl dependency
# chain never reach the runtime image. A Debian base has to install wget and
# then uninstall_packages it again at the end of the build; a separate stage is
# the cleaner expression of the same intent.
# ---------------------------------------------------------------------------
FROM ${WOLFI_BASE} AS component
USER 0

ARG DOWNLOADS_URL="https://downloads.bitnami.com/files/stacksmith"
ARG TARGETARCH
ENV OS_ARCH="${TARGETARCH:-amd64}"

RUN apk update && apk add --no-cache wget ca-certificates-bundle

COPY prebuildfs/opt/bitnami/checksums /opt/bitnami/checksums
RUN --mount=type=secret,id=downloads_url,env=SECRET_DOWNLOADS_URL \
    set -eu ; \
    DOWNLOADS_URL=${SECRET_DOWNLOADS_URL:-${DOWNLOADS_URL}} ; \
    mkdir -p /tmp/cache /rootfs-app ; cd /tmp/cache ; \
    for COMPONENT in \
      "wait-for-port-1.0.11-3-linux-${OS_ARCH}-debian-12" \
      "redis-8.10.1-0-linux-${OS_ARCH}-debian-12" ; \
    do \
      wget --no-verbose --tries=3 "${DOWNLOADS_URL}/${COMPONENT}.tar.gz" ; \
      sha256sum -c "/opt/bitnami/checksums/${COMPONENT}.tar.gz.sha256" ; \
      tar -zxf "${COMPONENT}.tar.gz" -C /rootfs-app --strip-components=2 --no-same-owner ; \
      rm -f "${COMPONENT}.tar.gz" ; \
    done

# ---------------------------------------------------------------------------
# Stage 2 - Redis Cluster runtime image
# ---------------------------------------------------------------------------
FROM ${WOLFI_BASE}
USER 0

ARG WOLFI_BASE
ARG TARGETARCH

LABEL org.opencontainers.image.base.name="${WOLFI_BASE}" \
      org.opencontainers.image.created="2026-09-17T03:45:00Z" \
      org.opencontainers.image.description="Application packaged by Broadcom, Inc." \
      org.opencontainers.image.documentation="https://github.com/bitnami/containers/tree/main/bitnami/redis-cluster/README.md" \
      org.opencontainers.image.source="https://github.com/bitnami/containers/tree/main/bitnami/redis-cluster" \
      org.opencontainers.image.title="redis-cluster" \
      org.opencontainers.image.vendor="Broadcom, Inc." \
      org.opencontainers.image.version="8.10.1"

ENV HOME="/" \
    OS_ARCH="${TARGETARCH:-amd64}" \
    OS_FLAVOUR="wolfi" \
    OS_NAME="linux"

SHELL ["/bin/sh", "-o", "errexit", "-c"]

# Runtime packages. The GNU userland is installed deliberately rather than
# relying on busybox applets: the Bitnami script library uses GNU-specific
# behaviour in sed, grep and awk. On Wolfi that costs nothing in CVE terms,
# because coreutils pulls libacl1 2.4.0 and libattr1 2.6.0 - the patched
# releases - where Debian would pull the unfixed 2.3.2 / 2.5.2.
#
#   bash                  - every Bitnami script is #!/bin/bash
#   coreutils sed grep    - GNU semantics the script library depends on
#   gawk findutils        - as above
#   procps                - pgrep/kill used by run.sh and the cluster helpers
#   posix-libc-utils-bin  - getent, used by libnet.sh and libos.sh
#   libgcc libgomp        - linked by the Redis binary
#   libstdc++             - as above
#
# libssl3 and ca-certificates-bundle are already in wolfi-base. wget is
# deliberately absent: nothing in this image uses it at runtime.
RUN apk update && \
    apk upgrade --no-cache && \
    apk add --no-cache \
      bash \
      coreutils \
      sed \
      grep \
      gawk \
      findutils \
      procps \
      posix-libc-utils-bin \
      libgcc \
      libgomp \
      libstdc++ && \
    rm -rf /var/cache/apk/*

# uid 1001 is the Bitnami convention. wolfi-base only ships "nonroot" (65532),
# so declare the account the image actually runs as.
RUN adduser -u 1001 -G root -S -H -h / -s /sbin/nologin redis

# Wolfi merges sbin into bin (/usr/sbin and /sbin are symlinks to usr/bin),
# so the prebuildfs helpers live under usr/bin here rather than usr/sbin as
# they do in the Debian variants - COPY cannot write through that symlink.
COPY prebuildfs /
COPY --from=component /rootfs-app /opt/bitnami

RUN rm -rf /opt/bitnami/checksums
RUN chmod g+rwX /opt/bitnami
RUN find / -perm /6000 -type f -exec chmod a-s {} \; || true

COPY rootfs /
RUN /opt/bitnami/scripts/redis-cluster/postunpack.sh

# The Bitnami redis component is built against debian-12 glibc; assert it
# actually runs here before the image is published.
RUN /opt/bitnami/redis/bin/redis-server --version && \
    /opt/bitnami/redis/bin/redis-cli --version && \
    ! command -v perl

ENV APP_VERSION="8.10.1" \
    BITNAMI_APP_NAME="redis-cluster" \
    IMAGE_REVISION="1" \
    PATH="/opt/bitnami/common/bin:/opt/bitnami/redis/bin:$PATH"

EXPOSE 6379

USER 1001
ENTRYPOINT [ "/opt/bitnami/scripts/redis-cluster/entrypoint.sh" ]
CMD [ "/opt/bitnami/scripts/redis-cluster/run.sh" ]

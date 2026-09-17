# Copyright Broadcom, Inc. All Rights Reserved.
# SPDX-License-Identifier: APACHE-2.0

# ---------------------------------------------------------------------------
# RabbitMQ 4.3.5 on Chainguard Wolfi.
#
# Variant of the upstream ../debian-12 image that replaces the minideb base
# with cgr.dev/chainguard/wolfi-base. Two things fall out of that swap:
#
#   1. Wolfi packages the FIXED acl 2.4.0 and attr 2.6.0 releases, so
#      CVE-2026-54369, CVE-2026-54370 and CVE-2026-54371 are genuinely absent
#      rather than waived by a VEX statement. Debian trixie is stuck on
#      acl 2.3.2 / attr 2.5.2 (marked no-dsa; fixed first in unstable), and
#      Docker Hardened Images rebuild those same unfixed sources.
#
#   2. Wolfi packages erlang-27 at exactly 27.3.4.17 - the OTP patch release
#      several advisories require and Bitnami does not publish a component
#      for - so no Erlang source build is needed.
#
# Build:
#   docker build -t bitnami-rabbitmq:4.3.5-wolfi-r1 .
# ---------------------------------------------------------------------------

ARG WOLFI_BASE="cgr.dev/chainguard/wolfi-base:latest"

# ---------------------------------------------------------------------------
# Stage 1 - fetch and verify the prebuilt Bitnami RabbitMQ component.
#
# The component is built against debian-12 glibc; Wolfi is glibc 2.44, so it
# loads and runs unmodified. Done in its own stage so the tarball and the
# download tooling never reach the runtime image.
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
    COMPONENT="rabbitmq-4.3.5-0-linux-${OS_ARCH}-debian-12" ; \
    wget --quiet --tries=3 "${DOWNLOADS_URL}/${COMPONENT}.tar.gz" ; \
    sha256sum -c "/opt/bitnami/checksums/${COMPONENT}.tar.gz.sha256" ; \
    tar -zxf "${COMPONENT}.tar.gz" -C /rootfs-app --strip-components=2 --no-same-owner ; \
    rm -f "${COMPONENT}.tar.gz"

# ---------------------------------------------------------------------------
# Stage 2 - RabbitMQ runtime image
# ---------------------------------------------------------------------------
FROM ${WOLFI_BASE}
USER 0

ARG WOLFI_BASE
ARG TARGETARCH
ARG OTP_VERSION="27.3.4.17"

LABEL org.opencontainers.image.base.name="${WOLFI_BASE}" \
      org.opencontainers.image.created="2026-09-17T00:00:00Z" \
      org.opencontainers.image.description="Application packaged by Broadcom, Inc." \
      org.opencontainers.image.documentation="https://github.com/bitnami/containers/tree/main/bitnami/rabbitmq/README.md" \
      org.opencontainers.image.source="https://github.com/bitnami/containers/tree/main/bitnami/rabbitmq" \
      org.opencontainers.image.title="rabbitmq" \
      org.opencontainers.image.vendor="Broadcom, Inc." \
      org.opencontainers.image.version="4.3.5"

ENV HOME="/opt/bitnami/rabbitmq/.rabbitmq" \
    OS_ARCH="${TARGETARCH:-amd64}" \
    OS_FLAVOUR="wolfi" \
    OS_NAME="linux" \
    PATH="/opt/bitnami/erlang/bin:/opt/bitnami/rabbitmq/sbin:$PATH"

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
#   procps                - pgrep/ps used by run.sh and the shutdown helpers
#   posix-libc-utils-bin  - getent, used by libnet.sh and libos.sh
#   glibc-locale-en       - en_US.UTF-8; no locale-gen (and no perl) needed
#   ncurses               - required by the Erlang runtime
#   wget                  - plugin download and HTTP readiness checks
#   erlang-27             - 27.3.4.17, the OTP patch release several advisories
#                           require and Bitnami publishes no component for
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
      glibc-locale-en \
      ncurses \
      wget \
      ca-certificates-bundle \
      erlang-27 && \
    rm -rf /var/cache/apk/*

# Fail the build if the Erlang we resolved is not the patch release this image
# claims to ship - a silent downgrade would reintroduce fixed OTP advisories.
RUN installed="$(apk info -v 2>/dev/null | grep '^erlang-27-' | head -1)" && \
    case "${installed}" in \
      "erlang-27-${OTP_VERSION}-"*) echo "erlang OK: ${installed}" ;; \
      *) echo "expected erlang-27 ${OTP_VERSION}, got '${installed}'" >&2 ; exit 1 ;; \
    esac && \
    erl -noshell -eval 'io:format("erts ~s / OTP ~s~n",[erlang:system_info(version),erlang:system_info(otp_release)]),halt().'

# The Bitnami layout expects Erlang under /opt/bitnami/erlang; Wolfi installs
# it to /usr/lib/erlang. Symlink rather than copy so apk keeps owning the
# files and the SBOM keeps reporting the package.
RUN mkdir -p /opt/bitnami && ln -s /usr/lib/erlang /opt/bitnami/erlang

# uid 1001 is the Bitnami convention. wolfi-base only ships "nonroot" (65532),
# so declare the account the image actually runs as.
RUN addgroup -g 1001 -S rabbitmq 2>/dev/null || true ; \
    adduser -u 1001 -G root -S -H -h /opt/bitnami/rabbitmq -s /sbin/nologin rabbitmq

# Wolfi merges sbin into bin (/usr/sbin and /sbin are symlinks to usr/bin),
# so the prebuildfs helpers live under usr/bin here rather than usr/sbin as
# they do in the Debian variants - COPY cannot write through that symlink.
COPY prebuildfs /
COPY --from=component /rootfs-app /opt/bitnami

RUN rm -rf /opt/bitnami/checksums
RUN chmod g+rwX /opt/bitnami
RUN find / -perm /6000 -type f -exec chmod a-s {} \; || true

COPY rootfs /
RUN /opt/bitnami/scripts/rabbitmq/postunpack.sh

ENV APP_VERSION="4.3.5" \
    BITNAMI_APP_NAME="rabbitmq" \
    IMAGE_REVISION="1" \
    LANG="en_US.UTF-8" \
    LANGUAGE="en_US:en"

EXPOSE 4369 5551 5552 5671 5672 15671 15672 25672

USER 1001
ENTRYPOINT [ "/opt/bitnami/scripts/rabbitmq/entrypoint.sh" ]
CMD [ "/opt/bitnami/scripts/rabbitmq/run.sh" ]

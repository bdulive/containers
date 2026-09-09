# Copyright Broadcom, Inc. All Rights Reserved.
# SPDX-License-Identifier: APACHE-2.0

# ---------------------------------------------------------------------------
# Stage 1 - Erlang/OTP security patch release, built from upstream source.
#
# The Bitnami "erlang" component is only published for OTP base releases (the
# newest available are 27.3.4 and 28.5). Every outstanding OTP advisory that
# affects this image is fixed exclusively in a four-component patch release,
# so no published component can clear them. We therefore compile the newest
# patch release of the same OTP line RabbitMQ 4.3.5 was built against
# (27.3.4.x), which keeps the runtime bit-for-bit compatible with the
# prebuilt RabbitMQ component while picking up every OTP security fix.
# ---------------------------------------------------------------------------
FROM docker.io/bitnami/minideb:trixie AS erlang-builder

ARG TARGETARCH
ARG OTP_VERSION="27.3.4.17"
ARG OTP_SRC_SHA256="56857d4e78e411252d6a5489a7f9870cf239b14250097ce3ceef97601905a2a9"

SHELL ["/bin/bash", "-o", "errexit", "-o", "nounset", "-o", "pipefail", "-c"]

RUN install_packages autoconf ca-certificates g++ gcc libc6-dev libncurses-dev libssl-dev make perl wget

RUN wget --quiet --tries=3 --output-document=/tmp/otp_src.tar.gz \
      "https://github.com/erlang/otp/releases/download/OTP-${OTP_VERSION}/otp_src_${OTP_VERSION}.tar.gz" && \
    echo "${OTP_SRC_SHA256}  /tmp/otp_src.tar.gz" | sha256sum -c - && \
    mkdir -p /tmp/otp && \
    tar -zxf /tmp/otp_src.tar.gz -C /tmp/otp --strip-components=1 && \
    rm -f /tmp/otp_src.tar.gz

WORKDIR /tmp/otp
# The excluded applications mirror the application set of the Bitnami erlang
# component: GUI, documentation and development-only apps are left out, every
# application RabbitMQ links against is kept.
RUN export ERL_TOP=/tmp/otp && \
    ./configure \
      --prefix=/opt/bitnami/erlang \
      --enable-threads \
      --enable-smp-support \
      --enable-kernel-poll \
      --with-ssl \
      --without-javac \
      --without-common_test \
      --without-debugger \
      --without-dialyzer \
      --without-diameter \
      --without-edoc \
      --without-erl_docgen \
      --without-et \
      --without-ftp \
      --without-jinterface \
      --without-megaco \
      --without-observer \
      --without-odbc \
      --without-ssh \
      --without-tftp \
      --without-wx && \
    make -j"$(nproc)" && \
    make install && \
    find /opt/bitnami/erlang -type d \( -name doc -o -name examples -o -name man \) -prune -exec rm -rf {} + && \
    find /opt/bitnami/erlang -type f -name '*.debug' -delete && \
    find /opt/bitnami/erlang -type f -executable \
      -exec sh -c 'for f; do strip --strip-unneeded "$f" 2>/dev/null || true; done' _ {} +

# Emit the component metadata that the prebuilt Bitnami component ships, so
# SBOM/CPE-based scanners keep reporting Erlang with an accurate version
# instead of not seeing it at all.
RUN mkdir -p /opt/bitnami/erlang/licenses && \
    cp /tmp/otp/LICENSE.txt "/opt/bitnami/erlang/licenses/erlang-${OTP_VERSION}.txt" && \
    cat > /opt/bitnami/erlang/.spdx-erlang.spdx <<EOF
{
    "SPDXID": "SPDXRef-DOCUMENT",
    "spdxVersion": "SPDX-2.3",
    "creationInfo": {
        "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "creators": [
            "Tool: containers/bitnami/rabbitmq/4.3/debian-13/Dockerfile"
        ]
    },
    "name": "SPDX document for Erlang ${OTP_VERSION}",
    "dataLicense": "CC0-1.0",
    "documentDescribes": [
        "SPDXRef-erlang"
    ],
    "documentNamespace": "pkg:bitnami/erlang@${OTP_VERSION}?arch=${TARGETARCH:-amd64}&distro=debian-13",
    "packages": [
        {
            "SPDXID": "SPDXRef-erlang",
            "name": "erlang",
            "versionInfo": "${OTP_VERSION}",
            "downloadLocation": "https://github.com/erlang/otp/releases/download/OTP-${OTP_VERSION}/otp_src_${OTP_VERSION}.tar.gz",
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "supplier": "Organization: upstream",
            "originator": "Organization: upstream",
            "primaryPackagePurpose": "APPLICATION",
            "filesAnalyzed": false,
            "externalRefs": [
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:erlang:erlang/otp:${OTP_VERSION}:*:*:*:*:*:*:*"
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:*:erlang:crypto:${OTP_VERSION}:*:*:*:*:*:*:*"
                },
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:bitnami/erlang@${OTP_VERSION}?arch=${TARGETARCH:-amd64}&distro=debian-13"
                }
            ],
            "copyrightText": "NOASSERTION"
        }
    ],
    "files": [],
    "hasExtractedLicensingInfos": [],
    "relationships": []
}
EOF

# ---------------------------------------------------------------------------
# Stage 2 - RabbitMQ runtime image
# ---------------------------------------------------------------------------
FROM docker.io/bitnami/minideb:trixie

ARG DOWNLOADS_URL="https://downloads.bitnami.com/files/stacksmith"
ARG TARGETARCH

LABEL org.opencontainers.image.base.name="docker.io/bitnami/minideb:trixie" \
      org.opencontainers.image.created="2026-09-09T00:00:00Z" \
      org.opencontainers.image.description="Application packaged by Broadcom, Inc." \
      org.opencontainers.image.documentation="https://github.com/bitnami/containers/tree/main/bitnami/rabbitmq/README.md" \
      org.opencontainers.image.source="https://github.com/bitnami/containers/tree/main/bitnami/rabbitmq" \
      org.opencontainers.image.title="rabbitmq" \
      org.opencontainers.image.vendor="Broadcom, Inc." \
      org.opencontainers.image.version="4.3.5"

ENV HOME="/opt/bitnami/rabbitmq/.rabbitmq" \
    OS_ARCH="${TARGETARCH:-amd64}" \
    OS_FLAVOUR="debian-13" \
    OS_NAME="linux" \
    PATH="/opt/bitnami/erlang/bin:/opt/bitnami/rabbitmq/sbin:$PATH"

COPY prebuildfs /
SHELL ["/bin/bash", "-o", "errexit", "-o", "nounset", "-o", "pipefail", "-c"]
# Install required system packages and dependencies.
#
# curl is deliberately not installed: libcurl4 hard-depends on libssh2-1,
# which has open heap-corruption advisories with no fix in Debian trixie.
# wget covers the same use cases (component download, plugin download,
# HTTP readiness checks) without pulling in libssh2.
RUN install_packages ca-certificates libgcc-s1 libssl3t64 libstdc++6 libtinfo6 locales openssl procps wget zlib1g
RUN --mount=type=secret,id=downloads_url,env=SECRET_DOWNLOADS_URL \
    DOWNLOADS_URL=${SECRET_DOWNLOADS_URL:-${DOWNLOADS_URL}} ; \
    mkdir -p /tmp/bitnami/pkg/cache/ ; cd /tmp/bitnami/pkg/cache/ || exit 1 ; \
    COMPONENTS=( \
      "rabbitmq-4.3.5-0-linux-${OS_ARCH}-debian-12" \
    ) ; \
    for COMPONENT in "${COMPONENTS[@]}"; do \
      if [ ! -f "${COMPONENT}.tar.gz" ]; then \
        wget --quiet --tries=3 "${DOWNLOADS_URL}/${COMPONENT}.tar.gz" ; \
      fi ; \
      sha256sum -c "/opt/bitnami/checksums/${COMPONENT}.tar.gz.sha256" ; \
      tar -zxf "${COMPONENT}.tar.gz" -C /opt/bitnami --strip-components=2 --no-same-owner ; \
      rm -rf "${COMPONENT}".tar.gz ; \
    done ; \
    rm -rf /opt/bitnami/checksums ;
COPY --from=erlang-builder /opt/bitnami/erlang /opt/bitnami/erlang
RUN apt-get update && apt-get upgrade -y && \
    apt-get clean && rm -rf /var/lib/apt/lists /var/cache/apt/archives
RUN chmod g+rwX /opt/bitnami
RUN find / -perm /6000 -type f -exec chmod a-s {} \; || true
RUN update-locale LANG=C.UTF-8 LC_MESSAGES=POSIX && \
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure locales && \
    echo 'en_US.UTF-8 UTF-8' >> /etc/locale.gen
RUN /opt/bitnami/scripts/locales/generate-locales.sh

COPY rootfs /
RUN /opt/bitnami/scripts/rabbitmq/postunpack.sh
# Drop Perl. Neither RabbitMQ nor the Bitnami scripts use it at runtime, and
# no Debian release currently ships a fix for the outstanding perl advisories,
# so removal is the only available remediation. perl-base is marked Essential
# (it backs debconf), hence the force flags - this has to stay the final
# dpkg/apt operation of the build.
RUN dpkg --purge --force-remove-essential --force-depends \
      perl perl-modules-5.40 libperl5.40 perl-base && \
    rm -rf /usr/share/perl /usr/share/perl5 /usr/lib/*/perl /usr/lib/*/perl5 && \
    ! command -v perl
ENV APP_VERSION="4.3.5" \
    BITNAMI_APP_NAME="rabbitmq" \
    IMAGE_REVISION="0" \
    LANG="en_US.UTF-8" \
    LANGUAGE="en_US:en"

EXPOSE 4369 5551 5552 5671 5672 15671 15672 25672

USER 1001
ENTRYPOINT [ "/opt/bitnami/scripts/rabbitmq/entrypoint.sh" ]
CMD [ "/opt/bitnami/scripts/rabbitmq/run.sh" ]

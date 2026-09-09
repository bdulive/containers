# RabbitMQ 4.3 - Debian 13 (CVE-remediated variant)

This is a hardened variant of `bitnami/rabbitmq:4.3.5-debian-12-r*` that clears all
26 CVEs reported against that image. It reuses the published Bitnami RabbitMQ
component unchanged; only the base OS, the Erlang runtime and the HTTP client are
different.

## What changed and why

| Change | Reason |
| --- | --- |
| Base image `bitnami/minideb:bookworm` -> `bitnami/minideb:trixie` | The four OpenSSL advisories are fixed only in Debian 13 (`openssl 3.5.7-1~deb13u2`, DSA-6465-1). Debian 12 still ships the vulnerable `3.0.20-1~deb12u2` with no fix available. |
| Erlang/OTP: prebuilt Bitnami component -> OTP `27.3.4.17` compiled from upstream source in a builder stage | Every OTP advisory is fixed only in a four-component patch release (highest required: `27.3.4.15`). Bitnami publishes components for base releases only - the newest available are `27.3.4` and `28.5`, both still vulnerable. Staying on the `27.3.4` line keeps the runtime identical to what RabbitMQ 4.3.5 was built against. |
| `curl` removed, `wget` used instead | `libcurl4` hard-depends on `libssh2-1`, which has three open heap-corruption advisories with no fix in Debian 13. `wget` has no libssh2 dependency. |
| `perl`, `perl-base`, `perl-modules-*`, `libperl*` purged | The eight perl advisories are unfixed in **every** Debian release, so removal is the only remediation. Neither RabbitMQ (pure BEAM, no native code) nor the Bitnami scripts use perl at runtime. |
| `libssl3` -> `libssl3t64` in the package list | Debian 13 package rename (time_t transition). |
| `rabbitmq` component still built for `debian-12` | Bitnami does not publish a `debian-13` build. The tarball contains zero native objects (`.so`), so it is portable across Debian releases and OTP patch levels. |

### RabbitMQ code changes

Three `curl` call sites were converted to `wget`:

- [`prebuildfs/opt/bitnami/scripts/libnet.sh`](prebuildfs/opt/bitnami/scripts/libnet.sh) - `wait_for_http_connection` (unused in this image)
- [`rootfs/opt/bitnami/scripts/librabbitmq.sh`](rootfs/opt/bitnami/scripts/librabbitmq.sh) - `rabbitmq_download_community_plugins`; `file://` URLs are now copied directly because GNU wget cannot read them
- [`rootfs/opt/bitnami/scripts/rabbitmq/apicheck.sh`](rootfs/opt/bitnami/scripts/rabbitmq/apicheck.sh) - reached only from `healthcheck.sh`, which nothing in the image invokes

And one perl call site:

- [`prebuildfs/opt/bitnami/scripts/libfile.sh`](prebuildfs/opt/bitnami/scripts/libfile.sh) - `replace_in_file_multiline` now uses `sed -z -E`, which gives the same "slurp the file, let `.` match newlines" semantics as perl's `undef $/` plus the `/s` flag. Unused in this image, and sed's ERE is narrower than perl's regex, so a future caller using perl-only syntax must translate it. (`replace_in_file`, the function RabbitMQ actually calls, already used `sed`.)

Everything else - entrypoint, `run.sh`, environment variables, exposed ports, volumes,
non-root UID 1001 - is unchanged from the `debian-12` variant.

## CVE remediation map

All 26 unique CVEs from the scan report (6 CRITICAL, 20 HIGH):

**Erlang/OTP `27.3.4` -> `27.3.4.17`** (11)

CVE-2026-28808 (C), CVE-2026-23941 (C), CVE-2026-32144, CVE-2026-42790,
CVE-2026-49759, CVE-2026-55952, CVE-2026-54890, CVE-2026-55737, CVE-2026-58227,
CVE-2026-55953, CVE-2026-59251

**`openssl` / `libssl3` `3.0.20-1~deb12u2` -> `3.5.7-1~deb13u2`** (4)

CVE-2026-75803 (C), CVE-2026-63076, CVE-2026-54874, CVE-2026-63072

**`perl` / `perl-base` / `perl-modules-*` / `libperl*` removed** (8)

CVE-2026-12087 (C), CVE-2026-13221 (C), CVE-2026-57433 (C), CVE-2026-48959,
CVE-2026-48961, CVE-2026-48962, CVE-2026-57432, CVE-2026-7017

**`libssh2-1` removed with `curl`** (3)

CVE-2026-66034, CVE-2026-58050, CVE-2026-66032

## Build

```console
docker build -t bitnami/rabbitmq:4.3.5-debian-13-r0 .
```

The Erlang builder stage compiles OTP from source, so a cold build takes roughly
15-25 minutes. To move to a newer OTP patch release, bump the two build args at
the top of the [Dockerfile](Dockerfile):

```console
docker build \
  --build-arg OTP_VERSION=27.3.4.17 \
  --build-arg OTP_SRC_SHA256=56857d4e78e411252d6a5489a7f9870cf239b14250097ce3ceef97601905a2a9 \
  -t bitnami/rabbitmq:4.3.5-debian-13-r0 .
```

## Verify

Trivy is necessary but **not sufficient** here - see [How each CVE was
verified](#how-each-cve-was-verified) for why. The per-package evidence below is
what actually re-validates the remediation map.

```console
# OpenSSL: the Debian changelog names the four CVEs it fixes
docker run --rm bitnami/rabbitmq:4.3.5-debian-13-r0 \
  bash -c 'zcat /usr/share/doc/openssl/changelog.Debian.gz | grep -E "CVE-2026-(63072|63076|54874|75803)"'

# Erlang/OTP: patch level and the per-application versions the advisories name
docker run --rm bitnami/rabbitmq:4.3.5-debian-13-r0 bash -c '
  cat /opt/bitnami/erlang/lib/erlang/releases/27/OTP_VERSION
  ls -d /opt/bitnami/erlang/lib/erlang/lib/{inets,ssl,public_key,erts,crypto}-*'

# perl and libssh2: gone, not merely upgraded
docker run --rm bitnami/rabbitmq:4.3.5-debian-13-r0 bash -c '
  dpkg-query -W -f="\${Package}\n" | grep -E "^(perl|libperl|libssh2)" || echo "no perl/libperl/libssh2 packages"
  command -v perl curl || echo "no perl, no curl"
  find / -name "libssh2*" 2>/dev/null | wc -l'

# broker comes up
docker run -d --name rmq-verify -e RABBITMQ_PASSWORD=bitnami123 \
  bitnami/rabbitmq:4.3.5-debian-13-r0
docker exec rmq-verify rabbitmq-diagnostics -q check_running
docker exec rmq-verify rabbitmq-diagnostics -q check_port_connectivity
```

## Verification results

Built and smoke-tested for `linux/arm64` on 2026-09-09 (the same Dockerfile builds
`linux/amd64`; the Debian 13 package set and versions were confirmed on amd64).

Trivy 0.74.0 (vulnerability DB of 2026-09-09), `CRITICAL,HIGH`, OS packages plus
Bitnami components, scanning the exported rootfs:

| Image | Findings | CRITICAL | HIGH | Distinct CVEs |
| --- | --- | --- | --- | --- |
| `4.3.5-debian-12` (baseline, built from the sibling directory) | 91 | 13 | 78 | 24 |
| `4.3.5-debian-13-r0` | 47 | 0 | 47 | 12 |

Every one of the 47 residual HIGH findings has an empty `FixedVersion` - no fix
exists in Debian 13 today. They are in `util-linux`/`login`/`mount` (12), the
`libblkid1`/`libmount1`/`libuuid1`/`libsmartcols1`/`liblastlog2-2` family (20),
`bsdutils` (4), `libsqlite3-0` (2), `wget` (2), and one each in `gzip`, `libacl1`,
`libncursesw6`, `ncurses-base`, `libsystemd0`, `libtinfo6`, `libudev1`. None of
them appear in the scan report this image was built to clear.

### How each CVE was verified

Trivy's database carries only **4 of the 26** CVEs from the scan report:
CVE-2026-13221, CVE-2026-48962, CVE-2026-57432 and CVE-2026-57433, all against
`perl`. Those four are reported on the baseline and are gone from
`4.3.5-debian-13-r0`. The other **22 are unknown to Trivy** - they appear in
neither scan, so the drop from 91 to 47 findings does not by itself prove
anything about them. Re-running Trivy will never re-validate the remediation map;
these are the checks that do:

| CVEs | Evidence |
| --- | --- |
| OpenSSL (4): CVE-2026-75803, -63072, -63076, -54874 | `/usr/share/doc/openssl/changelog.Debian.gz` in the built image names all four as fixed in `3.5.7-1~deb13u2`; installed version is `3.5.7`. |
| Erlang/OTP (11) | Image reports OTP `27.3.4.17`, above the highest fix version any of the 11 requires (`27.3.4.15`). Per-application versions `inets-9.3.2.7`, `ssl-11.2.12.12`, `public_key-1.17.1.5`, `erts-15.2.7.13`, `crypto-5.5.3.5` each meet or exceed the fixed version named in the corresponding advisory. |
| perl (8) | Package and files entirely absent: zero `perl*`/`libperl*` entries in the dpkg status, no `/usr/bin/perl`. Removal, not an upgrade - no Debian release ships a fix. |
| libssh2 (3) | Package and files entirely absent: `find / -name 'libssh2*'` is empty, and `curl`, the only thing that pulled it in, is not installed. |

Runtime checks against the built image:

- `rabbitmq-diagnostics check_running`, `check_port_connectivity`, `check_virtual_hosts` all pass; broker boots in ~1.8s
- `RabbitMQ version: 4.3.5`, `Erlang/OTP 27 [erts-15.2.7.13]`, `Crypto library: OpenSSL 3.5.7`
- Queue declare, publish and consume over the management API succeed
- The `wget` path in `apicheck.sh` returns `{"status":"ok"}`
- `rabbitmq_hash_password` (which shells out to the `openssl` CLI) produces a valid 92-char hash
- `install_packages` still works despite the perl purge
- Trivy still reports the Erlang component (via a generated SPDX document) at `27.3.4.17`, so the runtime is not hidden from SBOM/CPE scanners

## Maintenance note

The `debian-12` tree in this repository is generated by the Bitnami release
pipeline and is left untouched. This directory is a hand-maintained overlay: when
Bitnami publishes a `debian-13` RabbitMQ component, or an Erlang component at a
patch release, the corresponding change here can be dropped in favour of the
upstream component.

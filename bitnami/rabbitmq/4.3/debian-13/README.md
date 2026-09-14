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

## Third-party rescan, 2026-09-14

A follow-up third-party scan reported four findings against this variant. All four are
still reported by grype and Trivy against the current build, and **no rebuild removes
them**. Three are genuinely unfixed in Debian 13; one does not apply to this image at
all.

| CVE | Package | Installed | Disposition |
| --- | --- | --- | --- |
| CVE-2026-54369 | `libacl1` | `2.3.2-2+b1` | **Affected, no fix available.** Fixed upstream in acl 2.4.0, which Debian has not backported to trixie. |
| CVE-2026-54370 | `libacl1` | `2.3.2-2+b1` | **Affected, no fix available**, same package. The TOCTOU race is in the `getfacl`/`setfacl`/`chacl` utilities, which ship in the `acl` binary package - not installed here. |
| CVE-2026-54371 | `libattr1` | `1:2.5.2-3` | **Affected, no fix available.** Fixed upstream in attr 2.6.0, not backported. The affected `getfattr`/`setfattr` utilities ship in the `attr` package - not installed here. |
| CVE-2026-85091 | `zlib1g` | `1:1.3.dfsg+really1.3.1-1+b1` | **Not affected - vulnerable code not present.** See below. |

### Why no rebuild clears them

Debian declined to backport the acl and attr fixes to trixie: acl 2.4.0 changes the ABI
and attr 2.6.0 rewrites `walk_tree`, so both are deferred to a stable point release and
marked `no-dsa` / "minor issue". Debian's trixie security feed therefore carries **no
fixed version** for either source package, and a distro-matching scanner reports
`versionConstraint: "none (unknown)"` - it flags the package at *any* version.

That is what `wont-fix` in the scanner output means here: Debian has decided not to ship
a security update for trixie, not that the flaw is unfixable. `not-fixed` on the zlib row
means something different - no fix exists anywhere yet, sid included.

Removing the packages was prototyped and rejected. `libacl1` and `libattr1` are
dependencies of `coreutils`, `tar`, `sed` and `passwd`, so removal means replacing the
GNU userland: busybox does it but brings 14 advisories of its own (8 HIGH), and toybox -
which brings none - has no `tr` or `dd`, which the Bitnami scripts use on live paths.
Patching around that means editing `prebuildfs/` and `rootfs/`, the files rebased against
upstream on every Bitnami release, which is the one kind of divergence this variant
exists to avoid. Measurements and traps are in [CLAUDE.md](../../CLAUDE.md).

**These rows clear themselves** when the Debian trixie point release ships acl 2.4.0 and
attr 2.6.0. No action is needed here; a rebuild after that date picks them up through the
existing `apt-get upgrade` step.

### CVE-2026-85091 (zlib): not affected

The advisory covers upstream zlib **1.3.1.2 through 1.3.2**. Debian 13 ships upstream
**1.3.1**, below that floor. Verified three ways:

- `zlib1g 1:1.3.dfsg+really1.3.1-1+b1`; the Debian source package declares
  `ZLIB_VERSION "1.3.1"` / `ZLIB_VERNUM 0x1310`, and the shipped `libz.so.1` self-reports
  `1.3.1`.
- `gz_vacate()`, the function containing the heap overflow, does not exist anywhere in
  that source tree. It appears first in upstream `v1.3.1.2` (0 occurrences in
  `v1.3.1/gzwrite.c`, 5 in `v1.3.1.2/gzwrite.c`).
- Debian applies no patch that introduces it - the trixie patch series is empty.

There is also nothing to upgrade to: Debian marks sid (`really1.3.2`) vulnerable as well,
and GHSA-g5fp-32jq-cfw2 lists no patched version.

### Scanner severities differ

Both scanners report all four; a `--severity CRITICAL,HIGH` Trivy run hides three of them.

| CVE | grype | Trivy |
| --- | --- | --- |
| CVE-2026-54369 | High, `wont-fix` | HIGH, `affected` |
| CVE-2026-54370 | High, `wont-fix` | MEDIUM, `affected` |
| CVE-2026-54371 | Medium, `wont-fix` | MEDIUM, `affected` |
| CVE-2026-85091 | High, `not-fixed` | MEDIUM, `affected` |

Neither offers a `FixedVersion` for any of them.

## Build

This variant is published as a multi-architecture image (`linux/amd64`,
`linux/arm64`). `-r1` - a rebuild on the current Debian 13 package set - is built and
verified on both architectures but **not yet pushed**:

```console
docker pull insightfinderinc/bitnami-rabbitmq:4.3.5-debian-13-r0   # published
```

To build it yourself instead:

```console
docker build -t bitnami/rabbitmq:4.3.5-debian-13-r1 .
```

The Erlang builder stage compiles OTP from source, so a cold build takes roughly
15-25 minutes. To move to a newer OTP patch release, bump the two build args at
the top of the [Dockerfile](Dockerfile):

```console
docker build \
  --build-arg OTP_VERSION=27.3.4.17 \
  --build-arg OTP_SRC_SHA256=56857d4e78e411252d6a5489a7f9870cf239b14250097ce3ceef97601905a2a9 \
  -t bitnami/rabbitmq:4.3.5-debian-13-r1 .
```

## Verify

Use **grype** as the primary scanner, not Trivy. For this image Trivy's database
carries only 4 of the 26 CVEs from the scan report, while grype carries 23 - see
[Scanner coverage](#scanner-coverage). Both scanners need the *exported rootfs*:
Docker 29 writes an OCI layout that Trivy and Docker Scout reject when reading the
daemon image directly (`archive/tar: invalid tar header`) - and so does grype, which
reports the same failure as `docker: failed to read layer=...`. A pushed registry
reference scans directly with either tool.

```console
docker create --name probe bitnami/rabbitmq:4.3.5-debian-13-r1
mkdir fs && docker export probe | tar -x -C fs && docker rm -f probe

grype db update
grype dir:fs                       # expect: no finding with fix state "fixed"
trivy rootfs --scanners vuln --severity CRITICAL,HIGH fs
docker scout cves --only-severity critical,high fs://fs
```

The pass condition is **no finding with an available fix**, not a zero total:
everything left in this image is `wont-fix` or `not-fixed` upstream.

Three of the 26 (the libssh2 CVEs) are in no scanner's database yet, so they are
verified by the package being absent. The per-package checks:

```console
# OpenSSL: the Debian changelog names the four CVEs it fixes
docker run --rm bitnami/rabbitmq:4.3.5-debian-13-r1 \
  bash -c 'zcat /usr/share/doc/openssl/changelog.Debian.gz | grep -E "CVE-2026-(63072|63076|54874|75803)"'

# Erlang/OTP: patch level and the per-application versions the advisories name
docker run --rm bitnami/rabbitmq:4.3.5-debian-13-r1 bash -c '
  cat /opt/bitnami/erlang/lib/erlang/releases/27/OTP_VERSION
  ls -d /opt/bitnami/erlang/lib/erlang/lib/{inets,ssl,public_key,erts,crypto}-*'

# perl and libssh2: gone, not merely upgraded
docker run --rm bitnami/rabbitmq:4.3.5-debian-13-r1 bash -c '
  dpkg-query -W -f="\${Package}\n" | grep -E "^(perl|libperl|libssh2)" || echo "no perl/libperl/libssh2 packages"
  command -v perl curl || echo "no perl, no curl"
  find / -name "libssh2*" 2>/dev/null | wc -l'

# broker comes up
docker run -d --name rmq-verify -e RABBITMQ_PASSWORD=bitnami123 \
  bitnami/rabbitmq:4.3.5-debian-13-r1
docker exec rmq-verify rabbitmq-diagnostics -q check_running
docker exec rmq-verify rabbitmq-diagnostics -q check_port_connectivity
```

## Verification results

Built and smoke-tested for **both `linux/amd64` and `linux/arm64`** - `-r0` on
2026-09-09, `-r1` rebuilt and rescanned on the current package set 2026-09-14.
On each architecture: the broker reaches `rabbitmqctl status` reporting RabbitMQ
4.3.5 on `erts-15.2.7.13` (OTP 27.3.4.17, source-built) with `Crypto library:
OpenSSL 3.5.7`, and a durable quorum queue survives declare -> publish -> consume
(`{"routed":true}`, payload returned intact). On arm64 a real AMQP client (pika,
port 5672) additionally exercised 100-message classic queues, 50-message quorum
queues and topic-exchange routing including a negative match, and all four durable
queues plus a persisted message survived a container restart.

Grype 0.118.0, all severities, exported rootfs. The `-r1` row is identical on both
architectures (182 / 0 / 49 on each):

| Image | Matches | Critical | High | **With an available fix** |
| --- | --- | --- | --- | --- |
| `4.3.5-debian-12` (baseline, built from the sibling directory) | 443 | 36 | 110 | **52** |
| `4.3.5-debian-13-r1` | 182 | **0** | 49 | **0** |

Every remaining finding is `wont-fix` or `not-fixed` upstream - nothing left can be
cleared by rebuilding. All 52 fixable baseline findings were against `erlang`.

Trivy 0.74.0, **all severities** (not `CRITICAL,HIGH` - three of the four CVEs in the
[third-party rescan](#third-party-rescan-2026-09-14) are `MEDIUM` to Trivy and a
filtered run hides them). Identical on both architectures:

| Image | Findings | CRITICAL | HIGH | With a `FixedVersion` |
| --- | --- | --- | --- | --- |
| `4.3.5-debian-13-r1` | 189 | **0** | 44 | **0** |

Trivy also reports the two `bitnami` targets - `opt/bitnami/erlang` and
`opt/bitnami/rabbitmq` - as clean, confirming the source-built OTP is being read
through the generated SPDX rather than skipped.

**No CRITICAL findings remain.** The 4 that `-r0` carried were a single CVE,
`CVE-2026-5450` in glibc, counted across `libc6`, `libc-bin`, `libc-l10n` and
`locales`. Debian has since fixed it and the rebuild picked up
`libc6 2.41-12+deb13u4` through the existing `apt-get upgrade` step.

The one remaining notable non-report finding is **CVE-2026-85091** (zlib,
`not-fixed`), which the debian-12 baseline carries too and which this image is
[not affected by](#third-party-rescan-2026-09-14).

### Scanner coverage

The three scanners disagree sharply about the 26 CVEs in the scan report, so the
choice of tool matters more than usual here:

| Scanner | Carries how many of the 26 | Still present in this image |
| --- | --- | --- |
| grype 0.118.0 | **23** | 0 |
| Docker Scout | 9 | 0 |
| Trivy 0.74.0 | 4 (all `perl`) | 0 |

Grype reports 23 of the 26 on the debian-12 baseline and none on this image, which
is the direct before/after evidence. The remaining three - CVE-2026-58050,
CVE-2026-66032, CVE-2026-66034, all `libssh2` - are in **no** scanner's database
yet (grype reports zero findings of any kind against `libssh2-1` on the baseline),
so they rest on the package being absent.

Per CVE class:

| CVEs | Evidence |
| --- | --- |
| OpenSSL (4): CVE-2026-75803, -63072, -63076, -54874 | Reported by grype and Scout on the baseline, by neither here. `/usr/share/doc/openssl/changelog.Debian.gz` names all four as fixed in `3.5.7-1~deb13u2`; installed version is `3.5.7`. |
| Erlang/OTP (11) | Reported by grype on the baseline, not here. Image reports OTP `27.3.4.17`, above the highest fix version any of the 11 requires (`27.3.4.15`); `inets-9.3.2.7`, `ssl-11.2.12.12`, `public_key-1.17.1.5`, `erts-15.2.7.13`, `crypto-5.5.3.5` each meet or exceed their advisory's fix version. |
| perl (8) | Reported by all three scanners on the baseline, by none here. Package and files entirely absent - removal, not an upgrade, since no Debian release ships a fix. |
| libssh2 (3) | Not in any scanner database. `find / -name 'libssh2*'` is empty and `curl`, the only thing that pulled it in, is not installed. |

### Fixed beyond the scan report

The source-built OTP also cleared 14 HIGH Erlang CVEs that the prebuilt Bitnami
`erlang` component still carries and that were not in the scan report:
CVE-2025-48041, CVE-2026-42792, CVE-2026-55951, CVE-2026-59250, CVE-2026-66357,
CVE-2026-66835, CVE-2026-69664, CVE-2026-70399, CVE-2026-71380, CVE-2026-73270,
CVE-2026-73276, CVE-2026-73812, CVE-2026-74835, CVE-2026-75538.

Runtime checks against the built image:

- `rabbitmq-diagnostics check_running`, `check_port_connectivity`, `check_virtual_hosts` all pass; broker boots in ~2.2s
- `RabbitMQ version: 4.3.5`, `Erlang/OTP 27 [erts-15.2.7.13]`, `Crypto library: OpenSSL 3.5.7`
- Queue declare, publish and consume over the management API succeed
- The `wget` path in `apicheck.sh` returns `{"status":"ok"}`
- `rabbitmq_hash_password` (which shells out to the `openssl` CLI) produces a valid 92-char hash
- `install_packages` still works despite the perl purge
- Scanners still see the Erlang component (via the generated SPDX document) at `27.3.4.17`, so the runtime is not hidden from SBOM/CPE scanners

## Maintenance note

The `debian-12` tree in this repository is generated by the Bitnami release
pipeline and is left untouched. This directory is a hand-maintained overlay: when
Bitnami publishes a `debian-13` RabbitMQ component, or an Erlang component at a
patch release, the corresponding change here can be dropped in favour of the
upstream component.

# Redis Cluster 8.10 - Debian 13 (CVE-remediated variant)

This is a hardened variant of `bitnami/redis-cluster:8.10.1-debian-12-r*` that clears all
12 CVEs reported against that image. A follow-up third-party scan raised four further
advisories; three are unfixed in Debian 13 and one does not apply to this image - see
[Third-party rescan](#third-party-rescan-2026-09-14). It reuses the published Bitnami `redis` and
`wait-for-port` components unchanged; only the base OS and the build-time HTTP client
are different.

## What changed and why

| Change | Reason |
| --- | --- |
| Base image `bitnami/minideb:bookworm` -> `bitnami/minideb:trixie` | The four OpenSSL advisories are fixed only in Debian 13 (`openssl 3.5.7-1~deb13u2`). Debian 12 still ships the vulnerable `3.0.20-1~deb12u2` with no fix available. |
| All `perl*` / `libperl*` packages purged (`perl`, `perl-base`, `perl-modules-5.40`, `libperl5.40` on trixie today; the set is discovered at build time, not pinned) | The eight perl advisories are unfixed in **every** Debian release, so removal is the only remediation. Neither Redis nor the Bitnami scripts use perl at runtime. |
| `libssl3` -> `libssl3t64` in the package list | Debian 13 package rename (64-bit `time_t` transition). |
| `curl` removed, `wget` used to download components, then `wget` itself purged | `libcurl4` hard-depends on `libssh2-1`, which has open heap-corruption advisories with no fix in Debian 13. `wget` is only needed to fetch the components, so the build ends it with `uninstall_packages wget` - mirroring the `debian-12` variant's closing `uninstall_packages curl`. `autoremove --purge` takes the gnutls/idn2/nettle/psl dependency chain with it, keeping seven unfixable advisories out of the shipped image. Neither HTTP client is present at runtime. |
| `redis` / `wait-for-port` components still built for `debian-12` | Bitnami does not publish `debian-13` builds. `redis-server` links only against `libm`, `libssl`/`libcrypto`, `libc`, `libz` and `libzstd`, all of which Debian 13 provides at compatible SONAMEs; `wait-for-port` is a static-ish Go binary needing only `libc`. |

### Script changes

**None.** `prebuildfs/` and `rootfs/` are byte-identical to the `debian-12` variant,
which keeps this variant trivial to rebase onto future upstream releases.

Two shared library functions still reference tools this image no longer has, and are
deliberately left alone because neither is reachable here:

- `libfile.sh` `replace_in_file_multiline` calls `perl`. Nothing in the image calls it -
  `redis_conf_set` goes through `replace_in_file`, which uses `sed`.
- `libnet.sh` `wait_for_http_connection` calls `curl`. Nothing calls it either, and it
  was already broken in `debian-12`, which ends its build with `uninstall_packages curl`.
  This variant ends with `uninstall_packages wget`, so it stays equally unreachable.

A future caller of either would need to convert it first. Neither affects the CVE
result, which comes entirely from the package changes in the Dockerfile.

## CVE remediation map

All 12 unique CVEs from the scan report (4 CRITICAL, 8 HIGH):

**`openssl` / `libssl3` `3.0.20-1~deb12u2` -> `libssl3t64` / `openssl` `3.5.7-1~deb13u2`** (4)

CVE-2026-75803 (C), CVE-2026-63072, CVE-2026-63076, CVE-2026-54874

**`perl` / `perl-base` / `perl-modules-*` / `libperl*` removed** (8)

CVE-2026-12087 (C), CVE-2026-13221 (C), CVE-2026-57433 (C), CVE-2026-7017,
CVE-2026-48959, CVE-2026-48961, CVE-2026-48962, CVE-2026-57432

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

`-r0` is published as a multi-architecture image (`linux/amd64`, `linux/arm64`).
`-r1` - a rebuild on the current Debian 13 package set - is built and verified on both
architectures but **not yet pushed**:

```console
docker pull insightfinderinc/bitnami-redis-cluster:8.10.1-debian-13-r0   # published
```

To build it yourself instead:

```console
docker build -t bitnami/redis-cluster:8.10.1-debian-13-r1 .
```

## Verify

Use **grype** as the primary scanner. Its database carries all 12 CVEs from the scan
report; Trivy's carries only 4 - see [Scanner coverage](#scanner-coverage). Both
scanners need the *exported rootfs*: Docker 29 writes an OCI layout that Trivy rejects
when reading the daemon image directly (`archive/tar: invalid tar header`) - and so
does grype, which reports the same failure as `docker: failed to read layer=...`. A
pushed registry reference scans directly with either tool.

```console
docker create --name probe bitnami/redis-cluster:8.10.1-debian-13-r1
mkdir fs && docker export probe | tar -x -C fs && docker rm -f probe

grype db update
grype dir:fs
trivy rootfs --scanners vuln --severity CRITICAL,HIGH fs
```

The pass condition is **no finding with an available fix**, not a zero total:
everything left in this image is `wont-fix` or `not-fixed` upstream.

Per-package checks:

```console
# OpenSSL: the Debian changelog names the four CVEs it fixes
docker run --rm --entrypoint bash bitnami/redis-cluster:8.10.1-debian-13-r1 -c \
  'dpkg-query -W | grep -i ssl
   zcat /usr/share/doc/openssl/changelog.Debian.gz |
     grep -oE "CVE-2026-(63072|63076|54874|75803)" | sort -u'

# perl: gone, not merely upgraded
docker run --rm --entrypoint bash bitnami/redis-cluster:8.10.1-debian-13-r1 -c \
  'dpkg-query -W | grep -E "^(perl|libperl)" || echo "no perl packages"
   command -v perl || echo "no perl binary"'

# redis binaries resolve against Debian 13 libraries
docker run --rm --entrypoint bash bitnami/redis-cluster:8.10.1-debian-13-r1 -c \
  'ldd /opt/bitnami/redis/bin/redis-server; redis-server --version'

# a real 6-node cluster forms and serves traffic
docker compose -p rcverify up -d
docker exec rcverify-redis-node-0-1 redis-cli -a bitnami --no-auth-warning cluster info
docker exec rcverify-redis-node-0-1 redis-cli -c -a bitnami --no-auth-warning set alpha val
docker exec rcverify-redis-node-2-1 redis-cli -c -a bitnami --no-auth-warning get alpha
docker compose -p rcverify down -v
```

## Verification results

grype 0.118.0 and Trivy 0.74.0, rebuilt and rescanned 2026-09-14. Both `linux/amd64`
and `linux/arm64` were built and scanned and are identical on every row of this table.

The grype total dropped from 156 to 145 when `uninstall_packages wget` was added:
the seven `wget` advisories and their gnutls/idn2/nettle/psl dependants leave with
the package.

| | `8.10.1-debian-12-r0` (baseline) | `8.10.1-debian-13-r1` |
| --- | --- | --- |
| grype, all severities | 282 findings, 24 CRITICAL | **139 findings, 0 CRITICAL** |
| grype, findings with an available fix | 0 | **0** |
| Trivy, all severities | - | **145 findings, 0 CRITICAL, 42 HIGH** |
| Trivy, findings with a `FixedVersion` | 0 | **0** |
| CVEs from the scan report still present | **12 of 12** | **0 of 12** |

**The image now carries no CRITICAL findings at all.** The two that `-r0` had were
`CVE-2026-5450` in `libc6`/`libc-bin`, which Debian has since fixed - the rebuild picked
up `libc6 2.41-12+deb13u4` through the existing `apt-get upgrade` step, and grype no
longer reports that CVE - the ordinary payoff of rebuilding on the current package set.

Trivy's figure is quoted at all severities here rather than `CRITICAL,HIGH`, because
three of the four CVEs in the [third-party rescan](#third-party-rescan-2026-09-14) are
`MEDIUM` to Trivy and a filtered run hides them.

Functional check: a 6-node cluster from [`docker-compose.yml`](docker-compose.yml)
reached `cluster_state:ok` with 3 masters, 3 replicas and all 16384 slots assigned;
keys written through one node were read back through another via `-c` redirects, and
`info replication` showed the replica online. Killing a master container is survived with no data
loss: the cluster marked the node `fail` after ~22s (`cluster-node-timeout`), the replica
was promoted ~4s later, full 16384-slot coverage returned ~2s after that, and all 10 test
keys were readable through the promoted master with writes accepted afterwards.

Measure that sequence in that order if you re-run it. Polling `cluster_state:ok` straight
after the kill reads the *pre-failure* view - the surviving nodes have not noticed yet -
and reads taken in that window return empty for keys on the dead master, which looks
exactly like data loss and is not. Wait for `fail` in `cluster nodes`, then for the
replica's `role` to become `master`, then for `cluster_slots_ok:16384`.

### Scanner coverage

Of the 12 CVEs in the scan report:

| Scanner | CVEs in DB | Baseline hits | debian-13 hits |
| --- | --- | --- | --- |
| grype 0.118.0 | 12 | 12 | 0 |
| Trivy 0.74.0 | 4 | 4 | 0 |

grype confirms every CVE in the report individually, so the delta here is a complete
proof rather than a partial one - unlike the `rabbitmq` debian-13 variant, no CVE in
this report has to be verified by package absence alone.

# Redis Cluster 8.10 - Debian 13 (CVE-remediated variant)

This is a hardened variant of `bitnami/redis-cluster:8.10.1-debian-12-r*` that clears all
12 CVEs reported against that image. It reuses the published Bitnami `redis` and
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

## Build

This variant is published as a multi-architecture image (`linux/amd64`,
`linux/arm64`):

```console
docker pull insightfinderinc/bitnami-redis-cluster:8.10.1-debian-13-r0
```

To build it yourself instead:

```console
docker build -t bitnami/redis-cluster:8.10.1-debian-13-r0 .
```

## Verify

Use **grype** as the primary scanner. Its database carries all 12 CVEs from the scan
report; Trivy's carries only 4 - see [Scanner coverage](#scanner-coverage). Both
scanners need the *exported rootfs*: Docker 29 writes an OCI layout that Trivy rejects
when reading the daemon image directly (`archive/tar: invalid tar header`).

```console
docker create --name probe bitnami/redis-cluster:8.10.1-debian-13-r0
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
docker run --rm --entrypoint bash bitnami/redis-cluster:8.10.1-debian-13-r0 -c \
  'dpkg-query -W | grep -i ssl
   zcat /usr/share/doc/openssl/changelog.Debian.gz |
     grep -oE "CVE-2026-(63072|63076|54874|75803)" | sort -u'

# perl: gone, not merely upgraded
docker run --rm --entrypoint bash bitnami/redis-cluster:8.10.1-debian-13-r0 -c \
  'dpkg-query -W | grep -E "^(perl|libperl)" || echo "no perl packages"
   command -v perl || echo "no perl binary"'

# redis binaries resolve against Debian 13 libraries
docker run --rm --entrypoint bash bitnami/redis-cluster:8.10.1-debian-13-r0 -c \
  'ldd /opt/bitnami/redis/bin/redis-server; redis-server --version'

# a real 6-node cluster forms and serves traffic
docker compose -p rcverify up -d
docker exec rcverify-redis-node-0-1 redis-cli -a bitnami --no-auth-warning cluster info
docker exec rcverify-redis-node-0-1 redis-cli -c -a bitnami --no-auth-warning set alpha val
docker exec rcverify-redis-node-2-1 redis-cli -c -a bitnami --no-auth-warning get alpha
docker compose -p rcverify down -v
```

## Verification results

grype 0.118.0 and Trivy 0.74.0, databases as of 2026-09-09. Both `linux/amd64` and
`linux/arm64` were built and scanned, and are identical on every row of this table
(145 grype findings, 2 CRITICAL, 0 fixable, 0 of the 12).

The grype total dropped from 156 to 145 when `uninstall_packages wget` was added:
the seven `wget` advisories and their gnutls/idn2/nettle/psl dependants leave with
the package.

| | `8.10.1-debian-12-r0` (baseline) | `8.10.1-debian-13-r0` |
| --- | --- | --- |
| grype, all severities | 282 findings, 24 CRITICAL | **145 findings, 2 CRITICAL** |
| grype, findings with an available fix | 0 | **0** |
| Trivy, CRITICAL+HIGH | 80 findings, 13 CRITICAL | **47 findings, 0 CRITICAL** |
| Trivy, findings with a `FixedVersion` | 0 | **0** |
| CVEs from the scan report still present | **12 of 12** | **0 of 12** |

The two residual grype CRITICALs are `CVE-2026-5450` in `libc6`/`libc-bin`, marked
`wont-fix` by Debian. It is present in the `debian-12` baseline too and is not part of
this scan report.

Functional check: a 6-node cluster from [`docker-compose.yml`](docker-compose.yml)
reached `cluster_state:ok` with 3 masters, 3 replicas and all 16384 slots assigned;
keys written through one node were read back through another via `-c` redirects, and
`info replication` showed the replica online. Killing a master container promoted its
replica and the cluster returned to `cluster_state:ok` in ~3s with every key still
readable and writes accepted afterwards.

### Scanner coverage

Of the 12 CVEs in the scan report:

| Scanner | CVEs in DB | Baseline hits | debian-13 hits |
| --- | --- | --- | --- |
| grype 0.118.0 | 12 | 12 | 0 |
| Trivy 0.74.0 | 4 | 4 | 0 |

grype confirms every CVE in the report individually, so the delta here is a complete
proof rather than a partial one - unlike the `rabbitmq` debian-13 variant, no CVE in
this report has to be verified by package absence alone.

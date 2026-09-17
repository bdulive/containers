# Redis Cluster 8.10.1 on Chainguard Wolfi

Variant of [`../debian-13`](../debian-13) that replaces
`docker.io/bitnami/minideb:trixie` with `cgr.dev/chainguard/wolfi-base`.

Published as `insightfinderinc/bitnami-redis-cluster:8.10.1-wolfi-r1` (multi-arch,
amd64+arm64), index digest
`sha256:1e91ad6a0f61e1c109d0287f9f31538c4b9f516b574efebe3da41e71d69b7d85`.
`-r1` is a rebuild of `-r0` that picks up the patched `zlib` (see below).

## Why this exists

The customer scan that flagged the rabbitmq images flagged the same OS packages here:
`CVE-2026-54369` / `CVE-2026-54370` (acl), `CVE-2026-54371` (attr) and `CVE-2026-85091`
(zlib). The acl/attr findings cannot be cleared on any Debian base — `libacl1` arrives via
`coreutils`, `passwd`, `sed` and `tar`, and trixie is pinned to the unfixed acl 2.3.2 /
attr 2.5.2, marked `no-dsa` with the fix landing in unstable first.

Wolfi packages the **fixed** releases — `libacl1 2.4.0` and `libattr1 2.6.0` — so the three
acl/attr findings are genuinely absent, not waived by a VEX statement.

### Scan comparison (Trivy)

| variant | CRITICAL | HIGH | MEDIUM | LOW | total | of the 4 customer CVEs |
|---|---|---|---|---|---|---|
| `debian-13` r1 (published) | 0 | 42 | 46 | 56 | 145 | all 4 |
| **`wolfi`** | **0** | **0** | **1** | **0** | **1** | only the zlib one |

Identical on `linux/amd64` and `linux/arm64`.

Scanned with Trivy through the exported filesystem (`docker export` + `trivy rootfs`;
Docker 29's OCI layout cannot be read from the daemon directly):

| variant | Trivy total | fixable | of the 4 customer CVEs |
|---|---|---|---|
| `debian-13` r1 (published) | 145 | **0** | all 4 |
| **`wolfi`** | **1** | **1** | only the zlib one |

### CVE-2026-85091 (zlib): patched in `-r1`, still reported by Trivy 0.74

The tables above are `-r0`, which shipped `zlib 1.3.2-r6`. `-r1` ships
**`zlib 1.3.2.1_rc20260601-r0`**, which carries the fix. The evidence, in the order it was
checked on 2026-09-17:

- Chainguard's `zlib.yaml` builds the develop-branch snapshot with
  `0001-gz_write-don-t-keep-a-pointer-into-callers-buffer-on.patch`, authored 2026-09-15 —
  the backport of upstream `madler/zlib` commit `df84af25dc`, "Fix buffer overflow bug in
  non-blocking gzwrite".
- The installed package's apk metadata records build time `1789526845` = 2026-09-16
  02:47 UTC, i.e. **after** that patch.
- Both `packages.wolfi.dev/os/security.json` and `packages.cgr.dev/chainguard/security.json`
  now list `CVE-2026-85091` / `GHSA-g5fp-32jq-cfw2` as fixed in exactly
  `1.3.2.1_rc20260601-r0`. The earlier `1.3.3-r0` identifier was superseded — **do not wait
  for a 1.3.3 package; upstream has no such tag** (newest is `v1.3.2`).
- Docker Scout reads the live feed and reports **0 vulnerabilities** on this image.

**Trivy 0.74 still reports the finding.** Its bundled DB (built 2026-09-16 19:39 UTC, the
newest published as of this rebuild) carries the stale `1.3.3-r0` fixed-version, and
`1.3.2.1_rc20260601-r0` sorts below it, so the row is emitted anyway. This is a scanner-DB
lag, not a package state — it should clear on the next Trivy DB build without any change to
the image. Until then `trivy --ignore-unfixed` is non-empty on this variant and the
divergence is a known, dated one rather than an open finding.

**Do not pin zlib backwards to dodge it.** `1.3.1.2-r3` is still inside the affected range
*and* adds `CVE-2026-27171`.

A scan of this image taken before the move to Trivy-only also surfaced `CVE-2025-49112`
(Low, no fix) against the `redis` binary itself — the same Bitnami component the Debian
variant ships, so it is not introduced by this base.

## Build

No subscription or credentials needed — `cgr.dev/chainguard/wolfi-base` is public.

```console
docker build --platform linux/amd64,linux/arm64 \
  -t bitnami-redis-cluster:8.10.1-wolfi-r1 --load .
```

`TARGETARCH` selects the matching Bitnami component tarballs, each verified against the
per-arch checksum already in `prebuildfs/opt/bitnami/checksums/`.

## How it differs from the minideb variant

- **No perl force-purge.** The debian-13 variant has to `dpkg --purge
  --force-remove-essential` perl as its final build step, with assertions guarding against
  a stale package list. Wolfi installs no perl at all, so the whole hazard disappears — the
  build asserts `! command -v perl` and that is the end of it.
- **wget never enters the runtime image.** The debian-13 variant installs wget to fetch the
  components and then `uninstall_packages` it, to shed its gnutls/idn2/nettle/psl chain.
  Here the download happens in a separate build stage, which expresses the same intent
  without the install-then-remove dance.
- **GNU userland installed deliberately.** busybox applets would cover most calls, but the
  Bitnami script library relies on GNU behaviour in `sed`, `grep` and `awk`. On Wolfi that
  costs nothing in CVE terms, because `coreutils` pulls the *patched* acl/attr.
- **`getent` comes from `posix-libc-utils-bin`** — used by `libnet.sh` and `libos.sh`.
- **prebuildfs helpers live under `usr/bin`, not `usr/sbin`.** Wolfi merges sbin into bin
  (`/usr/sbin` and `/sbin` are symlinks to `usr/bin`), and `COPY` cannot write through a
  symlinked directory. `install_packages` and `uninstall_packages` are rewritten against
  `apk` instead of `apt`, keeping the same contract.
- **uid 1001 is created explicitly.** `wolfi-base` only ships `nonroot` (65532).
- **The build asserts the Redis binaries run**, since the Bitnami component is built against
  debian-12 glibc and this base is glibc 2.44.

## Verification

Built and tested on **both linux/amd64 and linux/arm64**.

A full 6-node cluster was brought up from `docker-compose.yml` on each architecture:

- `Cluster correctly created` — 3 masters, 3 replicas, `[OK] All 16384 slots covered`.
- `cluster_state:ok`, `cluster_slots_ok:16384`, `cluster_size:3`, `cluster_known_nodes:6`.
- Keys written and read back across all three slot ranges through `redis-cli -c`
  (following MOVED redirects).
- **Failover**: killing a master marked it `master,fail`, its replica was promoted, the
  cluster returned to `cluster_state:ok` with all 16384 slots within 5s, and every key
  written before the kill was still readable afterwards.
- `redis-server` reports `v=8.10.1`, `redis-cli 8.10.1`, no perl in the image.
- `-r1` additionally: `zlib 1.3.2.1_rc20260601-r0`, `libacl1 2.4.0-r3` and
  `libattr1 2.6.0-r3` on both arches; the 6-node bring-up, cross-slot key round-trip and
  master-kill failover were all re-run on `-r1` and passed unchanged.
- Per-arch binaries confirmed, not a mislabelled manifest: `redis-server` carries ELF
  `e_machine` 0x3e (x86-64) in the amd64 image and 0xb7 (aarch64) in the arm64 image.

`REDIS_NODES` parsing — which is what broke the earlier busybox/toybox prototype recorded
in the directory `CLAUDE.md` — works correctly here. That rejection was about replacing the
GNU userland with applets; this variant keeps GNU `coreutils`/`sed`/`grep`/`gawk` and gets
the patched acl/attr from the base instead, so it needs **no script-level divergence** and
rebases as cleanly as the Debian variant does.

amd64 was built and exercised under QEMU emulation on an arm64 host. Correctness is
verified; native-amd64 timing and behaviour under load are not.

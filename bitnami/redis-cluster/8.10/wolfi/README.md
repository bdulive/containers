# Redis Cluster 8.10.1 on Chainguard Wolfi

Variant of [`../debian-13`](../debian-13) that replaces
`docker.io/bitnami/minideb:trixie` with `cgr.dev/chainguard/wolfi-base`.

Built as `bitnami-redis-cluster:8.10.1-wolfi-r0`.

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

grype is the primary scanner for this image (see the directory `CLAUDE.md`: its DB carries
advisories Trivy's does not), scanned through the exported filesystem:

| variant | grype total | fixable | of the 4 customer CVEs |
|---|---|---|---|
| `debian-13` r1 (published) | 138 | **0** | all 4 |
| **`wolfi`** | **3** | **2** | only the zlib one |

### The one way this does not yet beat the Debian variant

**`grype --only-fixed` is not empty here**, so the repo's stated pass condition is not met.
Wolfi ships `zlib 1.3.2-r6`, which sits inside CVE-2026-85091's affected range
(1.3.1.2–1.3.2) and has a published fix identifier, `1.3.3-r0`, that has **not yet reached
the apk repo** — the newest available is `1.3.2-r7`. Debian trixie's zlib is upstream 1.3.1,
*below* the affected range, which is why the same advisory reads as unfixable-and-arguably-
inapplicable there but fixable-and-real here.

So the honest trade is: 138 findings with zero fixable, versus 3 findings with two fixable
(the zlib CVE and its GHSA alias). Rebuild once `zlib 1.3.3-r0` lands and this goes to a
clean `--only-fixed`.

**Do not pin zlib backwards to dodge it.** `1.3.1.2-r3` is still inside the affected range
*and* adds `CVE-2026-27171`.

The third grype finding is `CVE-2025-49112` (Low, no fix) matched against the `redis`
binary itself, which is the same Bitnami component the Debian variant ships.

## Build

No subscription or credentials needed — `cgr.dev/chainguard/wolfi-base` is public.

```console
docker build --platform linux/amd64,linux/arm64 \
  -t bitnami-redis-cluster:8.10.1-wolfi-r0 --load .
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
- Per-arch binaries confirmed, not a mislabelled manifest: `redis-server` carries ELF
  `e_machine` 0x3e (x86-64) in the amd64 image and 0xb7 (aarch64) in the arm64 image.

`REDIS_NODES` parsing — which is what broke the earlier busybox/toybox prototype recorded
in the directory `CLAUDE.md` — works correctly here. That rejection was about replacing the
GNU userland with applets; this variant keeps GNU `coreutils`/`sed`/`grep`/`gawk` and gets
the patched acl/attr from the base instead, so it needs **no script-level divergence** and
rebases as cleanly as the Debian variant does.

amd64 was built and exercised under QEMU emulation on an arm64 host. Correctness is
verified; native-amd64 timing and behaviour under load are not.

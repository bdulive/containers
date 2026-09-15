# RabbitMQ 4.3.5 on Chainguard Wolfi

Variant of [`../debian-13`](../debian-13) that replaces
`docker.io/bitnami/minideb:trixie` with `cgr.dev/chainguard/wolfi-base`.

Built as `bitnami-rabbitmq:4.3.5-wolfi-r0`. Not published.

## Why this exists

A customer scan of `4.3.5-debian-13-r0` reported four OS-package findings:
`CVE-2026-54369` / `CVE-2026-54370` (acl), `CVE-2026-54371` (attr) and `CVE-2026-85091`
(zlib). Neither Debian trixie nor Docker Hardened Images can clear the first three — on any
Debian base `libacl1` arrives via `coreutils`, `passwd`, `sed` and `tar`, and trixie is
pinned to the unfixed acl 2.3.2 / attr 2.5.2 (marked `no-dsa`, "fixed first in unstable").
DHI rebuilds those same unfixed sources and waives the findings with an OpenVEX statement
(`not_affected`, justification `vulnerable_code_cannot_be_controlled_by_adversary`) rather
than patching them, so a scanner that does not consume that VEX still reports all three.

Wolfi packages the **fixed** releases — `libacl1 2.4.0` and `libattr1 2.6.0` — so the three
acl/attr findings are genuinely absent, not waived.

It also packages `erlang-27` at exactly **27.3.4.17**, the OTP patch release the minideb
variant compiles from source, so the whole `erlang-builder` stage disappears. The Dockerfile
asserts that version at build time: a silent downgrade would reintroduce fixed OTP
advisories.

### Scan comparison (Trivy)

| variant | CRITICAL | HIGH | MEDIUM | LOW | total | of the 4 customer CVEs |
|---|---|---|---|---|---|---|
| `debian-13` r1 (published) | 0 | 44 | 72 | 72 | 189 | all 4 |
| `dhi.io/debian-base` rebase (tested, not kept) | 0 | 13 | 35 | 34 | 82 | all 4 |
| **`wolfi`** | **0** | **0** | **1** | **0** | **1** | only the zlib one |

Identical on `linux/amd64` and `linux/arm64`. The single remaining finding is
`CVE-2026-85091` on `zlib 1.3.2-r6`. Chainguard's feed already names the fix (`1.3.3-r0`);
it is not yet published to the repo, so it clears itself on a later rebuild.

grype agrees on both architectures but reports the same issue twice - once as
`CVE-2026-85091` and once as `GHSA-g5fp-32jq-cfw2` (same package, same fix version) - and
rates it High where Trivy rates it Medium. One underlying issue, not two.

**Do not pin zlib backwards to dodge it.** `1.3.1.2-r3` is still inside the CVE's affected
range (1.3.1.2–1.3.2) *and* adds `CVE-2026-27171`. Take 1.3.2 and rebuild when 1.3.3 lands.

## Build

No subscription or credentials needed — `cgr.dev/chainguard/wolfi-base` is public.

```console
docker build --platform linux/amd64,linux/arm64 \
  -t bitnami-rabbitmq:4.3.5-wolfi-r0 --load .
```

`TARGETARCH` selects the matching Bitnami component tarball, and each is verified against
the per-arch checksum already in `prebuildfs/opt/bitnami/checksums/`.

## How it differs from the minideb variant

- **No Erlang build stage.** `apk add erlang-27` gives 27.3.4.17 directly. Erlang lands in
  `/usr/lib/erlang` and is symlinked to `/opt/bitnami/erlang` so the Bitnami `PATH`
  convention still works — a symlink rather than a copy, so apk keeps owning the files and
  the SBOM keeps reporting the package.
- **GNU userland installed deliberately.** busybox applets would cover most calls, but the
  Bitnami script library relies on GNU behaviour in `sed`, `grep` and `awk`. On Wolfi that
  costs nothing in CVE terms, because `coreutils` pulls the *patched* acl/attr. Staying on
  bare busybox avoids acl/attr entirely if you ever want the stricter footprint.
- **No perl purge.** The minideb variant has to force-purge perl as its final dpkg
  operation because `locale-gen` needs it. Wolfi ships `glibc-locale-en`, so `en_US.UTF-8`
  works with no perl anywhere in the image.
- **`getent` comes from `posix-libc-utils-bin`** — used by `libnet.sh` and `libos.sh`.
- **prebuildfs helpers live under `usr/bin`, not `usr/sbin`.** Wolfi merges sbin into bin
  (`/usr/sbin` and `/sbin` are symlinks to `usr/bin`), and `COPY` cannot write through a
  symlinked directory. `install_packages` and `uninstall_packages` are rewritten against
  `apk` instead of `apt`, keeping the same contract.
- **uid 1001 is created explicitly.** `wolfi-base` only ships `nonroot` (65532).

Image is 513MB against 708MB for `4.3.5-debian-13-r1`.

## Verification

Built and tested on **both linux/amd64 and linux/arm64**; every check below passed
identically on each.

- Boots through the full Bitnami entrypoint to `Server startup complete; 3 plugins started`
  within 20s, RabbitMQ 4.3.5 on `erts 15.2.7.13` (OTP 27.3.4.17).
- Queue declare, publish and consume round-trip through the management API; the published
  payload comes back intact.
- `rabbitmq-diagnostics check_running` reports "fully booted and running", and
  `check_port_connectivity` connects on 5672, 15672 and 25672.
- Runs as `uid=1001(rabbitmq) gid=0(root)`, `LANG=en_US.UTF-8`.
- `libacl1 2.4.0-r3`, `libattr1 2.6.0-r3`, `erlang-27 27.3.4.17-r0` on both.
- The binaries really are per-arch, not a mislabelled manifest: `beam.smp` carries ELF
  `e_machine` 0x3e (x86-64) in the amd64 image and 0xb7 (aarch64) in the arm64 image.

The prebuilt Bitnami component is the `linux-<arch>-debian-12` build in both cases; it runs
unmodified on Wolfi's glibc 2.44.

amd64 was built and exercised under QEMU emulation on an arm64 host. Native-amd64 timing
and load behaviour are therefore unverified, though correctness is.

# containers

Fork of `bitnami/containers`. Only a handful of images are hand-maintained here; the other
~370 directories under `bitnami/` are upstream-generated and are left alone.

`origin` is this fork, `upstream` is `bitnami/containers`.

## Working rules

**Never commit automatically. The user reviews every change before it is committed.**
Make the edits, report what changed, and stop there — `git commit` happens only when the
user asks for it in that turn. Asking for a commit once does not authorise the next one.

The same applies to anything else that leaves this machine: pushing a branch, pushing an
image to `insightfinderinc`, or publishing in any other form. Build and scan freely; ask
before publishing.

## Directory index

| Path | Role |
| --- | --- |
| `bitnami/rabbitmq/` | Hand-maintained. CVE-remediated variants of 4.3.5. See `bitnami/rabbitmq/CLAUDE.md`. |
| `bitnami/redis-cluster/` | Hand-maintained. CVE-remediated variants of 8.10.1. See `bitnami/redis-cluster/CLAUDE.md`. |
| `bitnami/<everything else>/` | **Upstream-generated. Do not hand-edit.** Overwritten by the next `[bitnami/<name>] Release ...` commit pulled from `upstream`. |
| `README.md`, `CONTRIBUTING.md`, `TESTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md` | Upstream. Leave alone. |

Within a hand-maintained image, each variant is its own directory
(`<version>/<flavour>/`) with its own `Dockerfile`, `README.md`, `prebuildfs/` and
`rootfs/`. The per-image `CLAUDE.md` says which of those are generated and which are ours.

## Adding a new maintained image

Give it its own `bitnami/<name>/CLAUDE.md` covering local file roles, the component set,
image-specific remediation history, and scoped build/test commands. Add a row to the index
above and nothing more — **this file is a table of contents; image-specific detail lives in
the nested file, not here.**

## Base image flavours

Three flavours appear across the maintained images. The choice is a CVE-surface decision,
not a packaging preference:

| flavour dir | base | why |
| --- | --- | --- |
| `debian-12/` | `bitnami/minideb:bookworm` | Upstream-generated. |
| `debian-13/` | `bitnami/minideb:trixie` | Hand-maintained Debian variant. Most remediation lives in the Dockerfile. |
| `wolfi/` | `cgr.dev/chainguard/wolfi-base` | Clears advisories no Debian base can — Wolfi packages fixed releases Debian has only in unstable. |

**The acl/attr advisories (CVE-2026-54369/-54370/-54371) are unfixable on any Debian base.**
`libacl1` arrives via `coreutils`, `passwd`, `sed` and `tar`; trixie is pinned to the
unfixed acl 2.3.2 / attr 2.5.2, marked `no-dsa` with the fix landing in unstable first.
Wolfi packages the fixed acl 2.4.0 / attr 2.6.0, so the `wolfi/` variants clear them
outright. Docker Hardened Images do **not** — evaluated 2026-09-15 and rejected: DHI
rebuilds those same unfixed sources and waives the findings with an OpenVEX
`not_affected` statement, so any scanner that does not consume that VEX still reports all
three. Do not re-propose a DHI rebase.

Wolfi-specific gotchas that apply to every `wolfi/` variant:

- `/usr/sbin` and `/sbin` are symlinks to `usr/bin`, and `COPY` cannot write through a
  symlinked directory. The `prebuildfs` helpers live under `usr/bin/` there, and
  `install_packages`/`uninstall_packages` are rewritten against `apk`.
- Install the **GNU** userland (`coreutils sed grep gawk findutils`) rather than relying on
  busybox applets. The Bitnami script library depends on GNU behaviour, and on Wolfi the
  GNU packages cost nothing in CVE terms because they pull the *patched* acl/attr.
- `getent` comes from `posix-libc-utils-bin`; locales come from `glibc-locale-en`, so no
  perl is installed and no perl purge is needed.
- `wolfi-base` only ships `nonroot` (65532); uid 1001 must be created explicitly.
- Bitnami publishes no Wolfi components. The `linux-<arch>-debian-12` tarballs run
  unmodified on Wolfi's glibc 2.44 — assert this in the build rather than assuming it.

## Scanning

**Use Trivy. Do not use grype** — it is not installed on this machine. Older README
sections still quote grype totals from before that decision; treat those as historical
records, not as instructions, and do not add new ones.

```console
trivy image --scanners vuln <ref>                    # all findings
trivy image --scanners vuln --ignore-unfixed <ref>   # the pass condition: must be empty
```

Docker 29 writes an OCI layout that scanners reject when reading the local daemon image
directly (`archive/tar: invalid tar header`, or `unexpected EOF`). Scan a **pushed registry
reference**, or export the container and scan the directory:

```console
docker create --name probe <image> && docker export probe | tar -x -C fs && docker rm -f probe
trivy rootfs --scanners vuln --ignore-unfixed fs
```

The pass condition is **zero fixable findings, not a zero total.** Residual unfixable
findings are expected and are closed out with a vendor response, not a code change. Read an
advisory's affected range against the **upstream** version, not the Debian one — Debian
marks suites vulnerable conservatively, which will otherwise send you chasing a fix that
does not exist.

Always scan both architectures. Identical totals are expected; a divergence means an
arch-specific package slipped in.

## Build and publish

Maintained images are published to `insightfinderinc/bitnami-<name>:<version>-<flavour>-r<n>`.

```console
docker build --platform linux/amd64,linux/arm64 -t <ref> --push .
```

On Apple Silicon, build `linux/arm64` natively while iterating; emulated `linux/amd64` is
cheap for prebuilt-component images. Verify the manifest really carries both platforms and
that the binaries differ per arch (ELF `e_machine` 0x3e for x86-64, 0xb7 for aarch64) —
a manifest list alone does not prove it.

Functionally smoke-test before publishing; a clean scan is not evidence the image works.
Each image's `CLAUDE.md` defines what its real smoke test is (for redis-cluster it is the
6-node cluster, not a single container).

## Upstream sync

When pulling upstream releases, the generated flavour directories move and the
hand-maintained ones do not. Keep remediation in the **Dockerfile**: `prebuildfs/` and
`rootfs/` should stay byte-identical to the generated variant so
`diff -rq <gen-flavour> <maintained-flavour>` reports only `Dockerfile`,
`docker-compose.yml` and `README.md`. Script-level divergence buys nothing for the CVE
result and costs a rebase conflict every release.

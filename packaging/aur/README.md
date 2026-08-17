# AUR packaging

`PKGBUILD` + `hypranticheat-dkms.install` here are a working copy kept in
this repo for review/CI purposes; the actual AUR package is maintained in
its own separate git repo (`ssh://aur@aur.archlinux.org/hypranticheat.git`),
which AUR requires — pushing to *this* repo does not publish anything to
AUR. See `RELEASING.md` at the repo root for the update procedure.

## Split package

- **`hypranticheat`** — the userspace daemon/CLI (`anticheat`), docs, and
  the `/var/lib/anticheat/baselines` state directory.
- **`hypranticheat-dkms`** — the kernel module source, registered with
  DKMS. `hypranticheat-dkms.install` mirrors `scripts/dkms-install.sh`'s
  DKMS-add + Secure-Boot-MOK-signing setup as pacman `post_install`/
  `post_upgrade`/`pre_remove` hooks, so `pacman -S`/`-U`/`-R` drive the
  same sequence that script does manually.

Split so either half can be reinstalled or rebuilt independently — the
normal reason kernel-module AUR packages are structured this way.

## `source=` references a release tarball that doesn't exist yet

`PKGBUILD`'s `source=` points at the GitHub release archive for
`v${pkgver}` — an immutable tag-pinned tarball, not a mutable VCS ref, so
`sha256sums` is a real, checkable checksum rather than the `SKIP` a
`git+#tag=` source would force. This only resolves once that version is
actually tagged (see `RELEASING.md`); `sha256sums` is a placeholder until
then. To test mechanically before a real tag exists: build a local
tarball with the same layout GitHub's archive produces —

```sh
git archive --format=tar --prefix=hypranticheat-<pkgver>/ HEAD \
    | gzip > hypranticheat-<pkgver>.tar.gz
```

— point `source=` at it with a `file://` URL, run `updpkgsums` (computes
a real checksum against the local file, same as it will against the real
release tarball), build, and revert both `source=`/`sha256sums` before
committing — do not commit anything pointing anywhere other than the
real upstream release tarball.

## Verified locally

Built and packaged successfully with `makepkg` on Arch Linux (both split
packages, including a full run through the `git archive`-based local
tarball test above — confirmed the extraction directory name matches a
real GitHub archive's layout, and that `updpkgsums` computes a genuine
checksum rather than a no-op). `namcap`-clean except expected/benign
warnings: an intentionally-empty state directory, the private (`0700`)
MOK key directory correctly flagged as non-world-readable/executable,
and two informational/false-positive notes about the `-dkms` package
having no ELF files and namcap not detecting `dkms`'s use from a shell
script. `hypranticheat-dkms.install` is `shellcheck -s bash`-clean (no
shebang is correct/required — pacman sources `.install` files as
functions, it doesn't execute them). Not yet verified: an actual
`pacman -U` install/upgrade/remove cycle (would mutate the testing
machine's real DKMS registry and `/etc/dkms/framework.conf.d/`, so this
needs a disposable VM/container, not the machine this was authored on).

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

## `source=` references a tag that doesn't exist yet

`PKGBUILD`'s `source=` points at `#tag=v${pkgver}`, i.e. a real upstream
git tag — this only resolves once that version is actually tagged (see
`RELEASING.md`). Until then, this can't be built as committed; to test
mechanically before a real tag exists, point `source=` at a local
checkout instead (e.g. `git+file:///path/to/hypranticheat#branch=master`),
build, and revert before committing — do not commit a modified `source=`
pointing anywhere other than the real upstream tag.

## Verified locally

Built and packaged successfully with `makepkg` on Arch Linux (both split
packages), `namcap`-clean (the three remaining warnings — an
intentionally-empty state directory, and two informational/false-positive
notes about the `-dkms` package having no ELF files and namcap not
detecting `dkms`'s use from a shell script — are expected, not bugs), and
`hypranticheat-dkms.install` is `shellcheck`-clean. Not yet verified: an
actual `pacman -U` install/upgrade/remove cycle (would mutate the testing
machine's real DKMS registry and `/etc/dkms/framework.conf.d/`, so this
needs a disposable VM/container, not the machine this was authored on).

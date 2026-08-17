# Releasing

## Versioning

One version number, tracked in two places that must move together:

- `dkms.conf`'s `PACKAGE_VERSION` — this is not cosmetic. It's the literal
  path component DKMS uses for the staged source
  (`/usr/src/anticheat-$PACKAGE_VERSION`) and the built module
  (`/var/lib/dkms/anticheat/$PACKAGE_VERSION/...`); `scripts/dkms-install.sh`
  already reads it dynamically rather than hardcoding it, so that script
  itself needs no edit on a bump.
- `MODULE_VERSION("...")` at the bottom of `src/anticheat_module.c` —
  shows up in `modinfo anticheat.ko`.

Both should always read the same value. Use plain `MAJOR.MINOR.PATCH`,
bumped by judgment rather than a mechanical rule, since this project is a
kernel module + userspace CLI pair, not a library with a formal public
API:

- **MAJOR** — an incompatible change to the ioctl wire protocol between
  the daemon and the module (see next paragraph), or a change that
  removes/renames a CLI subcommand or its documented behavior.
- **MINOR** — a new detection feature, CLI subcommand, or flag, backward
  compatible with existing usage.
- **PATCH** — bug fixes, hardening, doc/CI changes with no new user-facing
  surface.

**`AC_IOCTL_VERSION` (`src/anticheat.h`) is a different number and moves
on a different, much rarer trigger.** It's the actual wire-protocol
version for the `/dev/anticheat` ioctl ABI (reported by `anticheat
status`), not the package version — bump it only when the ioctl struct
layout itself changes in an incompatible way (a daemon and module built
at different `AC_IOCTL_VERSION`s are the actual "these two don't speak
the same protocol" case this guards against), independent of whatever
`PACKAGE_VERSION`/`MODULE_VERSION` bump is happening in the same release.

## Release checklist

1. Confirm `master` is green (`.github/workflows/ci.yml` passing) and
   skim `git log v<LAST>..HEAD` for anything that changes the version
   bump above (does anything touch the ioctl ABI? a new subcommand? just
   fixes?).
2. Bump `dkms.conf`'s `PACKAGE_VERSION` and `MODULE_VERSION(...)` in
   `src/anticheat_module.c` to the new version, together, in one commit.
   Bump `AC_IOCTL_VERSION` in `src/anticheat.h` too, but only if this
   release actually changes the ioctl struct layout.
3. Open that as a normal PR (same flow as every other change in this
   repo — see recent merged PRs), get it through CI, merge it.
4. Tag the merged commit and push the tag:

   ```sh
   git checkout master && git pull --ff-only
   git tag -a v<VERSION> -m "v<VERSION>"
   git push origin v<VERSION>
   ```

5. The tag push triggers `.github/workflows/release.yml`, which builds
   the userspace daemon (packaged as a permission-preserving
   `anticheat-<tag>-x86_64.tar.gz` — a bare binary asset doesn't reliably
   keep its executable bit through a GitHub Release download) and
   creates a Release at that tag with it attached — this is the actual
   point of tagging a version: CI-built artifacts from a plain push are
   ephemeral (expire, aren't a stable download link); a Release's
   attached assets are permanent.

   **The kernel module is deliberately not published as a raw `.ko`
   asset.** The workflow still builds it (same `linux-6.12`-headers
   compile-smoke-test build `ci.yml` does on every push, gating the
   Release on it actually compiling) but doesn't attach it — a `.ko`
   linked against a synthesized `Module.symvers` to satisfy modpost is
   not the same thing as a module verified to load on any real running
   kernel (vermagic and, on a target with `CONFIG_MODVERSIONS`, symbol
   CRC checks would plausibly reject it against a real distro kernel).
   Publishing it as a generic downloadable "linux 6.12 module" would
   overstate what was actually verified. `make module`,
   `scripts/dkms-install.sh`, or the AUR package build a real one
   against the installing machine's own kernel instead.
6. Sanity-check the published Release before announcing anything:
   download the daemon archive, `tar -xzf` it, confirm the extracted
   binary is executable without a manual `chmod`, and run its `--help`/
   `status` against the userspace mock (`make test-mock`-style, doesn't
   need root). This is **not** a substitute for real load-time testing of
   the kernel module on a live kernel — see point 5 above — just a check
   that the one asset actually shipped isn't obviously broken.
7. Update the AUR package (`PKGBUILD`) to match:

   ```sh
   # in the AUR package's own git checkout, not this repo:
   sed -i "s/^pkgver=.*/pkgver=<VERSION>/; s/^pkgrel=.*/pkgrel=1/" PKGBUILD
   updpkgsums
   makepkg --printsrcinfo > .SRCINFO
   git commit -am "Update to v<VERSION>" && git push
   ```

   (`pkgrel` only bumps on its own, without a `pkgver` change, if the
   *packaging* changes but upstream didn't — e.g. a PKGBUILD fix.)

There is no separate "-dev"/pre-release version between releases — the
next bump happens at step 2 of the *next* release, not right after this
one ships.

#!/usr/bin/env bash
# dkms-install.sh — stage this checkout into /usr/src and run the DKMS
# add/build/install sequence. Run once per machine; DKMS itself takes care
# of every subsequent kernel upgrade automatically.
#
# Usage: sudo ./scripts/dkms-install.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi

command -v dkms >/dev/null 2>&1 || {
    echo "dkms not found — install it first (e.g. apt install dkms," >&2
    echo "dnf install dkms, or pacman -S dkms)" >&2
    exit 1
}

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="anticheat"
VERSION="$(awk -F'"' '/^PACKAGE_VERSION=/{print $2}' "${SRC_DIR}/dkms.conf")"
DEST="/usr/src/${NAME}-${VERSION}"

if [[ -e "$DEST" && "$(readlink -f "$DEST")" != "$(readlink -f "$SRC_DIR")" ]]; then
    echo "removing previous DKMS source tree at ${DEST}"
    dkms remove -m "$NAME" -v "$VERSION" --all 2>/dev/null || true
    rm -rf "$DEST"
fi

if [[ ! -e "$DEST" ]]; then
    echo "staging source into ${DEST}"
    mkdir -p "$DEST"
    # Only what the kernel build + sign helper need — not the daemon, tests,
    # or CI files, so kernel updates don't get charged for copying the
    # whole repo every time.
    cp -a "${SRC_DIR}/Makefile" "${SRC_DIR}/dkms.conf" "$DEST/"
    cp -a "${SRC_DIR}/src" "$DEST/"
    cp -a "${SRC_DIR}/scripts" "$DEST/"
fi

dkms add    -m "$NAME" -v "$VERSION"
dkms build  -m "$NAME" -v "$VERSION"
dkms install -m "$NAME" -v "$VERSION"

echo
echo "done. load it with: sudo modprobe anticheat"
echo "if this was the first install and Secure Boot is on, reboot now and"
echo "approve the key enrollment in the blue MOK Management screen."

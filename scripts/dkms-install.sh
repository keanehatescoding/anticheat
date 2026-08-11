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
MOK_DIR="/var/lib/anticheat/mok"
MOK_CERT="${MOK_DIR}/mok.der"

# DKMS's built-in Secure Boot signing needs to be told where to keep a
# persistent key (see the note in dkms.conf for why this can't just be a
# variable in this package's own dkms.conf). This fragment applies to every
# DKMS package on the machine, matching DKMS's normal one-key-for-everything
# model, so it's safe even if other DKMS modules are already installed.
install -d -m 0700 "$MOK_DIR"
install -D -m 0644 /dev/stdin /etc/dkms/framework.conf.d/anticheat.conf <<EOF
mok_signing_key="${MOK_DIR}/mok.priv"
mok_certificate="${MOK_CERT}"
EOF

if [[ -e "$DEST" && "$(readlink -f "$DEST")" != "$(readlink -f "$SRC_DIR")" ]]; then
    echo "removing previous DKMS source tree at ${DEST}"
    dkms remove -m "$NAME" -v "$VERSION" --all 2>/dev/null || true
    rm -rf "$DEST"
fi

if [[ ! -e "$DEST" ]]; then
    echo "staging source into ${DEST}"
    mkdir -p "$DEST"
    # Only what the kernel build needs — not the daemon, tests, or CI
    # files, so kernel updates don't get charged for copying the whole
    # repo every time.
    cp -a "${SRC_DIR}/Makefile" "${SRC_DIR}/dkms.conf" "$DEST/"
    cp -a "${SRC_DIR}/src" "$DEST/"
fi

dkms add    -m "$NAME" -v "$VERSION"
dkms build  -m "$NAME" -v "$VERSION"
dkms install -m "$NAME" -v "$VERSION"

echo
echo "done. load it with: sudo modprobe anticheat"

# The build above generates and uses the MOK; it does not enroll it. UEFI
# has no supported way to trust a new key without a physical/console
# confirmation (otherwise malware could self-enroll one too), so this part
# can't be automated past this point.
if ! command -v mokutil >/dev/null 2>&1; then
    echo "mokutil not found — if Secure Boot is on, install it and run:"
    echo "  sudo mokutil --import ${MOK_CERT}"
elif ! mokutil --sb-state 2>/dev/null | grep -qi enabled; then
    : # Secure Boot off (or no UEFI at all) — nothing further needed.
elif mokutil --test-key "$MOK_CERT" 2>/dev/null | grep -qi "already enrolled"; then
    echo "signing key already trusted — module should load as-is."
else
    echo "Secure Boot is ON and this signing key is not yet trusted."
    echo "Enrolling it now — you will be prompted to set a one-time password."
    echo "REBOOT after this and approve the request in the blue 'MOK Management'"
    echo "screen (Enroll MOK -> Continue -> enter the password -> Reboot)."
    echo "Until you do this, the signed module will still fail to load."
    mokutil --import "$MOK_CERT" || \
        echo "mokutil --import failed; enroll manually: sudo mokutil --import ${MOK_CERT}"
fi

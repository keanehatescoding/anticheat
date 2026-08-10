#!/usr/bin/env bash
# dkms-sign-helper.sh — sign the built anticheat.ko with a self-managed MOK
# (Machine Owner Key) so it loads under Secure Boot.
#
# Invoked by DKMS as: dkms-sign-helper.sh <path-to-module.ko>
# (DKMS calls this automatically after every build when dkms.conf sets
# sign_tool= to this script; see dkms.conf.)
#
# What this does NOT do: enroll the key into firmware for you. UEFI has no
# supported way to accept a new trusted key without a physical/console
# confirmation, by design (otherwise malware could self-enroll a key too).
# The first time this runs on a machine it stages the enrollment request
# and prints instructions; the player must reboot once and approve it in
# the blue MokManager screen. After that one-time step, every future
# rebuild (kernel upgrades, DKMS reinstalls) is fully automatic.
set -euo pipefail

MODULE="${1:?usage: $0 <module.ko>}"
KEY_DIR="/var/lib/anticheat/mok"
PRIV_KEY="${KEY_DIR}/MOK.priv"
PUB_CERT="${KEY_DIR}/MOK.der"
HASH_ALGO="sha256"

log() { printf '[anticheat-sign] %s\n' "$*" >&2; }

if [[ $EUID -ne 0 ]]; then
    log "must run as root (DKMS normally invokes this via sudo dkms build/install)"
    exit 1
fi

# ---------------------------------------------------------------------
# 1. Generate a signing key on first use. Reused for every future build,
#    so the player only ever has to enroll one key, ever.
# ---------------------------------------------------------------------
if [[ ! -f "$PRIV_KEY" || ! -f "$PUB_CERT" ]]; then
    log "no MOK found at ${KEY_DIR}, generating one (one-time)"
    install -d -m 0700 "$KEY_DIR"
    openssl req -new -x509 -newkey rsa:2048 \
        -keyout "$PRIV_KEY" -outform PEM \
        -out "$PUB_CERT" -outform DER \
        -nodes -days 36500 \
        -subj "/CN=anticheat module signing key/" \
        2>/dev/null
    chmod 0600 "$PRIV_KEY"
    chmod 0644 "$PUB_CERT"
fi

# ---------------------------------------------------------------------
# 2. Sign the module in place. sign-file ships with the kernel headers
#    used for this build, so it always matches the running kernel's
#    expected signature format.
# ---------------------------------------------------------------------
SIGN_FILE=""
for candidate in \
    "/lib/modules/$(uname -r)/build/scripts/sign-file" \
    "/usr/src/linux-headers-$(uname -r)/scripts/sign-file"
do
    if [[ -x "$candidate" ]]; then
        SIGN_FILE="$candidate"
        break
    fi
done
if [[ -z "$SIGN_FILE" ]]; then
    log "scripts/sign-file not found under kernel headers for $(uname -r); cannot sign"
    log "module will be installed UNSIGNED — Secure Boot will refuse to load it"
    exit 0   # don't fail the DKMS build over this; just ship unsigned
fi

"$SIGN_FILE" "$HASH_ALGO" "$PRIV_KEY" "$PUB_CERT" "$MODULE"
log "signed $(basename "$MODULE") with ${PUB_CERT}"

# ---------------------------------------------------------------------
# 3. One-time enrollment check. If Secure Boot is on and this key isn't
#    trusted yet, stage the MOK import and tell the player what to do.
#    Safe to run every build: mokutil is idempotent about already-enrolled
#    or already-pending keys.
# ---------------------------------------------------------------------
if command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>/dev/null | grep -qi "enabled"; then
    if mokutil --test-key "$PUB_CERT" 2>/dev/null | grep -qi "already enrolled"; then
        : # nothing to do
    else
        log "Secure Boot is ON and this signing key is not yet trusted."
        log "Enrolling it now — you will be prompted to set a one-time password."
        log "REBOOT after this and approve the request in the blue 'MOK Management'"
        log "screen (Enroll MOK -> Continue -> enter the password -> Reboot)."
        log "Until you do this, the signed module will still fail to load."
        mokutil --import "$PUB_CERT" || \
            log "mokutil --import failed; enroll manually: sudo mokutil --import ${PUB_CERT}"
    fi
fi

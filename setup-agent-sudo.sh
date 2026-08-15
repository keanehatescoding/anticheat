#!/bin/bash
# One-time setup: grants passwordless sudo for exactly the commands this
# dev workflow needs -- insmod/rmmod (to load/unload the kernel module
# under test) and this repo's test.sh (which itself runs as a normal user
# and only needs root for the insmod/rmmod/module-status parts). Nothing
# else is elevated; no other command, no shell, no wildcard.
#
# Run this yourself, once, with sudo -- it has to be, since installing a
# sudoers rule requires root and that's the entire point of the script:
#
#   sudo ./setup-agent-sudo.sh
#
# To undo: sudo rm /etc/sudoers.d/hypranticheat-dev
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo: sudo $0" >&2
    exit 1
fi

TARGET_USER="${SUDO_USER:-}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
    echo "Could not determine the non-root user to grant this to." >&2
    echo "Run it as: sudo ./setup-agent-sudo.sh  (not as a root shell)" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_SH="$REPO_DIR/test.sh"
INSMOD="$(command -v insmod || true)"
RMMOD="$(command -v rmmod || true)"

if [ ! -x "$TEST_SH" ]; then
    echo "Expected $TEST_SH to exist and be executable." >&2
    exit 1
fi
if [ -z "$INSMOD" ] || [ -z "$RMMOD" ]; then
    echo "Could not locate insmod/rmmod on PATH." >&2
    exit 1
fi

SUDOERS_FILE="/etc/sudoers.d/hypranticheat-dev"
RULE="$TARGET_USER ALL=(root) NOPASSWD: $INSMOD, $RMMOD, $TEST_SH"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
printf '%s\n' "$RULE" > "$TMP"
chmod 440 "$TMP"

if ! visudo -c -f "$TMP"; then
    echo "Generated sudoers rule failed validation -- not installing:" >&2
    cat "$TMP" >&2
    exit 1
fi

install -o root -g root -m 440 "$TMP" "$SUDOERS_FILE"

echo "Installed $SUDOERS_FILE:"
cat "$SUDOERS_FILE"
echo
echo "Verify: sudo -n $TEST_SH   (should not prompt for a password)"
echo "Remove: sudo rm $SUDOERS_FILE"

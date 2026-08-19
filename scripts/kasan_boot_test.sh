#!/bin/bash
# kasan_boot_test.sh -- boots a KASAN + lockdep instrumented linux-6.12
# kernel in a VM (via virtme-ng), loads the real anticheat.ko into it,
# exercises the daemon CLI plus the real (non-safe-mode) ioctl fuzz
# harness against the real /dev/anticheat, and fails if the console/
# dmesg output shows a KASAN report, a lockdep splat, or any oops/
# warning/general-protection-fault during the run.
#
# This is the "real" run test/ioctl_fuzz.c's own header comment and
# README's "ioctl fuzzing" section describe as the one that actually
# closes the kernel-assurance gap: CI's per-push dry run only proves the
# harness itself is correct against the mock, which has none of a real
# kernel's copy_from_user()/access_ok() to stress.
#
# Needs: a Linux host, ideally with KVM available (falls back to much
# slower QEMU/TCG software emulation if not -- see
# .github/workflows/kasan-boot.yml, which runs this nightly rather than
# per-push for exactly that reason: GitHub-hosted runners don't reliably
# offer /dev/kvm), virtme-ng ("pipx install virtme-ng" -- recent distros
# mark the system Python as externally-managed, so plain `pip install`
# outside a venv typically fails), qemu-system-x86, and the usual kernel
# build deps (bc flex bison libelf-dev libssl-dev dwarves).
#
# Run locally: ./scripts/kasan_boot_test.sh
# Override the fuzz run via environment: IOCTL_FUZZ_ITERATIONS=2000
# IOCTL_FUZZ_SEED=$(date +%s) ./scripts/kasan_boot_test.sh -- the fixed
# defaults below keep a bare local invocation reproducible; the nightly
# workflow passes a fresh seed each run instead, so repeated nightly
# runs accumulate coverage rather than re-fuzzing the identical sequence
# forever.
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1
REPO_ROOT="$PWD"

IOCTL_FUZZ_ITERATIONS="${IOCTL_FUZZ_ITERATIONS:-300}"
IOCTL_FUZZ_SEED="${IOCTL_FUZZ_SEED:-20260819}"
if ! [[ "$IOCTL_FUZZ_ITERATIONS" =~ ^[1-9][0-9]*$ && "$IOCTL_FUZZ_SEED" =~ ^[0-9]+$ ]]; then
    echo "IOCTL_FUZZ_ITERATIONS must be a positive integer and IOCTL_FUZZ_SEED a non-negative integer (got ITERATIONS=$IOCTL_FUZZ_ITERATIONS SEED=$IOCTL_FUZZ_SEED)" >&2
    exit 2
fi

KVER=6.12
WORKDIR="$(mktemp -d /tmp/ac_kasan_boot.XXXXXXXX)"
KDIR="$WORKDIR/linux-$KVER"
CONSOLE_LOG="$WORKDIR/console.log"

cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "== fetching linux-$KVER =="
curl -fsSL "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KVER.tar.xz" | tar -xJ -C "$WORKDIR"

echo "== configuring: defconfig + KASAN/lockdep debug fragment =="
make -C "$KDIR" ARCH=x86_64 defconfig

# Generic KASAN (not SW/HW tags -- this targets a plain x86_64 QEMU
# guest, no MTE/tag-capable hardware involved) + full lockdep validation.
# CONFIG_FRAME_WARN=0 because KASAN's redzones legitimately inflate stack
# frame sizes past the default warning threshold; that's expected
# instrumentation overhead, not a bug in this module's own code.
cat > "$WORKDIR/kasan-lockdep.config" <<'EOF'
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_INLINE=y
CONFIG_LOCKDEP=y
CONFIG_PROVE_LOCKING=y
CONFIG_DEBUG_ATOMIC_SLEEP=y
CONFIG_FRAME_WARN=0
EOF

"$KDIR/scripts/kconfig/merge_config.sh" -O "$KDIR" "$KDIR/.config" "$WORKDIR/kasan-lockdep.config"
make -C "$KDIR" ARCH=x86_64 olddefconfig

# merge_config.sh doesn't fail the build if a requested symbol silently
# didn't stick (e.g. a missing dependency) -- verify explicitly rather
# than discovering a plain, uninstrumented boot later via absence of any
# KASAN output at all.
for sym in CONFIG_KASAN CONFIG_KASAN_GENERIC CONFIG_LOCKDEP CONFIG_PROVE_LOCKING; do
    grep -qx "${sym}=y" "$KDIR/.config" || {
        echo "FATAL: $sym did not stick after olddefconfig -- see $KDIR/.config" >&2
        exit 1
    }
done

echo "== building the kernel (full build, not modules_prepare -- this is slow) =="
make -C "$KDIR" ARCH=x86_64 -j"$(nproc)" all

echo "== building anticheat.ko against this tree =="
make -C "$REPO_ROOT" KDIR="$KDIR" module
test -s "$REPO_ROOT/anticheat.ko"

echo "== building userspace (daemon + ioctl_fuzz) =="
make -C "$REPO_ROOT" CFLAGS="-O2 -Wall -Wextra -Werror" daemon ioctl-fuzz

echo "== writing in-VM payload =="
PAYLOAD="$WORKDIR/in_vm_payload.sh"
cat > "$PAYLOAD" <<PAYLOAD_EOF
#!/bin/bash
# Runs as root inside the guest, against the host filesystem virtme-ng
# shares in -- \$REPO_ROOT below is the real repo path, not a copy.
set -x
cd "$REPO_ROOT" || exit 1

insmod ./anticheat.ko ac_verbose=1 || { echo "AC_KASAN_BOOT: insmod failed"; exit 1; }
sleep 0.3

./anticheat status

# Same smoke sequence diag.sh already uses interactively: protect a
# throwaway child, exercise the read paths, unprotect, before moving on
# to the actual fuzz stress below.
sleep 300 &
V=\$!
./anticheat protect --pid "\$V"
sleep 0.3
./anticheat list
./anticheat events
./anticheat syscalls
./anticheat scan --pid \$\$
./anticheat modules
./anticheat vmcheck
./anticheat unprotect --pid "\$V"
kill "\$V" 2>/dev/null

echo "AC_KASAN_BOOT: running the real ioctl fuzz harness (full pointer-corruption fuzzing, no safe-pointers-only)"
./test/ioctl_fuzz $IOCTL_FUZZ_ITERATIONS $IOCTL_FUZZ_SEED

rmmod anticheat
echo "AC_KASAN_BOOT: payload complete"
PAYLOAD_EOF
chmod +x "$PAYLOAD"

echo "== booting via virtme-ng =="
# --memory bumped from vng's own default: KASAN's shadow memory roughly
# doubles effective memory pressure, and a too-small guest failing to
# boot at all would otherwise look identical to a genuine hang.
#
# `|| true`: vng's own exit code isn't the pass/fail signal here (same
# reasoning as the ioctl_fuzz harness's own exit code below) -- under
# `set -e`/pipefail a nonzero here would abort the script immediately,
# before the console log is copied out of $WORKDIR and before the real
# grep-based checks below ever run.
vng --run "$KDIR" --memory 3072M --exec "$PAYLOAD" 2>&1 | tee "$CONSOLE_LOG" || true

# Copy out of $WORKDIR now, unconditionally -- the EXIT trap deletes
# $WORKDIR on every exit path including failure, and CI needs this file
# to still exist afterward to upload it as an artifact.
cp "$CONSOLE_LOG" "$REPO_ROOT/kasan-console.log"

if ! grep -q "AC_KASAN_BOOT: payload complete" "$CONSOLE_LOG"; then
    echo "FAIL: payload never reported completion -- boot, insmod, or the in-VM script likely crashed/hung before finishing. See $REPO_ROOT/kasan-console.log." >&2
    exit 1
fi

echo "== checking captured console output for KASAN/lockdep/oops findings =="
# Pass/fail is this grep, not the ioctl_fuzz harness's own exit code --
# consistent with that harness's own header comment: its exit code only
# reflects whether *userspace* survived, not the kernel.
if grep -qE 'BUG:|KASAN:|WARNING:|Call Trace:|INFO: possible circular locking dependency|INFO: suspicious RCU usage|general protection fault|Oops:' "$CONSOLE_LOG"; then
    echo "FAIL: kernel-side finding detected in the console log above." >&2
    exit 1
fi

echo "PASS: kernel survived the real ioctl fuzz harness + CLI exercise under KASAN+lockdep with no findings"

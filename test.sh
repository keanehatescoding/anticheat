#!/bin/bash
# test.sh — end-to-end live test for the kernel anticheat.
# Requires root (loads a kernel module). Run:  sudo ./test.sh
set -u

cd "$(dirname "$0")" || exit 1
VICTIM_PID=""
DAEMON_PID=""
FAILED=0

say()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  PASS\033[0m  %s\n' "$*"; }
bad()  { printf '\033[1;31m  FAIL\033[0m  %s\n' "$*"; FAILED=1; }

# cleanup is invoked via trap below; shellcheck cannot always see that
# shellcheck disable=SC2317,SC2329
cleanup() {
    [ -n "$VICTIM_PID" ] && kill "$VICTIM_PID" 2>/dev/null
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
    sleep 0.2
    rmmod anticheat 2>/dev/null
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

say "building"
make >/dev/null 2>&1 || { echo "build failed"; exit 1; }

say "loading anticheat.ko"
rmmod anticheat 2>/dev/null
insmod ./anticheat.ko || { echo "insmod failed — check dmesg"; exit 1; }
sleep 0.3

say "status"
./anticheat status || bad "status"

say "syscall table integrity"
if ./anticheat syscalls; then ok "syscall table clean"; else bad "syscall check"; fi

say "module enumeration"
if ./anticheat modules >/dev/null; then ok "modules listed"; else bad "modules"; fi

say "protecting a victim process (a bash that will fork a child)"
bash -c 'sleep 300 & echo $! > /tmp/ac_child.pid; wait' &
VICTIM_PID=$!
if ./anticheat protect --pid "$VICTIM_PID" >/dev/null; then
    ok "protected pid $VICTIM_PID"
else
    bad "protect"
fi

say "fork inheritance: child of protected process should inherit"
sleep 0.5
CHILD_PID=$(cat /tmp/ac_child.pid 2>/dev/null)
rm -f /tmp/ac_child.pid
if [ -n "$CHILD_PID" ] && ./anticheat list | grep -q "$CHILD_PID"; then
    ok "child pid $CHILD_PID inherited protection"
else
    bad "fork inheritance (child pid was '$CHILD_PID')"
fi

say "ptrace denial: attempting to attach to the protected process"
# rc=124 means strace stayed attached until the timeout (denial FAILED).
# A clean denial exits immediately with a non-zero, non-124 status.
timeout 3 strace -p "$VICTIM_PID" -e trace=none >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
    ok "ptrace attach to protected process failed (rc=$rc)"
else
    bad "ptrace attach not denied (rc=$rc; 124 = hung attached)"
fi

sleep 0.5
# events are drained on read, so capture once and grep for both kinds
EVENTS=$(./anticheat events)
if printf '%s' "$EVENTS" | grep -q "PTRACE-DENIED"; then ok "PTRACE-DENIED event logged"; else bad "no ptrace event"; fi
if printf '%s' "$EVENTS" | grep -q "FORK"; then ok "FORK event logged"; else bad "no fork event"; fi

say "memory scan (RWX + anon-exec detection)"
SCAN_OUT=$(./anticheat scan --pid "$VICTIM_PID")
if [ -n "$SCAN_OUT" ]; then ok "scan ok"; else bad "scan"; fi
# vdso is present in every process's address space and has no backing
# file, so a correct scan must find at least one anon-exec mapping here —
# this is what makes AC_EV_ANON_EXEC's baseline-delta design testable
# without actually injecting shellcode into the victim.
if printf '%s' "$SCAN_OUT" | grep -qE 'anon-exec'; then
    ok "anon-exec detection found at least one mapping (expect vdso)"
else
    bad "anon-exec detection found nothing (expected vdso at minimum)"
fi

say "memory integrity baseline"
if ./anticheat scan --pid "$VICTIM_PID" --hash --save >/dev/null 2>&1; then
    ok "baseline saved"
else
    bad "baseline save"
fi
if ./anticheat scan --pid "$VICTIM_PID" --hash --check >/dev/null 2>&1; then
    ok "baseline verified"
else
    bad "baseline check"
fi

say "automatic baseline re-check (daemon should detect tampering)"
BLDIR="/var/lib/anticheat/baselines"
if [ -d "$BLDIR" ]; then
    for f in "$BLDIR"/*.txt; do
        [ -f "$f" ] || continue
        sed -i 's/[0-9a-f]\{64\}$/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef/' "$f"
    done
fi
AC_BASELINE_CHECK_INTERVAL=2 ./anticheat start --foreground >/tmp/ac_baseline_test.log 2>&1 &
DAEMON_PID=$!
sleep 4
if grep -q "differs from saved baseline" /tmp/ac_baseline_test.log; then
    ok "periodic baseline check detected tampering"
else
    bad "periodic baseline check did not detect tampering"
fi
kill "$DAEMON_PID" 2>/dev/null
wait "$DAEMON_PID" 2>/dev/null
DAEMON_PID=""
rm -f /tmp/ac_baseline_test.log

say "unprotect + cleanup"
if ./anticheat unprotect --pid "$VICTIM_PID" >/dev/null; then ok "unprotected"; else bad "unprotect"; fi
[ -n "$CHILD_PID" ] && kill "$CHILD_PID" 2>/dev/null

say "locking the module (rmmod must fail while locked)"
if ./anticheat lock >/dev/null; then ok "locked"; else bad "lock"; fi
if rmmod anticheat 2>/dev/null; then bad "rmmod succeeded while locked"; else ok "rmmod correctly refused"; fi
if ./anticheat unlock >/dev/null; then ok "unlocked"; else bad "unlock"; fi

say "self-protection: daemon should register its own pid"
./anticheat start --foreground >/tmp/ac_daemon.log 2>&1 &
DAEMON_PID=$!
sleep 1
if ./anticheat list | grep -q "$DAEMON_PID"; then
    ok "daemon self-protected (pid $DAEMON_PID)"
else
    bad "daemon did not appear in protected list"
fi
timeout 3 strace -p "$DAEMON_PID" -e trace=none >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
    ok "ptrace attach to daemon itself denied (rc=$rc)"
else
    bad "ptrace attach to daemon not denied (rc=$rc; 124 = hung attached)"
fi
kill "$DAEMON_PID" 2>/dev/null
wait "$DAEMON_PID" 2>/dev/null
DAEMON_PID=""

say "unloading"
if rmmod anticheat; then ok "module unloaded"; else bad "rmmod"; fi

echo
if [ "$FAILED" -eq 0 ]; then
    printf '\033[1;32mALL TESTS PASSED\033[0m\n'
else
    printf '\033[1;31mSOME TESTS FAILED\033[0m\n'
fi
exit "$FAILED"

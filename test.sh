#!/bin/bash
# test.sh — end-to-end live test for the kernel anticheat.
# Requires root (loads a kernel module). Run:  sudo ./test.sh
set -u

cd "$(dirname "$0")"
VICTIM_PID=""
FAILED=0

say()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  PASS\033[0m  %s\n' "$*"; }
bad()  { printf '\033[1;31m  FAIL\033[0m  %s\n' "$*"; FAILED=1; }

cleanup() {
    [ -n "$VICTIM_PID" ] && kill "$VICTIM_PID" 2>/dev/null
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
./anticheat modules >/dev/null && ok "modules listed" || bad "modules"

say "protecting a victim process (a bash that will fork a child)"
bash -c 'sleep 300 & echo $! > /tmp/ac_child.pid; wait' &
VICTIM_PID=$!
./anticheat protect --pid "$VICTIM_PID" >/dev/null && ok "protected pid $VICTIM_PID" || bad "protect"

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

say "memory scan (RWX detection)"
./anticheat scan --pid "$VICTIM_PID" >/dev/null && ok "scan ok" || bad "scan"

say "memory integrity baseline"
./anticheat scan --pid "$VICTIM_PID" --hash --save >/dev/null 2>&1 && ok "baseline saved" || bad "baseline save"
./anticheat scan --pid "$VICTIM_PID" --hash --check >/dev/null 2>&1 && ok "baseline verified" || bad "baseline check"

say "unprotect + cleanup"
./anticheat unprotect --pid "$VICTIM_PID" >/dev/null && ok "unprotected" || bad "unprotect"
[ -n "$CHILD_PID" ] && kill "$CHILD_PID" 2>/dev/null

say "locking the module (rmmod must fail while locked)"
./anticheat lock >/dev/null && ok "locked" || bad "lock"
if rmmod anticheat 2>/dev/null; then bad "rmmod succeeded while locked"; else ok "rmmod correctly refused"; fi
./anticheat unlock >/dev/null && ok "unlocked" || bad "unlock"

say "unloading"
rmmod anticheat && ok "module unloaded" || bad "rmmod"

echo
if [ "$FAILED" -eq 0 ]; then
    printf '\033[1;32mALL TESTS PASSED\033[0m\n'
else
    printf '\033[1;31mSOME TESTS FAILED\033[0m\n'
fi
exit "$FAILED"

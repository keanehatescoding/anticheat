#!/bin/bash
# mock_test.sh — run the daemon CLI end-to-end against a userspace mock of
# /dev/anticheat (test/libmock_anticheat.so via LD_PRELOAD).
#
# Exercises every command and code path without a kernel module or root:
#   status, protect/list/unprotect, scan (+hash baselines), syscalls
#   (clean AND compromised), modules (hidden module detection), events,
#   lock/unlock, and the monitoring daemon (incl. graceful SIGTERM exit).
#
# Build:  make test-mock
set -u

cd "$(dirname "$0")/.."

export LD_PRELOAD="$PWD/test/libmock_anticheat.so"
export AC_MOCK_ROOT=1
export AC_MOCK_STATE="/tmp/ac_mock_state_$$"
export AC_BASELINE_DIR="/tmp/ac_baselines_$$"

FAIL=0

pass() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; FAIL=1; }

# expect_rc <desc> <want_rc> <cmd...>
expect_rc() {
    local desc="$1" want="$2"; shift 2
    "$@" >/dev/null 2>&1
    local rc=$?
    if [ "$rc" -eq "$want" ]; then pass "$desc (rc=$rc)"; else fail "$desc (want rc=$want, got $rc)"; fi
}

# expect_out <desc> <needle> <cmd...>
expect_out() {
    local desc="$1" needle="$2"; shift 2
    local out
    out=$("$@" 2>&1)
    if printf '%s' "$out" | grep -qF "$needle"; then
        pass "$desc"
    else
        fail "$desc (missing '$needle'); output: $(printf '%s' "$out" | head -2)"
    fi
}

rm -f "$AC_MOCK_STATE"
mkdir -p "$AC_BASELINE_DIR"

# scan + hash the anticheat binary *itself*: after `exec`, the process is the
# scanner, so /proc/PID/mem is readable without ptrace privileges (yama scope).
SELFSCAN='exec ./anticheat scan --pid $BASHPID'

echo "== basic CLI =="
expect_rc  "help"                     0 ./anticheat help
expect_rc  "unknown command"          1 ./anticheat bogus

echo "== status =="
expect_rc  "status"                   0 ./anticheat status
expect_out "status: version"          "version"        ./anticheat status

echo "== protect / list / unprotect =="
expect_rc  "protect --pid \$\$"        0 ./anticheat protect --pid $$
expect_out "list shows pid"            "$$"             ./anticheat list
expect_rc  "protect --comm bash"      0 ./anticheat protect --comm bash
expect_rc  "unprotect"                0 ./anticheat unprotect --pid $$

echo "== scan (VMA + RWX) =="
expect_rc  "scan --pid \$\$"           0 ./anticheat scan --pid $$
expect_out "scan summary"              "VMA(s)"         ./anticheat scan --pid $$

echo "== memory-integrity baselines (self-scan) =="
expect_rc  "scan --hash --save"       0 bash -c "$SELFSCAN --hash --save"
expect_rc  "scan --hash --check"      0 bash -c "$SELFSCAN --hash --check"
expect_out "baseline matches"          "matches baseline" bash -c "$SELFSCAN --hash --check"

echo "== syscall integrity (clean + compromised) =="
expect_rc  "syscalls clean"           0 ./anticheat syscalls
expect_out "syscalls OK message"       "no hooks detected" ./anticheat syscalls
expect_rc  "syscalls compromised -> rc 2" 2 env AC_MOCK_HOOKED=1 ./anticheat syscalls
expect_out "syscalls alert"            "COMPROMISED"    env AC_MOCK_HOOKED=1 ./anticheat syscalls

echo "== hidden module detection =="
expect_rc  "modules -> rc 2 (hidden)" 2 ./anticheat modules
expect_out "modules: hidden count"     "hidden modules: 1" ./anticheat modules
expect_out "modules: hidden name"      "hidden_rootkit" ./anticheat modules

echo "== events =="
expect_out "events: ptrace denied"     "PTRACE-DENIED"  env AC_MOCK_ATTACK=1 ./anticheat events
expect_out "events: info"              "INFO"           ./anticheat events

echo "== lock / unlock =="
expect_rc  "lock"                     0 ./anticheat lock
expect_out "status: locked"            "locked            : 1" ./anticheat status
expect_rc  "unlock"                   0 ./anticheat unlock
expect_out "status: unlocked"          "locked            : 0" ./anticheat status

echo "== error paths =="
expect_rc  "scan without --pid"       1 ./anticheat scan
expect_rc  "protect without args"     1 ./anticheat protect

echo "== monitoring daemon (start --foreground) =="
# --preserve-status: report the command's own exit status; a clean exit after
# SIGTERM is rc=0, a hang is caught by -k (SIGKILL -> 137).
out=$(timeout -k 2 --preserve-status 4 env AC_MOCK_ATTACK=1 ./anticheat start --foreground 2>&1)
rc=$?
[ "$rc" -eq 0 ] && pass "start: clean exit on SIGTERM" || fail "start (rc=$rc)"
printf '%s' "$out" | grep -q "PTRACE-DENIED" && pass "start: PTRACE alert logged" \
    || fail "start: no PTRACE alert"
printf '%s' "$out" | grep -q "hidden from /proc/modules" && pass "start: hidden-module alert" \
    || fail "start: no hidden-module alert"

echo
if [ "$FAIL" -eq 0 ]; then
    printf '\033[1;32mALL MOCK TESTS PASSED\033[0m\n'
else
    printf '\033[1;31mSOME MOCK TESTS FAILED\033[0m\n'
fi
exit "$FAIL"

#!/bin/bash
# diag.sh — root diagnostics for the anticheat module (run: sudo ./diag.sh)
# Shows which kprobes registered, the resolved text bounds, the syscall
# table discovery result, and the failing commands' real output.
set -u
cd "$(dirname "$0")"

echo "== environment =="
echo "kernel: $(uname -r) $(uname -v)"
echo "yama ptrace_scope: $(cat /proc/sys/kernel/yama/ptrace_scope)"
echo "kptr_restrict:     $(cat /proc/sys/kernel/kptr_restrict)"
free -m | head -2

echo
echo "== load module (verbose) =="
rmmod anticheat 2>/dev/null
insmod ./anticheat.ko ac_verbose=1 || { echo "INSMOD FAILED"; exit 1; }
sleep 0.3

echo
echo "== dmesg: module init =="
dmesg | tail -80 | grep -iE "anticheat|probe|kprobe|syscall|text bounds" | tail -25

echo
echo "== status =="
./anticheat status

echo
echo "== control: root ptrace on a NON-protected process =="
sleep 300 & P=$!
timeout 2 strace -p $P -e trace=none >/dev/null 2>&1; rc=$?
kill $P 2>/dev/null
echo "strace -p non-protected rc=$rc   (0 = attach worked, 124 = hung/timed out)"

echo
echo "== protected process + attach =="
bash -c 'sleep 300 & echo $! > /tmp/ac_diag_child; wait' & V=$!
./anticheat protect --pid $V
sleep 0.5
C=$(cat /tmp/ac_diag_child); rm -f /tmp/ac_diag_child
echo "victim=$V child=$C"
timeout 2 strace -p $V -e trace=none >/dev/null 2>&1; rc=$?
echo "strace -p protected rc=$rc"
echo "list:"
./anticheat list

echo
echo "== events (should contain FORK + PTRACE-DENIED) =="
./anticheat events; echo "events rc=$?"

echo
echo "== syscalls =="
./anticheat syscalls; echo "rc=$?"

echo
echo "== kallsyms cross-check (root) =="
grep -E " (__x64_sys_read|__x64_sys_write|sys_call_table)$" /proc/kallsyms

echo
echo "== dmesg: after load (discovery diagnostics) =="
dmesg | tail -60 | grep -iE "anticheat" | tail -12

echo
echo "== scan (RWX) — expect diagnostics on failure =="
./anticheat scan --pid $$; echo "scan rc=$?"

echo
echo "== modules =="
./anticheat modules; echo "rc=$?"

echo
echo "== dmesg: post-attempt =="
dmesg | tail -30 | grep -iE "anticheat|probe|kprobe|ptrace|kill" | tail -15

./anticheat unprotect --pid $V >/dev/null 2>&1
kill $V $C 2>/dev/null
rmmod anticheat 2>/dev/null
echo "== done =="

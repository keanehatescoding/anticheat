#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""test_ratelimiter_unit.py -- fast, deterministic test of
RateLimiter._prune()'s bucket-cleanup behavior.

RateLimiter._buckets grows one entry per distinct key (source IP) ever
seen, with nothing to evict them but _prune() (see the class's own
docstring in ac_server.py). The live HTTP suite (test_server.sh)
thoroughly exercises the *rate-limiting* behavior this class provides,
but has no way to observe its *internal* memory behavior under many
distinct keys -- that's what this test is for, isolated from any server/
network/root, and fast enough (~1s) to run on every push rather than
only in the nightly stress job (see stress_test.sh for the live,
concurrent, sustained-load counterpart to this).

No unittest framework, no pytest -- matches this project's existing
test-script style (plain assert-and-report, see test_server.sh).
"""
import importlib.util
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ac_server", HERE / "ac_server.py")
ac_server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ac_server)

FAIL = 0


def check(name, cond):
    global FAIL
    status = "\033[1;32mPASS\033[0m" if cond else "\033[1;31mFAIL\033[0m"
    print(f"  {status}  {name}")
    if not cond:
        FAIL = 1


print("=== RateLimiter unit test: bucket pruning ===")
print()

WINDOW = 1  # seconds -- short so this test stays fast
N_KEYS = 500

rl = ac_server.RateLimiter(limit=1_000_000, window=WINDOW)

# Populate _buckets with many distinct keys, the same shape a burst of
# traffic from many distinct source IPs produces.
for i in range(N_KEYS):
    rl.allow(f"203.0.113.{i % 256}-{i}")

check(f"buckets populated ({N_KEYS} distinct keys)", len(rl._buckets) == N_KEYS)

# _prune() only runs opportunistically from inside allow() (roughly once
# per window -- see allow()'s "now - self._last_prune >= self.window"
# check), so an actual elapsed window plus one more allow() call is what
# it takes to trigger it for real, not a mocked clock.
time.sleep(WINDOW + 0.1)
rl.allow("trigger-prune")

# Every one of the N_KEYS buckets was first touched before the sleep, so
# all of them are stale by now and should have been evicted -- only the
# just-added "trigger-prune" key (and possibly nothing else) should
# remain. A real leak (a _prune() that silently stopped evicting
# anything) would instead leave this at N_KEYS + 1.
check(
    "stale buckets evicted after their window elapses "
    f"(before={N_KEYS}, after={len(rl._buckets)})",
    len(rl._buckets) <= 2,
)

# _prune() itself should also have advanced _last_prune -- otherwise
# every single allow() call after the window would re-scan the (by now
# empty) dict for no reason forever, which isn't a correctness bug but
# would be a silent perf regression from the "roughly once per window"
# design this class documents for itself.
check(
    "_last_prune advanced past the window (prune isn't re-scanning every call)",
    rl._last_prune > time.time() - WINDOW - 0.5,
)

print()
if FAIL:
    print("\033[1;31mSOME RATELIMITER UNIT TESTS FAILED\033[0m")
else:
    print("\033[1;32mALL RATELIMITER UNIT TESTS PASSED\033[0m")
sys.exit(FAIL)

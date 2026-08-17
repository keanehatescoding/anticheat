#!/bin/bash
# stress_test.sh -- sustained concurrent load against a real ac_server.py
# instance: $STRESS_CONCURRENCY workers hammering /report in parallel for
# $STRESS_DURATION seconds, verifying the server survives (no crash, no
# unexpected errors) and that every successfully-201'd report is actually
# durably recorded -- something test_server.sh's short, mostly-sequential
# suite doesn't exercise. Complements test_ratelimiter_unit.py: that one
# proves RateLimiter._buckets doesn't grow unboundedly in isolation; this
# one proves the server as a whole holds up under real concurrent
# ThreadingHTTPServer + one-SQLite-connection-per-request load.
#
# No root, no kernel module -- pure HTTP against a throwaway SQLite DB,
# same as test_server.sh. Deliberately NOT part of the fast per-push CI
# job (see .github/workflows/stress.yml) -- this is meant to run for
# minutes, not seconds.
#
# Override via environment: STRESS_DURATION=1800 STRESS_CONCURRENCY=50
# ./server/stress_test.sh for a real extended soak run locally.
set -u

cd "$(dirname "$0")" || exit 1

DURATION="${STRESS_DURATION:-90}"
CONCURRENCY="${STRESS_CONCURRENCY:-20}"
PORT=18900
TESTDIR="$(mktemp -d /tmp/ac_server_stress.XXXXXXXX)"
DB="$TESTDIR/ac_server.db"
REPORT_KEY="stress-report-key-$$"
ADMIN_KEY="stress-admin-key-$$"
BASE="http://127.0.0.1:$PORT"

FAIL=0
pass() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; FAIL=1; }

SERVER_PID=""
WORKER_PIDS=""
# shellcheck disable=SC2317,SC2329
cleanup() {
    # Worker PIDs first: each runs its own while-loop for the full
    # $DURATION independently of the server, so on any early/abnormal
    # exit (Ctrl-C, a CI job timeout sending SIGTERM, a failure earlier
    # in this script) they must be killed explicitly -- they are NOT
    # children of $SERVER_PID and killing only that PID leaves every
    # worker's loop running for the rest of its original $DURATION,
    # orphaned, still hammering $PORT.
    # shellcheck disable=SC2086
    [ -n "$WORKER_PIDS" ] && kill $WORKER_PIDS 2>/dev/null
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    # shellcheck disable=SC2086
    [ -n "$WORKER_PIDS" ] && wait $WORKER_PIDS 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    rm -rf "$TESTDIR"
}
trap cleanup EXIT
# EXIT alone does not reliably run on every signal-terminated shell in
# every context -- explicit traps make cleanup unconditional rather than
# incidental, which matters here specifically because leftover workers
# are a real, previously-hit failure mode (see the comment above), not
# a hypothetical one.
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

echo "=== server stress test: $CONCURRENCY workers x ${DURATION}s ==="
echo

# Rate limit set far above anything this run could plausibly trip --
# rate-limiting correctness itself is test_server.sh's job; this run is
# about concurrency/durability, and a 429 here would just be noise
# obscuring that signal.
AC_SERVER_REPORT_KEY="$REPORT_KEY" AC_SERVER_ADMIN_KEY="$ADMIN_KEY" \
    python3 ./ac_server.py --host 127.0.0.1 --port "$PORT" --db "$DB" \
    --rate-limit 1000000 --rate-window 60 \
    >"$TESTDIR/server.log" 2>&1 &
SERVER_PID=$!

READY=0
for _ in $(seq 1 50); do
    if curl -s "$BASE/banned/x" -H "Authorization: Bearer $ADMIN_KEY" 2>/dev/null \
        | grep -q '"banned"'; then
        READY=1
        break
    fi
    sleep 0.1
done
if [ "$READY" -ne 1 ]; then
    fail "server never became ready on $BASE (port collision with another service?)"
    exit 1
fi

# Each worker hammers /report with its own client_id for the full
# duration, recording how many 201s and how many non-201s it saw. Result
# written to a file rather than a shared variable -- these run as
# separate background processes, nothing else crosses that boundary.
worker() {
    local id="$1"
    local cid="stress-worker-$id-$$"
    local ok=0
    local errors=0
    local n=0
    local end=$(( $(date +%s) + DURATION ))
    while [ "$(date +%s)" -lt "$end" ]; do
        n=$((n + 1))
        code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/report" \
            -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
            -d "{\"client_id\":\"$cid\",\"event_type\":\"X\",\"detail\":\"n=$n\",\"ts\":$n}")
        if [ "$code" = "201" ]; then
            ok=$((ok + 1))
        else
            errors=$((errors + 1))
        fi
    done
    printf '%s %d %d\n' "$cid" "$ok" "$errors" > "$TESTDIR/worker-$id.result"
}

for i in $(seq 1 "$CONCURRENCY"); do
    worker "$i" &
    WORKER_PIDS="$WORKER_PIDS $!"
done
# shellcheck disable=SC2086
wait $WORKER_PIDS
WORKER_PIDS=""  # all reaped normally -- nothing left for cleanup() to kill

echo "-- checking every worker's successful reports landed durably --"
TOTAL_OK=0
TOTAL_ERRORS=0
DB_MISMATCH=0
for i in $(seq 1 "$CONCURRENCY"); do
    read -r CID OK ERRORS < "$TESTDIR/worker-$i.result"
    TOTAL_OK=$((TOTAL_OK + OK))
    TOTAL_ERRORS=$((TOTAL_ERRORS + ERRORS))
    # Queried directly against the DB file, not the /reports API -- that
    # endpoint caps at 200 rows (see list_reports()'s default limit),
    # which a sustained run can easily exceed; a direct COUNT(*) has no
    # such cap and is the actual ground truth being checked here.
    DB_COUNT=$(python3 -c "
import sqlite3
con = sqlite3.connect('$DB')
print(con.execute('SELECT COUNT(*) FROM reports WHERE client_id = ?', ('$CID',)).fetchone()[0])
")
    if [ "$DB_COUNT" != "$OK" ]; then
        fail "worker $i: sent $OK successful reports but DB has $DB_COUNT rows for $CID"
        DB_MISMATCH=1
    fi
done
[ "$DB_MISMATCH" -eq 0 ] && pass "every worker's successful reports landed durably in the DB"

pass "sustained load: $TOTAL_OK total successful reports across $CONCURRENCY workers in ${DURATION}s"
if [ "$TOTAL_ERRORS" -gt 0 ]; then
    fail "$TOTAL_ERRORS requests failed with a non-201 status (rate limit was set high enough that none of this should be rate-limiting)"
else
    pass "zero failed requests during the run"
fi

if grep -q "Traceback" "$TESTDIR/server.log"; then
    fail "server logged an unhandled exception during the stress run"
else
    pass "no unhandled exceptions logged during the stress run"
fi

echo "-- confirming the server is still responsive after sustained load --"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/banned/x" -H "Authorization: Bearer $ADMIN_KEY")
if [ "$CODE" = "200" ]; then
    pass "server still responsive after sustained load"
else
    fail "server not responsive after sustained load (got $CODE)"
fi

echo
if [ "$FAIL" -eq 0 ]; then
    printf '\033[1;32mALL STRESS CHECKS PASSED\033[0m\n'
else
    printf '\033[1;31mSOME STRESS CHECKS FAILED\033[0m\n'
fi
exit "$FAIL"

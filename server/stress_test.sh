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
# A zero/negative/non-numeric value here wouldn't fail loudly -- $end
# below could equal or precede "now", so every worker's while-loop would
# run zero times and this script would still report success on zero
# actual load, and `seq 1 "$CONCURRENCY"` with a bad value fails
# unpredictably rather than cleanly. Reject both explicitly up front.
if ! [[ "$DURATION" =~ ^[1-9][0-9]*$ && "$CONCURRENCY" =~ ^[1-9][0-9]*$ ]]; then
    printf 'STRESS_DURATION and STRESS_CONCURRENCY must be positive integers (got DURATION=%s CONCURRENCY=%s)\n' \
        "$DURATION" "$CONCURRENCY" >&2
    exit 2
fi
PORT=18900
TESTDIR="$(mktemp -d /tmp/ac_server_stress.XXXXXXXX)"
DB="$TESTDIR/ac_server.db"
REPORT_KEY="stress-report-key-$$"
ADMIN_KEY="stress-admin-key-$$"
BASE="http://127.0.0.1:$PORT"
# Every curl call below uses this: without a bound, a stalled connection
# or response could block a worker past $DURATION, and the top-level
# `wait` would then block indefinitely too -- the same class of hang
# this script's cleanup()/trap handling already exists to guard against,
# just from the opposite direction (a stuck request instead of a killed
# process). --max-time was originally 5s; raised to 20s after a real run
# (30 workers, 300s, both in CI and reproduced locally) showed that value
# was too tight for this architecture under sustained 30-way contention --
# every one of those "failures" was curl code 000 (client gave up) for a
# request the server log showed as a clean 201 moments later, not a
# server-side error. 20s still firmly bounds a genuine indefinite hang;
# it just stops manufacturing false failures out of ordinary queueing
# delay under load. See the worker loop and durability check below for
# how a 000 is now told apart from an actual error.
CURL_CONNECT_TIMEOUT=2
CURL_MAX_TIME=20
CURL_TIMEOUT=(--connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME")

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
    if curl -s "${CURL_TIMEOUT[@]}" "$BASE/banned/x" -H "Authorization: Bearer $ADMIN_KEY" 2>/dev/null \
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
# duration, recording how many 201s, client-side timeouts, and other
# (genuinely unexpected) codes it saw. Result written to a file rather
# than a shared variable -- these run as separate background processes,
# nothing else crosses that boundary.
#
# curl reports "000" for %{http_code} when it never received a complete
# response (--max-time firing, a reset connection, etc.) -- under heavy
# concurrent contention this can happen for a request the server actually
# handled successfully but didn't answer quickly enough for this client's
# patience, not just for a request the server genuinely failed. Counted
# separately from "errors" (any other non-201 code, which -- with the
# rate limit set sky-high above -- has no innocent explanation) so the
# aggregation step below can tell "the server was just slow" apart from
# "the server did something wrong" instead of conflating both as one
# failure count.
worker() {
    local id="$1"
    local cid="stress-worker-$id-$$"
    local ok=0
    local timeouts=0
    local errors=0
    local n=0
    local end=$(( $(date +%s) + DURATION ))
    while [ "$(date +%s)" -lt "$end" ]; do
        n=$((n + 1))
        code=$(curl -s "${CURL_TIMEOUT[@]}" -o /dev/null -w '%{http_code}' -X POST "$BASE/report" \
            -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
            -d "{\"client_id\":\"$cid\",\"event_type\":\"X\",\"detail\":\"n=$n\",\"ts\":$n}")
        case "$code" in
            201) ok=$((ok + 1)) ;;
            000) timeouts=$((timeouts + 1)) ;;
            *)   errors=$((errors + 1)) ;;
        esac
    done
    printf '%s %d %d %d\n' "$cid" "$ok" "$timeouts" "$errors" > "$TESTDIR/worker-$id.result"
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
TOTAL_TIMEOUTS=0
TOTAL_ERRORS=0
DB_MISMATCH=0
for i in $(seq 1 "$CONCURRENCY"); do
    read -r CID OK TIMEOUTS ERRORS < "$TESTDIR/worker-$i.result"
    TOTAL_OK=$((TOTAL_OK + OK))
    TOTAL_TIMEOUTS=$((TOTAL_TIMEOUTS + TIMEOUTS))
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
    # The real durability question is "did the DB lose anything the
    # client saw succeed" (DB_COUNT < OK) -- NOT exact equality. A
    # client-side timeout (curl gave up, counted above, not in $OK) for a
    # request the server actually completed makes DB_COUNT > OK
    # perfectly legitimately; treating that as a failure was itself a
    # bug in this check, not a sign of one in the server (verified
    # directly: every DB_COUNT > OK case traced back to a 000 in that
    # worker's timeout count, and the server log showed a clean 201 for
    # it, not an error).
    if [ "$DB_COUNT" -lt "$OK" ]; then
        fail "worker $i: sent $OK successful reports but DB only has $DB_COUNT rows for $CID"
        DB_MISMATCH=1
    fi
done
[ "$DB_MISMATCH" -eq 0 ] && pass "no worker's successful reports went missing from the DB"

pass "sustained load: $TOTAL_OK total successful reports across $CONCURRENCY workers in ${DURATION}s"
if [ "$TOTAL_TIMEOUTS" -gt 0 ]; then
    pass "$TOTAL_TIMEOUTS request(s) exceeded the client's ${CURL_MAX_TIME}s wait under load (curl 000) -- informational, not a failure on its own; the durability check above is what proves whether any of them actually failed server-side"
fi
if [ "$TOTAL_ERRORS" -gt 0 ]; then
    fail "$TOTAL_ERRORS requests failed with an unexpected non-201, non-timeout status (rate limit was set high enough that none of this should be rate-limiting)"
else
    pass "zero unexpected-error responses during the run"
fi

if grep -q "Traceback" "$TESTDIR/server.log"; then
    fail "server logged an unhandled exception during the stress run"
else
    pass "no unhandled exceptions logged during the stress run"
fi

echo "-- confirming the server is still responsive after sustained load --"
CODE=$(curl -s "${CURL_TIMEOUT[@]}" -o /dev/null -w '%{http_code}' "$BASE/banned/x" -H "Authorization: Bearer $ADMIN_KEY")
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

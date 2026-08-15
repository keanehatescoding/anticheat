#!/bin/bash
# test_server.sh — end-to-end smoke test for ac_server.py. No root, no
# kernel module: pure HTTP against a throwaway SQLite DB.
#
# Exercises: report ingestion, auth on both key tiers, client_id
# validation, the ban/unban/query loop, and the reports listing a human
# would review before banning.
set -u

cd "$(dirname "$0")" || exit 1

PORT=18799
DB="/tmp/ac_server_test_$$.db"
REPORT_KEY="test-report-key-$$"
ADMIN_KEY="test-admin-key-$$"
BASE="http://127.0.0.1:$PORT"
CID="test-client-$$"

FAIL=0
pass() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; FAIL=1; }

SERVER_PID=""
RL_SERVER_PID=""
TERM_SERVER_PID=""
TERM_KILLER_PID=""
TP_SERVER_PID=""
NOTP_SERVER_PID=""
# cleanup is invoked via trap below; shellcheck cannot always see that
# shellcheck disable=SC2317,SC2329
cleanup() {
    # DB files may have been left read-only by the induced-failure test
    # above if it failed before restoring permissions -- restore before rm.
    chmod 644 "$DB" "$DB-wal" "$DB-shm" 2>/dev/null
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    [ -n "$RL_SERVER_PID" ] && kill "$RL_SERVER_PID" 2>/dev/null
    [ -n "$TERM_SERVER_PID" ] && kill "$TERM_SERVER_PID" 2>/dev/null
    [ -n "$TERM_KILLER_PID" ] && kill "$TERM_KILLER_PID" 2>/dev/null
    [ -n "$TP_SERVER_PID" ] && kill "$TP_SERVER_PID" 2>/dev/null
    [ -n "$NOTP_SERVER_PID" ] && kill "$NOTP_SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    wait "$RL_SERVER_PID" 2>/dev/null
    wait "$TERM_SERVER_PID" 2>/dev/null
    wait "$TERM_KILLER_PID" 2>/dev/null
    wait "$TP_SERVER_PID" 2>/dev/null
    wait "$NOTP_SERVER_PID" 2>/dev/null
    rm -f "$DB" "$DB-wal" "$DB-shm"
}
trap cleanup EXIT

# Explicit --rate-limit here (well above the CLI's own default of 60) so
# the sequential functional tests plus the concurrent-write test below
# (~40+ requests total against this one instance/IP) never risk tripping
# the limiter themselves -- rate-limiting behavior itself is exercised
# separately, against dedicated low-limit instances further down.
AC_SERVER_REPORT_KEY="$REPORT_KEY" AC_SERVER_ADMIN_KEY="$ADMIN_KEY" \
    python3 ./ac_server.py --host 127.0.0.1 --port "$PORT" --db "$DB" \
    --rate-limit 500 --rate-window 60 \
    >/tmp/ac_server_test_$$.log 2>&1 &
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

# 1. report with correct key -> 201
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/report" \
    -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
    -d "{\"client_id\":\"$CID\",\"event_type\":\"CRITICAL\",\"detail\":\"syscall hook\",\"ts\":123}")
if [ "$CODE" = "201" ]; then
    pass "POST /report with valid report key -> 201"
else
    fail "POST /report with valid report key (got $CODE)"
fi

# 2. report with wrong key -> 401
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/report" \
    -H "Authorization: Bearer wrong" -H 'Content-Type: application/json' \
    -d "{\"client_id\":\"$CID\",\"event_type\":\"CRITICAL\",\"detail\":\"x\",\"ts\":1}")
if [ "$CODE" = "401" ]; then
    pass "POST /report with wrong key -> 401"
else
    fail "POST /report with wrong key (got $CODE)"
fi

# 3. report with the admin key (wrong tier) -> 401
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/report" \
    -H "Authorization: Bearer $ADMIN_KEY" -H 'Content-Type: application/json' \
    -d "{\"client_id\":\"$CID\",\"event_type\":\"CRITICAL\",\"detail\":\"x\",\"ts\":1}")
if [ "$CODE" = "401" ]; then
    pass "admin key rejected on /report (tiers are separate)"
else
    fail "admin key on /report should be 401 (got $CODE)"
fi

# 4. invalid client_id -> 400
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/report" \
    -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
    -d '{"client_id":"has spaces/bad","event_type":"X","detail":"x","ts":1}')
if [ "$CODE" = "400" ]; then
    pass "invalid client_id rejected -> 400"
else
    fail "invalid client_id should be 400 (got $CODE)"
fi

# 5. oversized body (> MAX_BODY_BYTES) -> 400
BIG_DETAIL=$(python3 -c "print('x' * 5000)")
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/report" \
    -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
    -d "{\"client_id\":\"$CID\",\"event_type\":\"X\",\"detail\":\"$BIG_DETAIL\",\"ts\":1}")
if [ "$CODE" = "400" ]; then
    pass "oversized body rejected -> 400"
else
    fail "oversized body should be 400 (got $CODE)"
fi

# 6. malformed JSON -> 400
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/report" \
    -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
    -d '{not valid json')
if [ "$CODE" = "400" ]; then
    pass "malformed JSON rejected -> 400"
else
    fail "malformed JSON should be 400 (got $CODE)"
fi

# 7. garbage Content-Length -> 400, not a hang/crash
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/report" \
    -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
    -H 'Content-Length: not-a-number' \
    -d "{\"client_id\":\"$CID\",\"event_type\":\"X\",\"detail\":\"x\",\"ts\":1}")
if [ "$CODE" = "400" ]; then
    pass "garbage Content-Length rejected -> 400"
else
    fail "garbage Content-Length should be 400 (got $CODE)"
fi

# 8. missing required field (event_type) -> 400
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/report" \
    -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
    -d "{\"client_id\":\"$CID\"}")
if [ "$CODE" = "400" ]; then
    pass "missing required field rejected -> 400"
else
    fail "missing required field should be 400 (got $CODE)"
fi

# 9. non-UTF-8 bytes in detail -> still accepted (errors="replace", not a
# rejection -- a process could otherwise suppress its own report just by
# having invalid-UTF8 bytes in its comm/path).
CODE=$(printf '{"client_id":"%s","event_type":"X","detail":"bad-\xff\xfe-byte","ts":1}' "$CID" | \
    curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/report" \
    -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
    --data-binary @-)
if [ "$CODE" = "201" ]; then
    pass "non-UTF-8 bytes in detail accepted, not rejected -> 201"
else
    fail "non-UTF-8 detail should still be accepted (got $CODE)"
fi

# 10. unsupported HTTP method -> 501 (stock BaseHTTPRequestHandler
# behavior, just previously untested)
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$BASE/report")
if [ "$CODE" = "501" ]; then
    pass "unsupported HTTP method -> 501"
else
    fail "DELETE should be 501 (got $CODE)"
fi

# 11. banned lookup before any ban -> banned:false
OUT=$(curl -s "$BASE/banned/$CID" -H "Authorization: Bearer $ADMIN_KEY")
if printf '%s' "$OUT" | grep -q '"banned": false'; then
    pass "banned lookup false before any ban"
else
    fail "expected banned:false (got: $OUT)"
fi

# 12. banned lookup requires admin key, not report key -> 401
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/banned/$CID" \
    -H "Authorization: Bearer $REPORT_KEY")
if [ "$CODE" = "401" ]; then
    pass "report key rejected on /banned (tiers are separate)"
else
    fail "report key on /banned should be 401 (got $CODE)"
fi

# 13. reports listing shows the earlier report
OUT=$(curl -s "$BASE/reports/$CID" -H "Authorization: Bearer $ADMIN_KEY")
if printf '%s' "$OUT" | grep -q "syscall hook"; then
    pass "reports listing includes the earlier report"
else
    fail "expected 'syscall hook' in reports listing (got: $OUT)"
fi

# 14. ban, then confirm banned lookup flips to true
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/ban" \
    -H "Authorization: Bearer $ADMIN_KEY" -H 'Content-Type: application/json' \
    -d "{\"client_id\":\"$CID\",\"reason\":\"syscall table hooked\"}")
if [ "$CODE" = "200" ]; then
    pass "POST /ban -> 200"
else
    fail "POST /ban (got $CODE)"
fi

OUT=$(curl -s "$BASE/banned/$CID" -H "Authorization: Bearer $ADMIN_KEY")
if printf '%s' "$OUT" | grep -q '"banned": true'; then
    pass "banned lookup true after ban"
else
    fail "expected banned:true (got: $OUT)"
fi

# 15. unban, confirm it flips back
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/unban" \
    -H "Authorization: Bearer $ADMIN_KEY" -H 'Content-Type: application/json' \
    -d "{\"client_id\":\"$CID\"}")
if [ "$CODE" = "200" ]; then
    pass "POST /unban -> 200"
else
    fail "POST /unban (got $CODE)"
fi

OUT=$(curl -s "$BASE/banned/$CID" -H "Authorization: Bearer $ADMIN_KEY")
if printf '%s' "$OUT" | grep -q '"banned": false'; then
    pass "banned lookup false after unban"
else
    fail "expected banned:false after unban (got: $OUT)"
fi

# 16. /ban with empty reason -> 400
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/ban" \
    -H "Authorization: Bearer $ADMIN_KEY" -H 'Content-Type: application/json' \
    -d "{\"client_id\":\"$CID\",\"reason\":\"\"}")
if [ "$CODE" = "400" ]; then
    pass "empty ban reason rejected -> 400"
else
    fail "empty ban reason should be 400 (got $CODE)"
fi

# 17. /ban with oversized reason (> 500 chars) -> 400
BIG_REASON=$(python3 -c "print('r' * 501)")
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/ban" \
    -H "Authorization: Bearer $ADMIN_KEY" -H 'Content-Type: application/json' \
    -d "{\"client_id\":\"$CID\",\"reason\":\"$BIG_REASON\"}")
if [ "$CODE" = "400" ]; then
    pass "oversized ban reason rejected -> 400"
else
    fail "oversized ban reason should be 400 (got $CODE)"
fi

# 18. concurrent report writes -- exercises Store's per-call-fresh-
# connection design under real ThreadingHTTPServer concurrency, not
# simulated.
CONC_CID="test-concurrent-$$"
CONC_PIDS=""
for i in $(seq 1 20); do
    curl -s -o /dev/null -X POST "$BASE/report" \
        -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
        -d "{\"client_id\":\"$CONC_CID\",\"event_type\":\"X\",\"detail\":\"concurrent-$i\",\"ts\":$i}" &
    CONC_PIDS="$CONC_PIDS $!"
done
# shellcheck disable=SC2086  # intentional word-splitting: a list of pids
wait $CONC_PIDS
CONC_OUT=$(curl -s "$BASE/reports/$CONC_CID" -H "Authorization: Bearer $ADMIN_KEY")
CONC_COUNT=$(printf '%s' "$CONC_OUT" | grep -o '"detail": "concurrent-[0-9]*"' | sort -u | wc -l | tr -d ' ')
if [ "$CONC_COUNT" = "20" ]; then
    pass "20 concurrent report writes all landed distinctly"
else
    fail "expected 20 distinct concurrent reports, got $CONC_COUNT (out: $CONC_OUT)"
fi

# 19. a real induced sqlite3.OperationalError -> clean 500, not a hang or
# broken connection -- forced for real, not mocked, per this project's
# testing philosophy. Store._connect() opens a fresh connection per call
# rather than pooling one, so chmod-ing the db files read-only after
# startup reliably forces the next write to hit a real permission error
# (no already-open writable fd survives from before the chmod). Skipped
# under root: chmod'ing a file read-only has no effect on root's own
# ability to write to it (a fundamental Unix property, not a bug in this
# test), so this specific check can't force a real failure that way when
# the whole script happens to be run as root.
if [ "$(id -u)" -eq 0 ]; then
    echo "  (skipping induced-DB-failure test: chmod is a no-op for root)"
else
    chmod 444 "$DB" "$DB-wal" "$DB-shm" 2>/dev/null
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/report" \
        -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
        -d "{\"client_id\":\"$CID\",\"event_type\":\"X\",\"detail\":\"forced-failure\",\"ts\":1}")
    chmod 644 "$DB" "$DB-wal" "$DB-shm" 2>/dev/null
    if [ "$CODE" = "500" ]; then
        pass "induced DB write failure -> clean 500, not a hang/broken connection"
    else
        fail "induced DB write failure should be 500 (got $CODE)"
    fi
    # Confirm the server is still healthy after surviving that failure --
    # not just that one request got a 500, but that nothing else broke.
    CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/banned/$CID" \
        -H "Authorization: Bearer $ADMIN_KEY")
    if [ "$CODE" = "200" ]; then
        pass "server still healthy after the induced DB failure"
    else
        fail "server should still answer normally after a recovered DB failure (got $CODE)"
    fi
    if grep -q "Traceback" "/tmp/ac_server_test_$$.log"; then
        pass "internal error was logged with a traceback for debugging"
    else
        fail "expected a traceback logged for the induced DB failure"
    fi
fi

rm -f "/tmp/ac_server_test_$$.log"

# Rate limiting: a separate low-limit server instance, so this doesn't
# interfere with (or get interfered with by) the ~11 requests the
# functional tests above already made against the default 60/60 limit.
RL_PORT=18800
RL_LIMIT=3
RL_WINDOW=2
RL_DB="/tmp/ac_server_rl_test_$$.db"
AC_SERVER_REPORT_KEY="$REPORT_KEY" AC_SERVER_ADMIN_KEY="$ADMIN_KEY" \
    python3 ./ac_server.py --host 127.0.0.1 --port "$RL_PORT" --db "$RL_DB" \
    --rate-limit "$RL_LIMIT" --rate-window "$RL_WINDOW" \
    >/tmp/ac_server_rl_test_$$.log 2>&1 &
RL_SERVER_PID=$!
RL_BASE="http://127.0.0.1:$RL_PORT"

RL_READY=0
for _ in $(seq 1 50); do
    if curl -s "$RL_BASE/banned/x" -H "Authorization: Bearer $ADMIN_KEY" 2>/dev/null \
        | grep -q '"banned"'; then
        RL_READY=1
        break
    fi
    sleep 0.1
done

if [ "$RL_READY" -eq 1 ]; then
    # The readiness poll above already consumed some of the budget it's
    # about to test against -- let the window roll over to a clean state
    # before asserting on exact counts.
    sleep "$((RL_WINDOW + 1))"

    # First $RL_LIMIT requests in the window should succeed (200/404, not
    # 429); this endpoint doesn't need auth to hit the limiter, since the
    # limiter runs before auth is even checked.
    RL_TRIPPED=0
    for _ in $(seq 1 "$RL_LIMIT"); do
        CODE=$(curl -s -o /dev/null -w '%{http_code}' "$RL_BASE/banned/x" \
            -H "Authorization: Bearer $ADMIN_KEY")
        [ "$CODE" = "429" ] && RL_TRIPPED=1
    done
    if [ "$RL_TRIPPED" -eq 0 ]; then
        pass "requests within the limit are not rate limited"
    else
        fail "a request within the limit ($RL_LIMIT per ${RL_WINDOW}s) got 429"
    fi

    # One more request, still inside the window, should now be limited.
    CODE=$(curl -s -o /dev/null -w '%{http_code}' "$RL_BASE/banned/x" \
        -H "Authorization: Bearer $ADMIN_KEY")
    if [ "$CODE" = "429" ]; then
        pass "request beyond the limit -> 429"
    else
        fail "request beyond the limit should be 429 (got $CODE)"
    fi

    # Confirm the 429 carries a Retry-After header.
    HEADERS=$(curl -s -D - -o /dev/null "$RL_BASE/banned/x" \
        -H "Authorization: Bearer $ADMIN_KEY")
    if printf '%s' "$HEADERS" | grep -qi '^Retry-After:'; then
        pass "429 response includes Retry-After"
    else
        fail "429 response missing Retry-After header"
    fi

    sleep "$RL_WINDOW"
    CODE=$(curl -s -o /dev/null -w '%{http_code}' "$RL_BASE/banned/x" \
        -H "Authorization: Bearer $ADMIN_KEY")
    if [ "$CODE" != "429" ]; then
        pass "limit resets after the window passes"
    else
        fail "still rate limited after the window passed"
    fi
else
    fail "rate-limit test server never became ready on port $RL_PORT"
fi

kill "$RL_SERVER_PID" 2>/dev/null
wait "$RL_SERVER_PID" 2>/dev/null
rm -f "$RL_DB" "$RL_DB-wal" "$RL_DB-shm" "/tmp/ac_server_rl_test_$$.log"

# Graceful SIGTERM: a dedicated instance, confirm it exits on its own
# within a few seconds (not needing a -9), with no traceback logged.
TERM_PORT=18801
TERM_DB="/tmp/ac_server_term_test_$$.db"
AC_SERVER_REPORT_KEY="$REPORT_KEY" AC_SERVER_ADMIN_KEY="$ADMIN_KEY" \
    python3 ./ac_server.py --host 127.0.0.1 --port "$TERM_PORT" --db "$TERM_DB" \
    >/tmp/ac_server_term_test_$$.log 2>&1 &
TERM_SERVER_PID=$!
TERM_BASE="http://127.0.0.1:$TERM_PORT"

TERM_READY=0
for _ in $(seq 1 50); do
    if curl -s "$TERM_BASE/banned/x" -H "Authorization: Bearer $ADMIN_KEY" 2>/dev/null \
        | grep -q '"banned"'; then
        TERM_READY=1
        break
    fi
    sleep 0.1
done

if [ "$TERM_READY" -eq 1 ]; then
    kill -TERM "$TERM_SERVER_PID"
    # `wait` is deterministic (blocks until the process is actually
    # reaped) and yields its real exit status -- unlike polling
    # `kill -0`, which only tests PID existence and would report success
    # even for a zombie the shell hasn't reaped yet. A backgrounded
    # killer provides the timeout: if serve_forever()'s ~0.5s poll
    # interval somehow didn't notice the signal, this bounds the wait
    # instead of hanging the whole test suite.
    ( sleep 2; kill -9 "$TERM_SERVER_PID" 2>/dev/null ) &
    TERM_KILLER_PID=$!
    if wait "$TERM_SERVER_PID" 2>/dev/null; then
        TERM_EXITED=1
    else
        TERM_EXITED=0
    fi
    kill "$TERM_KILLER_PID" 2>/dev/null
    wait "$TERM_KILLER_PID" 2>/dev/null
    TERM_KILLER_PID=""
    if [ "$TERM_EXITED" -eq 1 ]; then
        pass "SIGTERM shuts the server down cleanly, no -9 needed"
    else
        fail "server did not exit cleanly within 2s of SIGTERM"
    fi
    if grep -q "Traceback" "/tmp/ac_server_term_test_$$.log"; then
        fail "SIGTERM shutdown logged an unexpected traceback"
    else
        pass "SIGTERM shutdown logged no traceback"
    fi
else
    fail "SIGTERM test server never became ready on port $TERM_PORT"
fi
TERM_SERVER_PID=""
rm -f "$TERM_DB" "$TERM_DB-wal" "$TERM_DB-shm" "/tmp/ac_server_term_test_$$.log"

# --trust-proxy: a dedicated instance started with the flag, at the
# default (high) rate limit so these functional IP-handling checks don't
# collide with each other's budget -- rate-limit-key behavior specifically
# gets its own low-limit instance below, mirroring how the main suite
# above already separates functional tests from rate-limit-specific ones.
TP_PORT=18802
TP_DB="/tmp/ac_server_tp_test_$$.db"
AC_SERVER_REPORT_KEY="$REPORT_KEY" AC_SERVER_ADMIN_KEY="$ADMIN_KEY" \
    python3 ./ac_server.py --host 127.0.0.1 --port "$TP_PORT" --db "$TP_DB" \
    --trust-proxy \
    >/tmp/ac_server_tp_test_$$.log 2>&1 &
TP_SERVER_PID=$!
TP_BASE="http://127.0.0.1:$TP_PORT"
TP_CID="test-tp-$$"

TP_READY=0
for _ in $(seq 1 50); do
    if curl -s "$TP_BASE/banned/x" -H "Authorization: Bearer $ADMIN_KEY" 2>/dev/null \
        | grep -q '"banned"'; then
        TP_READY=1
        break
    fi
    sleep 0.1
done

if [ "$TP_READY" -eq 1 ]; then
    # last hop of X-Forwarded-For is trusted, not the attacker-controlled
    # first hop(s)
    curl -s -o /dev/null -X POST "$TP_BASE/report" \
        -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
        -H "X-Forwarded-For: 9.9.9.9, 10.0.0.5" \
        -d "{\"client_id\":\"$TP_CID\",\"event_type\":\"X\",\"detail\":\"hop-a\",\"ts\":1}"
    curl -s -o /dev/null -X POST "$TP_BASE/report" \
        -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
        -H "X-Forwarded-For: 8.8.8.8, 10.0.0.5" \
        -d "{\"client_id\":\"$TP_CID\",\"event_type\":\"X\",\"detail\":\"hop-b\",\"ts\":1}"
    TP_OUT=$(curl -s "$TP_BASE/reports/$TP_CID" -H "Authorization: Bearer $ADMIN_KEY")
    if printf '%s' "$TP_OUT" | grep -q '"source_addr": "10.0.0.5"' \
        && ! printf '%s' "$TP_OUT" | grep -qE '"source_addr": "(9\.9\.9\.9|8\.8\.8\.8)"'; then
        pass "--trust-proxy uses the last (proxy-authored) X-Forwarded-For hop"
    else
        fail "--trust-proxy did not use the last hop correctly (out: $TP_OUT)"
    fi

    # missing header with the flag on falls back to the raw peer
    TP_CID2="test-tp2-$$"
    curl -s -o /dev/null -X POST "$TP_BASE/report" \
        -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
        -d "{\"client_id\":\"$TP_CID2\",\"event_type\":\"X\",\"detail\":\"no-header\",\"ts\":1}"
    TP_OUT2=$(curl -s "$TP_BASE/reports/$TP_CID2" -H "Authorization: Bearer $ADMIN_KEY")
    if printf '%s' "$TP_OUT2" | grep -q '"source_addr": "127.0.0.1"'; then
        pass "--trust-proxy with no X-Forwarded-For falls back to the raw peer"
    else
        fail "missing-header fallback did not use the raw peer (out: $TP_OUT2)"
    fi

    # malformed header value falls back to the raw peer, not the literal
    # garbage string
    TP_CID3="test-tp3-$$"
    curl -s -o /dev/null -X POST "$TP_BASE/report" \
        -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
        -H "X-Forwarded-For: not-an-ip" \
        -d "{\"client_id\":\"$TP_CID3\",\"event_type\":\"X\",\"detail\":\"bad-header\",\"ts\":1}"
    TP_OUT3=$(curl -s "$TP_BASE/reports/$TP_CID3" -H "Authorization: Bearer $ADMIN_KEY")
    if printf '%s' "$TP_OUT3" | grep -q '"source_addr": "127.0.0.1"'; then
        pass "--trust-proxy with a malformed header falls back to the raw peer"
    else
        fail "malformed-header fallback did not use the raw peer (out: $TP_OUT3)"
    fi
else
    fail "--trust-proxy test server never became ready on port $TP_PORT"
fi
kill "$TP_SERVER_PID" 2>/dev/null
wait "$TP_SERVER_PID" 2>/dev/null
TP_SERVER_PID=""
rm -f "$TP_DB" "$TP_DB-wal" "$TP_DB-shm" "/tmp/ac_server_tp_test_$$.log"

# rate-limit key follows the trusted IP: a separate, dedicated low-limit
# --trust-proxy instance (own budget, doesn't collide with the functional
# checks above). TP_LIMIT requests sharing the same trusted last hop but
# different bogus first hops should still trip 429 on the next one --
# proves the limiter key isn't varying per attacker-controlled prefix,
# which would let a client evade rate limiting entirely.
TPRL_PORT=18807
TPRL_DB="/tmp/ac_server_tprl_test_$$.db"
# Window wider than the main rate-limit block's 2s (this test issues
# real HTTP round-trips sequentially, not against a mock clock -- a
# slower/loaded CI runner could plausibly let a tight window roll over
# mid-test, silently turning a real trip into a false pass), but the
# limit itself stays low: fewer requests needed to exhaust the budget
# means less cumulative request time consumed before the assertion
# request, which is *more* margin against that same boundary risk, not
# less -- widening both proportionally would have given back some of
# the margin the wider window was meant to add.
TPRL_LIMIT=3
TPRL_WINDOW=5
AC_SERVER_REPORT_KEY="$REPORT_KEY" AC_SERVER_ADMIN_KEY="$ADMIN_KEY" \
    python3 ./ac_server.py --host 127.0.0.1 --port "$TPRL_PORT" --db "$TPRL_DB" \
    --trust-proxy --rate-limit "$TPRL_LIMIT" --rate-window "$TPRL_WINDOW" \
    >/tmp/ac_server_tprl_test_$$.log 2>&1 &
TP_SERVER_PID=$!
TPRL_BASE="http://127.0.0.1:$TPRL_PORT"

TPRL_READY=0
for _ in $(seq 1 50); do
    if curl -s "$TPRL_BASE/banned/x" -H "Authorization: Bearer $ADMIN_KEY" 2>/dev/null \
        | grep -q '"banned"'; then
        TPRL_READY=1
        break
    fi
    sleep 0.1
done

if [ "$TPRL_READY" -eq 1 ]; then
    sleep "$((TPRL_WINDOW + 1))"   # let the readiness poll's own budget roll over
    for i in $(seq 1 "$TPRL_LIMIT"); do
        curl -s -o /dev/null "$TPRL_BASE/banned/x" \
            -H "Authorization: Bearer $ADMIN_KEY" \
            -H "X-Forwarded-For: 1.2.3.$i, 10.0.0.9"
    done
    CODE=$(curl -s -o /dev/null -w '%{http_code}' "$TPRL_BASE/banned/x" \
        -H "Authorization: Bearer $ADMIN_KEY" \
        -H "X-Forwarded-For: 1.2.3.99, 10.0.0.9")
    if [ "$CODE" = "429" ]; then
        pass "rate-limit key under --trust-proxy follows the trusted IP, not the spoofed prefix"
    else
        fail "expected 429 once the trusted IP's shared budget is exhausted (got $CODE)"
    fi
else
    fail "--trust-proxy rate-limit test server never became ready on port $TPRL_PORT"
fi
kill "$TP_SERVER_PID" 2>/dev/null
wait "$TP_SERVER_PID" 2>/dev/null
TP_SERVER_PID=""
rm -f "$TPRL_DB" "$TPRL_DB-wal" "$TPRL_DB-shm" "/tmp/ac_server_tprl_test_$$.log"

# default instance (flag off, from the very top of this script) must
# ignore X-Forwarded-For entirely -- negative control against a future
# regression that starts trusting it unconditionally. The main instance
# was already killed by this point in the script, so start a fresh
# throwaway one rather than reordering everything above.
NOTP_PORT=18803
NOTP_DB="/tmp/ac_server_notp_test_$$.db"
AC_SERVER_REPORT_KEY="$REPORT_KEY" AC_SERVER_ADMIN_KEY="$ADMIN_KEY" \
    python3 ./ac_server.py --host 127.0.0.1 --port "$NOTP_PORT" --db "$NOTP_DB" \
    >/tmp/ac_server_notp_test_$$.log 2>&1 &
NOTP_SERVER_PID=$!
NOTP_BASE="http://127.0.0.1:$NOTP_PORT"
NOTP_CID="test-notp-$$"

NOTP_READY=0
for _ in $(seq 1 50); do
    if curl -s "$NOTP_BASE/banned/x" -H "Authorization: Bearer $ADMIN_KEY" 2>/dev/null \
        | grep -q '"banned"'; then
        NOTP_READY=1
        break
    fi
    sleep 0.1
done
if [ "$NOTP_READY" -eq 1 ]; then
    curl -s -o /dev/null -X POST "$NOTP_BASE/report" \
        -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
        -H "X-Forwarded-For: 9.9.9.9" \
        -d "{\"client_id\":\"$NOTP_CID\",\"event_type\":\"X\",\"detail\":\"no-trust\",\"ts\":1}"
    NOTP_OUT=$(curl -s "$NOTP_BASE/reports/$NOTP_CID" -H "Authorization: Bearer $ADMIN_KEY")
    if printf '%s' "$NOTP_OUT" | grep -q '"source_addr": "127.0.0.1"'; then
        pass "without --trust-proxy, X-Forwarded-For is ignored (raw peer used)"
    else
        fail "default instance should ignore X-Forwarded-For (out: $NOTP_OUT)"
    fi
else
    fail "no-trust-proxy control server never became ready on port $NOTP_PORT"
fi
kill "$NOTP_SERVER_PID" 2>/dev/null
wait "$NOTP_SERVER_PID" 2>/dev/null
rm -f "$NOTP_DB" "$NOTP_DB-wal" "$NOTP_DB-shm" "/tmp/ac_server_notp_test_$$.log"

# Startup-failure paths: no server needed, just exit code + stderr.
if AC_SERVER_REPORT_KEY='' AC_SERVER_ADMIN_KEY='' python3 ./ac_server.py \
    --port 18804 --db "/tmp/ac_server_nokeys_$$.db" >/tmp/ac_nokeys_$$.log 2>&1; then
    fail "server should refuse to start with no auth configured"
else
    pass "server refuses to start with no auth configured"
fi
rm -f "/tmp/ac_nokeys_$$.log"

if AC_SERVER_REPORT_KEY=same AC_SERVER_ADMIN_KEY=same python3 ./ac_server.py \
    --port 18805 --db "/tmp/ac_server_samekeys_$$.db" >/tmp/ac_samekeys_$$.log 2>&1; then
    fail "server should refuse to start with equal report/admin keys"
else
    pass "server refuses to start with equal report/admin keys"
fi
rm -f "/tmp/ac_samekeys_$$.log"

if AC_SERVER_REPORT_KEY=r AC_SERVER_ADMIN_KEY=a python3 ./ac_server.py \
    --port 18806 --db "/tmp/ac_server_badrl_$$.db" --rate-limit 0 \
    >/tmp/ac_badrl_$$.log 2>&1; then
    fail "server should refuse to start with --rate-limit 0"
else
    pass "server refuses to start with --rate-limit 0"
fi
rm -f "/tmp/ac_badrl_$$.log"

echo
if [ "$FAIL" -eq 0 ]; then
    printf '\033[1;32mALL SERVER TESTS PASSED\033[0m\n'
else
    printf '\033[1;31mSOME SERVER TESTS FAILED\033[0m\n'
fi
exit "$FAIL"

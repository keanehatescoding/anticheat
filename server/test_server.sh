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
# cleanup is invoked via trap below; shellcheck cannot always see that
# shellcheck disable=SC2317,SC2329
cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    rm -f "$DB" "$DB-wal" "$DB-shm"
}
trap cleanup EXIT

AC_SERVER_REPORT_KEY="$REPORT_KEY" AC_SERVER_ADMIN_KEY="$ADMIN_KEY" \
    python3 ./ac_server.py --host 127.0.0.1 --port "$PORT" --db "$DB" \
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

# 5. banned lookup before any ban -> banned:false
OUT=$(curl -s "$BASE/banned/$CID" -H "Authorization: Bearer $ADMIN_KEY")
if printf '%s' "$OUT" | grep -q '"banned": false'; then
    pass "banned lookup false before any ban"
else
    fail "expected banned:false (got: $OUT)"
fi

# 6. banned lookup requires admin key, not report key -> 401
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/banned/$CID" \
    -H "Authorization: Bearer $REPORT_KEY")
if [ "$CODE" = "401" ]; then
    pass "report key rejected on /banned (tiers are separate)"
else
    fail "report key on /banned should be 401 (got $CODE)"
fi

# 7. reports listing shows the earlier report
OUT=$(curl -s "$BASE/reports/$CID" -H "Authorization: Bearer $ADMIN_KEY")
if printf '%s' "$OUT" | grep -q "syscall hook"; then
    pass "reports listing includes the earlier report"
else
    fail "expected 'syscall hook' in reports listing (got: $OUT)"
fi

# 8. ban, then confirm banned lookup flips to true
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

# 9. unban, confirm it flips back
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

rm -f "/tmp/ac_server_test_$$.log"

echo
if [ "$FAIL" -eq 0 ]; then
    printf '\033[1;32mALL SERVER TESTS PASSED\033[0m\n'
else
    printf '\033[1;31mSOME SERVER TESTS FAILED\033[0m\n'
fi
exit "$FAIL"

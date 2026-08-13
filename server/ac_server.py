#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
ac_server.py -- minimal report-ingestion + ban-lookup server for the
hypranticheat daemon's ban pipeline.

Two things this deliberately is NOT:

  - An enforcement point. This project has no game or matchmaking server
    to integrate with, so there is nothing here that kicks or blocks a
    player. GET /banned/<client_id> is the API a real game server would
    call before letting someone connect; calling it is left to that
    (nonexistent, in this project) system.

  - An auto-ban system. A report is a client-side daemon's unverified
    claim about itself -- and the daemon runs on the exact machine a
    cheat author controls, so a report can be wrong, spoofed, or replayed
    by an attacker probing for false positives. Reports only accumulate;
    a human decides whether to actually ban via POST /ban after reviewing
    GET /reports/<client_id>. Auto-banning on unverified client input
    would turn a bug or a spoofed report into a banned real player, which
    is a worse failure mode than a slower human-in-the-loop pipeline.

Storage is a single SQLite file (zero extra services to run). Auth is two
static bearer tokens: a report key (used by daemon instances, via
AC_REPORT_KEY) and an admin key (used by whoever reviews/bans/queries).
There is no built-in TLS -- run this behind a reverse proxy for anything
reachable over an untrusted network, or keep it LAN/localhost-only, which
is the deployment this was actually built and tested against.
"""
import argparse
import hmac
import http.server
import json
import re
import sqlite3
import sys
import threading
import time

CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
MAX_BODY_BYTES = 4096


class RateLimiter:
    """Fixed-window limiter: at most `limit` requests per `window` seconds,
    per key (source IP here). Not built for distributed scale or precise
    edge behavior (a fixed window allows a brief double-rate burst right
    at the boundary) -- enough to bound abuse against a single small
    process, which is the actual deployment this is for. Applied to every
    endpoint, not just /report: unauthenticated attempts against /banned
    or /ban are exactly the kind of thing worth throttling too (ID
    enumeration, admin-key brute-forcing), not just report flooding."""

    def __init__(self, limit, window):
        self.limit = limit
        self.window = window
        self._lock = threading.Lock()
        self._buckets = {}  # key -> (window_start, count)

    def allow(self, key):
        now = time.time()
        with self._lock:
            window_start, count = self._buckets.get(key, (now, 0))
            if now - window_start >= self.window:
                window_start, count = now, 0
            count += 1
            self._buckets[key] = (window_start, count)
            return count <= self.limit


def now_ts():
    return int(time.time())


class Store:
    """One SQLite connection per request (see handler) -- simplest way to
    be correct under ThreadingHTTPServer without sharing a connection
    across threads."""

    def __init__(self, db_path):
        self.db_path = db_path
        conn = self._connect()
        conn.execute(
            """CREATE TABLE IF NOT EXISTS reports (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   client_id TEXT NOT NULL,
                   event_type TEXT NOT NULL,
                   detail TEXT NOT NULL,
                   client_ts INTEGER,
                   received_at INTEGER NOT NULL,
                   source_addr TEXT NOT NULL
               )"""
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reports_client ON reports(client_id)"
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS bans (
                   client_id TEXT PRIMARY KEY,
                   reason TEXT NOT NULL,
                   banned_at INTEGER NOT NULL
               )"""
        )
        conn.commit()
        conn.close()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def add_report(self, client_id, event_type, detail, client_ts, source_addr):
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO reports (client_id, event_type, detail, "
                "client_ts, received_at, source_addr) VALUES (?,?,?,?,?,?)",
                (client_id, event_type, detail, client_ts, now_ts(), source_addr),
            )
            conn.commit()
        finally:
            conn.close()

    def list_reports(self, client_id, limit=200):
        conn = self._connect()
        try:
            cur = conn.execute(
                "SELECT event_type, detail, client_ts, received_at, source_addr "
                "FROM reports WHERE client_id = ? ORDER BY id DESC LIMIT ?",
                (client_id, limit),
            )
            return [
                {
                    "event_type": r[0],
                    "detail": r[1],
                    "client_ts": r[2],
                    "received_at": r[3],
                    "source_addr": r[4],
                }
                for r in cur.fetchall()
            ]
        finally:
            conn.close()

    def ban(self, client_id, reason):
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO bans (client_id, reason, banned_at) VALUES (?,?,?) "
                "ON CONFLICT(client_id) DO UPDATE SET reason=excluded.reason, "
                "banned_at=excluded.banned_at",
                (client_id, reason, now_ts()),
            )
            conn.commit()
        finally:
            conn.close()

    def unban(self, client_id):
        conn = self._connect()
        try:
            cur = conn.execute("DELETE FROM bans WHERE client_id = ?", (client_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def ban_status(self, client_id):
        conn = self._connect()
        try:
            cur = conn.execute(
                "SELECT reason, banned_at FROM bans WHERE client_id = ?",
                (client_id,),
            )
            row = cur.fetchone()
            if not row:
                return {"banned": False}
            return {"banned": True, "reason": row[0], "banned_at": row[1]}
        finally:
            conn.close()


def make_handler(store, report_key, admin_key, rate_limiter):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "ac_server/1"

        def log_message(self, fmt, *args):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

        def _send_json(self, code, obj, extra_headers=None):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _rate_limited(self):
            if rate_limiter.allow(self.client_address[0]):
                return False
            self._send_json(
                429,
                {"error": "rate limited"},
                {"Retry-After": str(rate_limiter.window)},
            )
            return True

        def _bearer(self):
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return None
            return auth[len("Bearer "):]

        def _authed(self, expected):
            got = self._bearer()
            # hmac.compare_digest is constant-time; a naive == here would
            # leak key-prefix-match timing to anyone who can hit this
            # endpoint repeatedly.
            return got is not None and hmac.compare_digest(got, expected)

        def _read_json_body(self):
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0 or length > MAX_BODY_BYTES:
                return None
            raw = self.rfile.read(length)
            try:
                return json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return None

        @staticmethod
        def _valid_client_id(v):
            return isinstance(v, str) and CLIENT_ID_RE.match(v) is not None

        def do_POST(self):
            if self._rate_limited():
                return
            if self.path == "/report":
                return self._handle_report()
            if self.path == "/ban":
                return self._handle_ban()
            if self.path == "/unban":
                return self._handle_unban()
            self._send_json(404, {"error": "not found"})

        def do_GET(self):
            if self._rate_limited():
                return
            if self.path.startswith("/banned/"):
                return self._handle_banned(self.path[len("/banned/"):])
            if self.path.startswith("/reports/"):
                return self._handle_reports(self.path[len("/reports/"):])
            self._send_json(404, {"error": "not found"})

        def _handle_report(self):
            if not self._authed(report_key):
                return self._send_json(401, {"error": "unauthorized"})
            body = self._read_json_body()
            if not body:
                return self._send_json(400, {"error": "bad request"})
            client_id = body.get("client_id")
            event_type = body.get("event_type")
            detail = body.get("detail")
            client_ts = body.get("ts")
            if not self._valid_client_id(client_id):
                return self._send_json(400, {"error": "invalid client_id"})
            if not isinstance(event_type, str) or len(event_type) > 64:
                return self._send_json(400, {"error": "invalid event_type"})
            if not isinstance(detail, str) or len(detail) > 2000:
                return self._send_json(400, {"error": "invalid detail"})
            if not isinstance(client_ts, (int, float)):
                client_ts = None
            store.add_report(
                client_id, event_type, detail, client_ts, self.client_address[0]
            )
            self._send_json(201, {"ok": True})

        def _handle_ban(self):
            if not self._authed(admin_key):
                return self._send_json(401, {"error": "unauthorized"})
            body = self._read_json_body()
            if not body:
                return self._send_json(400, {"error": "bad request"})
            client_id = body.get("client_id")
            reason = body.get("reason")
            if not self._valid_client_id(client_id):
                return self._send_json(400, {"error": "invalid client_id"})
            if not isinstance(reason, str) or not (0 < len(reason) <= 500):
                return self._send_json(400, {"error": "invalid reason"})
            store.ban(client_id, reason)
            self._send_json(200, {"ok": True})

        def _handle_unban(self):
            if not self._authed(admin_key):
                return self._send_json(401, {"error": "unauthorized"})
            body = self._read_json_body()
            if not body:
                return self._send_json(400, {"error": "bad request"})
            client_id = body.get("client_id")
            if not self._valid_client_id(client_id):
                return self._send_json(400, {"error": "invalid client_id"})
            existed = store.unban(client_id)
            self._send_json(200, {"ok": True, "was_banned": existed})

        def _handle_banned(self, client_id):
            if not self._authed(admin_key):
                return self._send_json(401, {"error": "unauthorized"})
            if not self._valid_client_id(client_id):
                return self._send_json(400, {"error": "invalid client_id"})
            self._send_json(200, store.ban_status(client_id))

        def _handle_reports(self, client_id):
            if not self._authed(admin_key):
                return self._send_json(401, {"error": "unauthorized"})
            if not self._valid_client_id(client_id):
                return self._send_json(400, {"error": "invalid client_id"})
            self._send_json(200, {"reports": store.list_reports(client_id)})

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--db", default="ac_server.db")
    ap.add_argument(
        "--report-key",
        default=None,
        help="bearer token daemons use for POST /report "
        "(default: $AC_SERVER_REPORT_KEY)",
    )
    ap.add_argument(
        "--admin-key",
        default=None,
        help="bearer token for ban/unban/query endpoints "
        "(default: $AC_SERVER_ADMIN_KEY)",
    )
    ap.add_argument(
        "--rate-limit",
        type=int,
        default=60,
        help="max requests per --rate-window seconds, per source IP, "
        "across every endpoint (default: 60)",
    )
    ap.add_argument(
        "--rate-window",
        type=int,
        default=60,
        help="rate-limit window in seconds (default: 60)",
    )
    args = ap.parse_args()

    import os

    report_key = args.report_key or os.environ.get("AC_SERVER_REPORT_KEY")
    admin_key = args.admin_key or os.environ.get("AC_SERVER_ADMIN_KEY")
    if not report_key or not admin_key:
        sys.stderr.write(
            "ac_server: --report-key/--admin-key (or AC_SERVER_REPORT_KEY/"
            "AC_SERVER_ADMIN_KEY) are required -- refusing to start with no "
            "auth configured\n"
        )
        sys.exit(1)
    if report_key == admin_key:
        sys.stderr.write("ac_server: report-key and admin-key must differ\n")
        sys.exit(1)

    if args.rate_limit <= 0 or args.rate_window <= 0:
        sys.stderr.write("ac_server: --rate-limit/--rate-window must be positive\n")
        sys.exit(1)

    store = Store(args.db)
    rate_limiter = RateLimiter(args.rate_limit, args.rate_window)
    handler = make_handler(store, report_key, admin_key, rate_limiter)
    httpd = http.server.ThreadingHTTPServer((args.host, args.port), handler)
    sys.stderr.write(
        "ac_server: listening on %s:%d, db=%s, rate limit %d req/%ds per IP "
        "(plain HTTP -- put a TLS reverse proxy in front for anything "
        "beyond localhost/LAN)\n"
        % (args.host, args.port, args.db, args.rate_limit, args.rate_window)
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

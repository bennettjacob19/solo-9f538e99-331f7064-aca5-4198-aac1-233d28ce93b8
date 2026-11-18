"""Shared configuration and the SQLite state plane.

Three processes (web console / resolver / authoritative endpoint) share one
SQLite database in WAL mode:

  control   -- desired behaviour of the authoritative endpoint, written by the
               web console, read by the authoritative endpoint per query.
  cache     -- the resolver's cache.  Absolute epoch deadlines are stored, so a
               resolver restart can never extend the validity of an old A
               record; the stale window simply keeps counting down.
  query_log -- every client query the resolver answered, with its source.
  auth_log  -- every query the authoritative endpoint saw, with the action it
               took (answered / nxdomain / dropped / delayed).
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time

# --------------------------------------------------------------------------
# Configuration (environment overridable; defaults are the spec values).
# --------------------------------------------------------------------------
FIXED_DOMAIN = os.environ.get("FIXED_DOMAIN", "service.example").strip().rstrip(".")
FQDN = FIXED_DOMAIN + "."

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")

FRESH_TTL = float(os.environ.get("FRESH_TTL", "5"))        # successful answers are fresh for 5s
STALE_WINDOW = float(os.environ.get("STALE_WINDOW", "20"))  # stale A usable <=20s after expiry
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "2.0"))

AUTH_HOST = os.environ.get("AUTH_HOST", "127.0.0.1")
AUTH_PORT = int(os.environ.get("AUTH_PORT", "5354"))
RESOLVER_HOST = os.environ.get("RESOLVER_HOST", "127.0.0.1")
RESOLVER_PORT = int(os.environ.get("RESOLVER_PORT", "5353"))
WEB_PORT = int(os.environ.get("WEB_PORT", "8000"))

DEFAULT_IP = os.environ.get("DEFAULT_IP", "192.0.2.10")
DEFAULT_DELAY = float(os.environ.get("DEFAULT_DELAY", "3.0"))

# Shared HMAC-SHA256 secret for authenticating upstream answers.  It is a
# deployment secret and must never be exposed by the web console.  Set
# DNS_HMAC_KEY explicitly, or let it be generated once into HMAC_KEY_FILE on
# the shared volume (so every process and every restart uses the same key).
HMAC_KEY = os.environ.get("DNS_HMAC_KEY", "").encode()
HMAC_KEY_ID = os.environ.get("DNS_HMAC_KEY_ID", "k1")
HMAC_KEY_FILE = os.environ.get(
    "HMAC_KEY_FILE",
    os.path.join(os.path.dirname(DB_PATH) or ".", "hmac.key"),
)
_HMAC_CACHE: bytes | None = None
_HMAC_LOCK = threading.Lock()


def hmac_secret() -> bytes:
    """The shared HMAC key, identical for every process and every restart."""
    global _HMAC_CACHE
    if HMAC_KEY:
        return HMAC_KEY
    if _HMAC_CACHE is not None:
        return _HMAC_CACHE
    with _HMAC_LOCK:
        if _HMAC_CACHE is not None:
            return _HMAC_CACHE
        directory = os.path.dirname(HMAC_KEY_FILE)
        if directory:
            os.makedirs(directory, exist_ok=True)
        # Generate into a temp file and publish it with an atomic link, so a
        # concurrent process never reads a half-written key.
        tmp = f"{HMAC_KEY_FILE}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, os.urandom(32))
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(tmp, HMAC_KEY_FILE)
        except FileExistsError:
            pass  # another process won the race: use its key
        except OSError:
            # Filesystems without hard links: only create if still absent.
            try:
                with open(tmp, "rb") as src, open(HMAC_KEY_FILE, "xb") as dst:
                    dst.write(src.read())
            except FileExistsError:
                pass
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
        with open(HMAC_KEY_FILE, "rb") as fh:
            key = fh.read()
        if len(key) < 16:
            raise RuntimeError(f"HMAC key file {HMAC_KEY_FILE} is too short")
        _HMAC_CACHE = key
        return key


def hmac_key_fingerprint() -> str:
    """Public identifier for the key (safe to display), never the key itself."""
    return hashlib.sha256(hmac_secret()).hexdigest()[:16]


SCHEMA = """
CREATE TABLE IF NOT EXISTS control (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  mode TEXT NOT NULL,              -- a | nxdomain | delay | timeout
  ip TEXT NOT NULL,
  delay_seconds REAL NOT NULL,
  auth_state TEXT NOT NULL DEFAULT 'ok',  -- ok | badsig | noauth (answer signing)
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS cache (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  qname TEXT NOT NULL,
  rcode TEXT NOT NULL,             -- NOERROR | NXDOMAIN
  a_record TEXT,                   -- NULL once NXDOMAIN is confirmed (old A purged)
  fetched_at REAL NOT NULL,        -- last successful upstream answer (epoch)
  fresh_until REAL NOT NULL,       -- serve-fresh deadline (epoch)
  stale_until REAL,                -- A only: last moment a stale A may be served
  nx_confirmed_at REAL
);
CREATE TABLE IF NOT EXISTS query_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, source TEXT, rcode TEXT, answers TEXT, detail TEXT,
  auth TEXT                       -- answer-auth outcome: ok / missing / ...
);
CREATE TABLE IF NOT EXISTS auth_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, mode TEXT, action TEXT, detail TEXT
);
"""

_LOG_TABLES = ("query_log", "auth_log")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    # Switching the journal mode briefly needs an exclusive lock; when several
    # processes start together SQLite can report it busy immediately, so retry.
    for attempt in range(20):
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            break
        except sqlite3.OperationalError:
            if attempt == 19:
                conn.close()
                raise
            time.sleep(0.2)
    return conn


def _migrate(c: sqlite3.Connection) -> None:
    """Add columns introduced after an older database was created."""
    cols = {r["name"] for r in c.execute("PRAGMA table_info(control)")}
    if "auth_state" not in cols:
        c.execute("ALTER TABLE control ADD COLUMN auth_state TEXT NOT NULL"
                  " DEFAULT 'ok'")
    qcols = {r["name"] for r in c.execute("PRAGMA table_info(query_log)")}
    if "auth" not in qcols:
        c.execute("ALTER TABLE query_log ADD COLUMN auth TEXT")


def init_db() -> None:
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with _connect() as c:
        c.executescript(SCHEMA)
        _migrate(c)
        c.execute(
            "INSERT OR IGNORE INTO control"
            "(id, mode, ip, delay_seconds, auth_state, updated_at)"
            " VALUES (1, 'a', ?, ?, 'ok', ?)",
            (DEFAULT_IP, DEFAULT_DELAY, time.time()),
        )


# --------------------------------------------------------------------------
# control table (web writes, authoritative endpoint reads)
# --------------------------------------------------------------------------
def get_control() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM control WHERE id = 1").fetchone()
        return dict(row) if row else None


def set_control(mode: str, ip: str, delay_seconds: float,
                auth_state: str = "ok") -> None:
    with _connect() as c:
        c.execute(
            "UPDATE control SET mode = ?, ip = ?, delay_seconds = ?,"
            " auth_state = ?, updated_at = ? WHERE id = 1",
            (mode, ip, float(delay_seconds), auth_state, time.time()),
        )


# --------------------------------------------------------------------------
# cache table (resolver only)
# --------------------------------------------------------------------------
def get_cache() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM cache WHERE id = 1").fetchone()
        return dict(row) if row else None


def put_cache_a(ip: str, now: float) -> None:
    """Store a freshly fetched A record: fresh for FRESH_TTL, then stale-usable
    for STALE_WINDOW more seconds.  Absolute epochs are persisted, so a restart
    does not extend either deadline."""
    with _connect() as c:
        c.execute(
            "INSERT INTO cache(id, qname, rcode, a_record, fetched_at, fresh_until,"
            "                 stale_until, nx_confirmed_at)"
            " VALUES (1, ?, 'NOERROR', ?, ?, ?, ?, NULL)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   qname = excluded.qname, rcode = 'NOERROR',"
            "   a_record = excluded.a_record, fetched_at = excluded.fetched_at,"
            "   fresh_until = excluded.fresh_until, stale_until = excluded.stale_until,"
            "   nx_confirmed_at = NULL",
            (FQDN, ip, now, now + FRESH_TTL, now + FRESH_TTL + STALE_WINDOW),
        )


def put_cache_nxdomain(now: float) -> None:
    """Confirm NXDOMAIN.  Any old A record is purged immediately and durably:
    from this moment no answer may contain the old A again, and NXDOMAIN itself
    is only cached fresh (never used as stale backup)."""
    with _connect() as c:
        c.execute(
            "INSERT INTO cache(id, qname, rcode, a_record, fetched_at, fresh_until,"
            "                 stale_until, nx_confirmed_at)"
            " VALUES (1, ?, 'NXDOMAIN', NULL, ?, ?, NULL, ?)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   qname = excluded.qname, rcode = 'NXDOMAIN', a_record = NULL,"
            "   fetched_at = excluded.fetched_at, fresh_until = excluded.fresh_until,"
            "   stale_until = NULL, nx_confirmed_at = excluded.nx_confirmed_at",
            (FQDN, now, now + FRESH_TTL, now),
        )


# --------------------------------------------------------------------------
# logs
# --------------------------------------------------------------------------
def _log(table: str, columns: tuple[str, ...], values: tuple) -> None:
    assert table in _LOG_TABLES
    cols = ", ".join(columns)
    marks = ", ".join("?" for _ in columns)
    with _connect() as c:
        c.execute(f"INSERT INTO {table}({cols}) VALUES ({marks})", values)
        c.execute(
            f"DELETE FROM {table} WHERE id NOT IN"
            f" (SELECT id FROM {table} ORDER BY id DESC LIMIT 300)"
        )


def log_query(qname, qtype, source, rcode, answers, detail, auth=None) -> None:
    _log(
        "query_log",
        ("ts", "qname", "qtype", "source", "rcode", "answers", "detail", "auth"),
        (time.time(), qname, qtype, source, rcode, answers, detail, auth),
    )


def log_auth(qname, qtype, mode, action, detail) -> None:
    _log(
        "auth_log",
        ("ts", "qname", "qtype", "mode", "action", "detail"),
        (time.time(), qname, qtype, mode, action, detail),
    )


def recent(table: str, limit: int = 15) -> list[dict]:
    assert table in _LOG_TABLES
    with _connect() as c:
        rows = c.execute(
            f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

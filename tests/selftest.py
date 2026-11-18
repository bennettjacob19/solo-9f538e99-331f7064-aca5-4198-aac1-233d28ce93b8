#!/usr/bin/env python3
"""End-to-end self-test for the serve-stale DNS duty system.

Spawns auth + resolver + web on loopback with the production timing
parameters (fresh TTL 5s, stale window 20s, upstream timeout 2s) and drives
the key interleavings:

  A. basic fetch / fresh-cache hit / TTL countdown / refresh after expiry
  B. upstream timeout after expiry -> stale A (<=20s) -> SERVFAIL beyond
  C. confirmed NXDOMAIN purges the old A; NXDOMAIN is never served stale
  D. a late (delayed) old answer cannot resurrect anything
  E. resolver restart does not extend the old A's validity
  F. web console smoke test (page, mode switch, query, state)
  G. HMAC answer authentication: bad signature / missing signature are
     treated as upstream unavailable (no cache poisoning, no purge);
     authenticated A refreshes, authenticated NXDOMAIN purges
  H. replay / tamper / unsigned answers from a rogue upstream: rejected,
     while a correctly signed rogue answer is accepted (positive control)
  I. the shared key is persisted (same key across processes/restarts)

Exits non-zero if any check fails.  Runtime: ~95s.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dnslib import QTYPE, DNSRecord  # noqa: E402

DOMAIN = "service.example"
AUTH_PORT, RES_PORT, WEB_PORT = 15354, 15353, 18000
TMP = tempfile.mkdtemp(prefix="dns-selftest-")
DB = os.path.join(TMP, "app.db")

env = dict(os.environ)
DNS_HMAC_KEY = "selftest-shared-hmac-key-0123456789abcdef"
HMAC_KEY = DNS_HMAC_KEY
env.update(
    DB_PATH=DB,
    DNS_HMAC_KEY=HMAC_KEY,
    DNS_HMAC_KEY_ID="k1",
    FIXED_DOMAIN=DOMAIN,
    AUTH_HOST="127.0.0.1",
    AUTH_PORT=str(AUTH_PORT),
    RESOLVER_HOST="127.0.0.1",
    RESOLVER_PORT=str(RES_PORT),
    WEB_PORT=str(WEB_PORT),
    FRESH_TTL="5",
    STALE_WINDOW="20",
    UPSTREAM_TIMEOUT="2",
    DEFAULT_IP="192.0.2.10",
    DEFAULT_DELAY="3",
    PYTHONPATH=ROOT,
    PYTHONUNBUFFERED="1",
)

procs: dict[str, subprocess.Popen] = {}
FAILS: list[str] = []


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def start(name: str, module: str, extra_env: dict | None = None) -> None:
    log = open(os.path.join(TMP, f"{name}.log"), "ab")
    run_env = dict(env)
    for k, v in (extra_env or {}).items():
        if v is None:
            run_env.pop(k, None)   # explicit deletion (e.g. drop DNS_HMAC_KEY)
        else:
            run_env[k] = v
    procs[name] = subprocess.Popen(
        [sys.executable, "-m", module],
        cwd=ROOT, env=run_env, stdout=log, stderr=subprocess.STDOUT,
    )


def start_cmd(name: str, argv: list[str], extra_env: dict | None = None) -> None:
    log = open(os.path.join(TMP, f"{name}.log"), "ab")
    run_env = dict(env)
    for k, v in (extra_env or {}).items():
        if v is None:
            run_env.pop(k, None)
        else:
            run_env[k] = v
    procs[name] = subprocess.Popen(
        argv, cwd=ROOT, env=run_env, stdout=log, stderr=subprocess.STDOUT,
    )


def stop(name: str) -> None:
    p = procs.get(name)
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


def set_mode(mode: str, ip: str = "192.0.2.10", delay: float = 3.0,
             auth_state: str = "ok", db: str | None = None) -> None:
    conn = sqlite3.connect(db or DB, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute(
        "INSERT INTO control(id, mode, ip, delay_seconds, auth_state, updated_at)"
        " VALUES (1, ?, ?, ?, ?, ?)"
        " ON CONFLICT(id) DO UPDATE SET mode=excluded.mode, ip=excluded.ip,"
        " delay_seconds=excluded.delay_seconds, auth_state=excluded.auth_state,"
        " updated_at=excluded.updated_at",
        (mode, ip, delay, auth_state, time.time()),
    )
    conn.commit()
    conn.close()


def get_cache() -> dict | None:
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM cache WHERE id = 1").fetchone()
    conn.close()
    return dict(row) if row else None


def auth_actions() -> list[tuple]:
    conn = sqlite3.connect(DB, timeout=15)
    rows = conn.execute(
        "SELECT mode, action, detail FROM auth_log ORDER BY id"
    ).fetchall()
    conn.close()
    return rows


def clear_cache(db: str | None = None) -> None:
    conn = sqlite3.connect(db or DB, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("DELETE FROM cache WHERE id = 1")
    conn.commit()
    conn.close()


def get_cache_from(db: str) -> dict | None:
    conn = sqlite3.connect(db, timeout=15)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM cache WHERE id = 1").fetchone()
    conn.close()
    return dict(row) if row else None


def dns_query(port: int | None = None) -> tuple[int, list[tuple], str | None, str]:
    """Returns (rcode, [(type, data, ttl)], source, auth)."""
    q = DNSRecord.question(DOMAIN, "A")
    data = q.send("127.0.0.1", port or RES_PORT, timeout=8)
    rep = DNSRecord.parse(data)
    answers = [(QTYPE[rr.rtype], str(rr.rdata), rr.ttl) for rr in rep.rr]
    src = auth = None
    for rr in rep.ar:
        if rr.rtype == QTYPE.TXT:
            txt = str(rr.rdata).strip('"')
            if txt.startswith("source="):
                src = txt.split("=", 1)[1].split()[0]
            if "auth=" in txt:
                auth = txt.split("auth=", 1)[1].split()[0]
    return rep.header.rcode, answers, src, auth


def check(name: str, cond: bool, info: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {info}", flush=True)
    if not cond:
        FAILS.append(name)


def sleep_until(ts: float) -> None:
    time.sleep(max(0.0, ts - time.time()))


def wait_resolver_ready(timeout: float = 25) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            dns_query()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def wait_web_ready(timeout: float = 25) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{WEB_PORT}/api/state", timeout=2
            ) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


# --------------------------------------------------------------------------
# scenario
# --------------------------------------------------------------------------
def main() -> int:
    print(f"[selftest] workdir={TMP}", flush=True)
    start("auth", "app.auth_server")
    start("resolver", "app.resolver")
    start("web", "app.web")
    try:
        if not (wait_resolver_ready() and wait_web_ready()):
            print("  [FAIL] services did not come up")
            return 1

        # -- A. basic fetch / fresh cache / refresh --------------------------
        print("A. 基本应答与新鲜缓存", flush=True)
        clear_cache()  # the readiness probe already populated the cache
        set_mode("a", "192.0.2.10")
        rc, ans, src, auth = dns_query()
        check("A1 上游取回 A 且认证通过", rc == 0 and ans == [("A", "192.0.2.10", 5)]
              and src == "upstream" and auth == "ok",
              f"rcode={rc} ans={ans} src={src} auth={auth}")
        rc, ans, src, auth = dns_query()
        check("A2 命中新鲜缓存", rc == 0 and src == "cache-fresh"
              and ans and ans[0][1] == "192.0.2.10" and 1 <= ans[0][2] <= 5,
              f"ans={ans} src={src}")
        check("A2b 缓存应答不带上游认证字段", auth is None, f"auth={auth}")
        set_mode("a", "192.0.2.20")  # change the A record on the auth side
        rc, ans, src, auth = dns_query()
        check("A3 缓存期内仍给旧 IP", rc == 0 and src == "cache-fresh"
              and ans and ans[0][1] == "192.0.2.10", f"ans={ans} src={src}")
        time.sleep(5.5)
        rc, ans, src, auth = dns_query()
        check("A4 过期后重新取回新 IP", rc == 0 and src == "upstream"
              and ans == [("A", "192.0.2.20", 5)], f"ans={ans} src={src}")
        cache = get_cache()
        fresh_until, stale_until = cache["fresh_until"], cache["stale_until"]

        # -- B. stale on timeout, SERVFAIL beyond the window -----------------
        print("B. 过期+上游超时 -> 旧 A 沿用 <=20s -> SERVFAIL", flush=True)
        set_mode("timeout")
        sleep_until(fresh_until + 0.5)
        t0 = time.time()
        rc, ans, src, auth = dns_query()
        check("B1 上游超时后给旧 A(stale)",
              rc == 0 and src == "cache-stale" and ans
              and ans[0][1] == "192.0.2.20"
              and stale_until - time.time() - 1 <= ans[0][2] <= 20,
              f"ans={ans} src={src} 耗时={time.time()-t0:.1f}s")
        sleep_until(stale_until - 4)
        rc, ans, src, auth = dns_query()
        check("B2 窗口末尾仍是 stale", rc == 0 and src == "cache-stale",
              f"ans={ans} src={src}")
        sleep_until(stale_until + 1)
        rc, ans, src, auth = dns_query()
        check("B3 超过 20s 返回 SERVFAIL", rc == 2 and not ans and src == "none",
              f"rcode={rc} ans={ans} src={src}")

        # -- C. NXDOMAIN purges old A; NXDOMAIN never served stale -----------
        print("C. 确认 NXDOMAIN 清除旧 A；NXDOMAIN 不作过期备用", flush=True)
        set_mode("a", "192.0.2.30")
        rc, ans, src, auth = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        set_mode("nxdomain")
        time.sleep(5.5)  # let the fresh A expire
        rc, ans, src, auth = dns_query()
        check("C1 上游确认 NXDOMAIN", rc == 3 and not ans and src == "upstream",
              f"rcode={rc} ans={ans} src={src}")
        cache = get_cache()
        check("C2 旧 A 已被持久清除",
              cache["rcode"] == "NXDOMAIN" and cache["a_record"] is None
              and cache["stale_until"] is None,
              f"cache={cache}")
        set_mode("timeout")
        time.sleep(5.5)  # let the fresh NXDOMAIN expire
        rc, ans, src, auth = dns_query()
        check("C3 NXDOMAIN 不作 stale 备用 -> SERVFAIL",
              rc == 2 and not ans and src == "none",
              f"rcode={rc} ans={ans} src={src}")

        # -- D. late old answer cannot resurrect -----------------------------
        print("D. 超时后迟到的旧答复不能复活记录", flush=True)
        set_mode("a", "192.0.2.40")
        rc, ans, src, auth = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        set_mode("delay", "192.0.2.40", 3.0)  # 3s delay > 2s upstream timeout
        time.sleep(5.5)  # fresh A expires
        t0 = time.time()
        rc, ans, src, auth = dns_query()  # upstream times out at 2s; delayed A lands ~1s later
        check("D1 延迟模式下先按超时处理 -> stale",
              rc == 0 and src == "cache-stale" and 1.8 <= time.time() - t0 <= 4,
              f"ans={ans} src={src} 耗时={time.time()-t0:.1f}s")
        time.sleep(1.5)  # the delayed A has now arrived at a closed socket
        set_mode("nxdomain")
        rc, ans, src, auth = dns_query()
        check("D2 随后确认 NXDOMAIN", rc == 3 and src == "upstream",
              f"rcode={rc} src={src}")
        set_mode("timeout")
        time.sleep(5.5)  # past NXDOMAIN freshness; delayed A long arrived
        rc, ans, src, auth = dns_query()
        check("D3 迟到旧 A 未复活任何记录 -> SERVFAIL",
              rc == 2 and not ans, f"rcode={rc} ans={ans} src={src}")
        cache = get_cache()
        check("D4 缓存中仍无 A 记录", cache["a_record"] is None,
              f"cache={cache}")
        delayed = [r for r in auth_actions() if r[0] == "delay" and r[1] == "answered"]
        check("D5 权威端确实发出过延迟应答（被解析器丢弃）", len(delayed) >= 1,
              f"delay 应答次数={len(delayed)}")

        # -- E. restart does not extend validity -----------------------------
        print("E. 重启不延长旧 A 有效期", flush=True)
        set_mode("a", "192.0.2.50")
        rc, ans, src, auth = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        stale_until = get_cache()["stale_until"]
        time.sleep(4)
        stop("resolver")
        time.sleep(1)
        start("resolver", "app.resolver")  # restart with the same DB
        set_mode("timeout")
        assert wait_resolver_ready(), "resolver did not come back"
        sleep_until(stale_until - 4)
        rc, ans, src, auth = dns_query()
        check("E1 重启后窗口内仍可用旧 A(绝对期限未变)",
              rc == 0 and src == "cache-stale" and ans
              and ans[0][1] == "192.0.2.50", f"ans={ans} src={src}")
        sleep_until(stale_until + 2)
        rc, ans, src, auth = dns_query()
        check("E2 到达原绝对期限即 SERVFAIL（未被重启延长）",
              rc == 2 and not ans, f"rcode={rc} ans={ans} src={src}")

        # -- F. web console smoke test ---------------------------------------
        print("F. 网页控制台冒烟", flush=True)
        with urllib.request.urlopen(f"http://127.0.0.1:{WEB_PORT}/", timeout=5) as r:
            body = r.read().decode()
        check("F1 主页可访问且含认证开关",
              r.status == 200 and "DNS" in body and "正确签名" in body
              and "应答认证" in body)
        req = urllib.request.Request(
            f"http://127.0.0.1:{WEB_PORT}/api/mode",
            data=json.dumps({"mode": "a", "ip": "192.0.2.60"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            ok = json.load(r)["ok"]
        check("F2 网页切换模式生效", ok and get_control_mode() == "a")
        req = urllib.request.Request(f"http://127.0.0.1:{WEB_PORT}/api/query",
                                     method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            res = json.load(r)
        check("F3 网页发起真实查询并显示来源与认证结果",
              res["ok"] and res["rcode"] == "NOERROR"
              and res["source"] in ("upstream", "cache-fresh")
              and res["answers"] and res["answers"][0]["data"] == "192.0.2.60"
              and res.get("auth") in ("ok", ""),
              f"res={res.get('rcode')} src={res.get('source')} "
              f"auth={res.get('auth')}")
        with urllib.request.urlopen(
                f"http://127.0.0.1:{WEB_PORT}/api/state", timeout=5) as r:
            st = json.load(r)
        check("F4 状态接口含控制/缓存/日志/密钥指纹",
              st["control"]["mode"] == "a" and st["cache"]
              and len(st["resolver_log"]) > 0 and len(st["auth_log"]) > 0
              and st["auth"]["key_id"] == "k1"
              and len(st["auth"]["fingerprint"]) == 16
              and DNS_HMAC_KEY not in json.dumps(st),
              f"auth={st.get('auth')}")
        check("F4b 解析器日志带认证结果字段",
              any(r.get("auth") == "ok" for r in st["resolver_log"]),
              f"auths={[r.get('auth') for r in st['resolver_log'][:5]]}")
        req = urllib.request.Request(
            f"http://127.0.0.1:{WEB_PORT}/api/mode",
            data=json.dumps({"mode": "bogus"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
            check("F5 非法模式被拒绝", False)
        except urllib.error.HTTPError as e:
            check("F5 非法模式被拒绝", e.code == 400)
        req = urllib.request.Request(
            f"http://127.0.0.1:{WEB_PORT}/api/mode",
            data=json.dumps({"mode": "a", "auth_state": "badsig"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            ok = json.load(r)["ok"]
        check("F6 网页可切换到错误签名",
              ok and get_control()["auth_state"] == "badsig")
        req = urllib.request.Request(
            f"http://127.0.0.1:{WEB_PORT}/api/mode",
            data=json.dumps({"mode": "a", "auth_state": "bogus"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
            check("F7 非法签名状态被拒绝", False)
        except urllib.error.HTTPError as e:
            check("F7 非法签名状态被拒绝", e.code == 400)

        scenario_j()
        scenario_g()
        scenario_h()
        scenario_i()
    finally:
        for name in list(procs):
            stop(name)
        print(f"[selftest] logs in {TMP}", flush=True)

    print(f"\n{'=' * 60}\n结果: {len(FAILS)} 项失败" if FAILS
          else f"\n{'=' * 60}\n结果: 全部通过", flush=True)
    return 1 if FAILS else 0


def get_control_mode() -> str:
    conn = sqlite3.connect(DB, timeout=15)
    mode = conn.execute("SELECT mode FROM control WHERE id = 1").fetchone()[0]
    conn.close()
    return mode


def get_control() -> dict:
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM control WHERE id = 1").fetchone()
    conn.close()
    return dict(row)


# --------------------------------------------------------------------------
# J. unit-level checks of the authentication primitive (no processes needed)
# --------------------------------------------------------------------------
def scenario_j() -> None:
    print("J. 认证原语：挑战长度、绑定字段、重放", flush=True)
    from dnslib import A, CLASS, DNSRecord, QTYPE, RCODE, RR
    from app import message_auth as ma

    secret = HMAC_KEY.encode()
    domain = DOMAIN
    c1 = ma.new_challenge()
    c2 = ma.new_challenge()
    check("J1 挑战为 128 位随机值（每次不同）",
          len(c1) == 32 and c1 != c2 and all(ch in "0123456789abcdef" for ch in c1),
          f"len={len(c1)}")

    def make(ip="192.0.2.1", ttl=5, rcode=RCODE.NOERROR, qname=domain,
             txn=0x1234, challenge=c1, secret_=secret):
        q = DNSRecord.question(qname, "A")
        q.header.id = txn
        rep = q.reply()
        rep.header.rcode = rcode
        if ip:
            rep.add_answer(RR(domain + ".", QTYPE.A, CLASS.IN, ttl, A(ip)))
        data = ma.build_answer(rep, domain, secret_, "k1", challenge,
                               signing_enabled=True)
        return DNSRecord.parse(data), challenge

    def verify(rep, challenge=c1, secret_=secret):
        return ma.verify(rep, domain, secret_, "k1", challenge)[0]

    rep, ch = make()
    check("J2 正确签名的答复通过", verify(rep) == ma.OK, verify(rep))
    check("J3 缺少认证 TXT 被拒",
          ma.verify(DNSRecord.parse(DNSRecord.question(domain, "A").reply()
                                    .pack()), domain, secret, "k1", c1)[0]
          == ma.MISSING)

    # Each bound field must be tamper-evident: sign genuine content, then
    # alter exactly one field and re-parse as an on-path attacker would.
    def signed_genuine():
        q = DNSRecord.question(domain, "A")
        q.header.id = 0x1234
        good = q.reply()
        good.add_answer(RR(domain + ".", QTYPE.A, CLASS.IN, 5, A("192.0.2.1")))
        return DNSRecord.parse(ma.build_answer(good, domain, secret, "k1", c1,
                                               True))

    binds = [
        ("查询名",
         lambda r: setattr(r.q, "qname",
                           DNSRecord.question("other.example", "A").q.qname)),
        ("事务 ID", lambda r: setattr(r.header, "id", 0x4321)),
        ("结果码", lambda r: setattr(r.header, "rcode", RCODE.NXDOMAIN)),
        ("A 地址", lambda r: setattr(r.rr[0], "rdata", A("198.51.100.7"))),
        ("TTL", lambda r: setattr(r.rr[0], "ttl", 999)),
    ]
    for label, mutate in binds:
        parsed = signed_genuine()
        mutate(parsed)
        got = ma.verify(DNSRecord.parse(parsed.pack()), domain, secret,
                        "k1", c1)[0]
        check(f"J4 篡改{label}被拒", got != ma.OK, f"outcome={got}")

    # Replay: a signature bound to a different challenge must not verify.
    rep, _ = make()
    check("J5 重放旧挑战被拒（挑战不匹配）",
          verify(rep, challenge=c2) == ma.BAD_CHALLENGE)

    # Wrong key must not verify even with the right challenge.
    rep, _ = make(secret_=b"another-key-entirely")
    check("J6 错误密钥签名被拒", verify(rep) == ma.BAD_SIG)

    # NXDOMAIN answers bind rcode (there is no A to bind).
    rep, _ = make(ip=None, rcode=RCODE.NXDOMAIN)
    check("J7 认证通过的 NXDOMAIN 可验证", verify(rep) == ma.OK)
    q = DNSRecord.question(domain, "A")
    q.header.id = 0x1234
    good = q.reply()
    good.header.rcode = RCODE.NXDOMAIN
    parsed = DNSRecord.parse(ma.build_answer(good, domain, secret, "k1", c1, True))
    parsed.header.rcode = RCODE.NOERROR           # flip NXDOMAIN -> NOERROR
    got = ma.verify(DNSRecord.parse(parsed.pack()), domain, secret, "k1", c1)[0]
    check("J8 篡改结果码 NXDOMAIN->NOERROR 被拒", got == ma.BAD_SIG,
          f"outcome={got}")


# --------------------------------------------------------------------------
# G. HMAC answer authentication with the real authoritative endpoint
# --------------------------------------------------------------------------
def scenario_g() -> None:
    print("G. HMAC 应答认证：错误/缺失签名视为回源不可用", flush=True)

    # G1/G2: no cached record -> forged answers cannot create one
    clear_cache()
    set_mode("a", "192.0.2.10", auth_state="badsig")
    rc, ans, src, auth = dns_query()
    check("G1 错误签名 -> SERVFAIL，不写缓存",
          rc == 2 and not ans and src == "none" and auth == "bad-signature"
          and get_cache() is None, f"rcode={rc} ans={ans} src={src} auth={auth}")

    clear_cache()
    set_mode("a", "192.0.2.10", auth_state="noauth")
    rc, ans, src, auth = dns_query()
    check("G2 缺失签名 -> SERVFAIL，不写缓存",
          rc == 2 and not ans and src == "none" and auth == "missing"
          and get_cache() is None, f"rcode={rc} ans={ans} src={src} auth={auth}")

    # G3: a valid A is cached; a forged refresh cannot replace it.  Within the
    # stale window the old A is still served (as on any upstream outage).
    set_mode("a", "192.0.2.20", auth_state="ok")
    rc, ans, src, auth = dns_query()
    assert rc == 0 and ans[0][1] == "192.0.2.20" and auth == "ok", \
        f"setup failed: {rc} {ans} {auth}"
    cache0 = get_cache()
    # configured A differs from the address the badsig endpoint tampers to
    set_mode("a", "192.0.2.21", auth_state="badsig")
    sleep_until(cache0["fresh_until"] + 0.3)
    rc, ans, src, auth = dns_query()
    check("G3 篡改 A 答复被拒 -> 旧 A 仅按 stale 窗口沿用",
          rc == 0 and src == "cache-stale" and ans[0][1] == "192.0.2.20"
          and auth == "bad-signature",
          f"ans={ans} src={src} auth={auth}")
    cache1 = get_cache()
    check("G3b 缓存未被伪造答复刷新（IP/期限不变）",
          cache1["a_record"] == "192.0.2.20"
          and cache1["fresh_until"] == cache0["fresh_until"]
          and cache1["stale_until"] == cache0["stale_until"],
          f"cache_before={cache0} cache_after={cache1}")

    # G4: past the original 20s window -> SERVFAIL, still no refresh
    sleep_until(cache0["stale_until"] + 0.5)
    rc, ans, src, auth = dns_query()
    check("G4 认证失败超过 stale 窗口 -> SERVFAIL",
          rc == 2 and not ans and src == "none" and auth == "bad-signature",
          f"rcode={rc} ans={ans} src={src} auth={auth}")
    check("G4b 缓存中仍无伪造地址", get_cache()["a_record"] == "192.0.2.20")

    # G5: an unauthenticated NXDOMAIN must not purge the old A
    set_mode("a", "192.0.2.30", auth_state="ok")
    rc, ans, src, auth = dns_query()
    assert rc == 0 and ans[0][1] == "192.0.2.30" and src == "upstream", \
        f"setup failed: {rc} {ans} {src}"
    cache2 = get_cache()
    set_mode("nxdomain", auth_state="badsig")
    sleep_until(cache2["fresh_until"] + 0.3)
    rc, ans, src, auth = dns_query()
    check("G5 伪造 NXDOMAIN 不能清除旧 A（仍在 stale 窗口）",
          rc == 0 and src == "cache-stale" and ans[0][1] == "192.0.2.30"
          and auth == "bad-signature", f"ans={ans} src={src} auth={auth}")
    cache3 = get_cache()
    check("G5b 缓存仍是 NOERROR，旧 A 未被清除",
          cache3["rcode"] == "NOERROR" and cache3["a_record"] == "192.0.2.30"
          and cache3["stale_until"] == cache2["stale_until"], f"cache={cache3}")

    # G6: authenticated NXDOMAIN does purge, and it is used
    set_mode("nxdomain", auth_state="ok")
    rc, ans, src, auth = dns_query()
    check("G6 认证通过的 NXDOMAIN 被接受并清除旧 A",
          rc == 3 and not ans and src == "upstream" and auth == "ok"
          and get_cache()["rcode"] == "NXDOMAIN"
          and get_cache()["a_record"] is None,
          f"rcode={rc} src={src} auth={auth} cache={get_cache()}")

    # G7: NXDOMAIN is still never served stale, even when auth now fails
    set_mode("timeout")
    time.sleep(5.5)
    rc, ans, src, auth = dns_query()
    check("G7 认证失败且无可用 A -> SERVFAIL（NXDOMAIN 不作 stale）",
          rc == 2 and not ans and src == "none",
          f"rcode={rc} ans={ans} src={src} auth={auth}")


# --------------------------------------------------------------------------
# H. rogue upstream: replay / tamper / unsigned / wrong key / valid
# --------------------------------------------------------------------------
ROGUE_PORT = 25354
ROGUE_RES_PORT = 25353
ROGUE_DB = os.path.join(TMP, "rogue", "app.db")
ROGUE_CONF = os.path.join(TMP, "rogue", "mode.json")


def set_rogue(mode: str) -> None:
    os.makedirs(os.path.dirname(ROGUE_CONF), exist_ok=True)
    with open(ROGUE_CONF, "w", encoding="utf-8") as fh:
        json.dump({"mode": mode}, fh)


def scenario_h() -> None:
    print("H. 重放/篡改/无签名/错误密钥的答复均被拒绝", flush=True)
    set_rogue("valid")
    start_cmd("rogue", [sys.executable, os.path.join(ROOT, "tests",
                                                   "rogue_upstream.py"),
                        str(ROGUE_PORT), ROGUE_CONF, DOMAIN, HMAC_KEY, "k1"])
    rogue_env = {
        "DB_PATH": ROGUE_DB,
        "AUTH_HOST": "127.0.0.1",
        "AUTH_PORT": str(ROGUE_PORT),
        "RESOLVER_PORT": str(ROGUE_RES_PORT),
        "HMAC_KEY_FILE": os.path.join(TMP, "rogue", "hmac.key"),
    }
    start("rogue_resolver", "app.resolver", rogue_env)
    t0 = time.time()
    ready = False
    while time.time() - t0 < 20:
        try:
            dns_query(ROGUE_RES_PORT)
            ready = True
            break
        except Exception:
            time.sleep(0.3)
    check("H0 伪造上游联调环境就绪", ready)
    if not ready:
        return

    cases = [
        ("valid", "正确签名的伪造上游（正面对照）", 0, "ok", "192.0.2.99"),
        ("tampered", "签名有效但 A/应答内容被篡改", 2, "bad-signature", None),
        ("unsigned", "完全无签名", 2, "missing", None),
        ("replay", "重放旧挑战的签名（挑战不匹配）", 2, "bad-challenge", None),
        ("wrongkey", "用错误密钥签名", 2, "bad-signature", None),
        ("forge_then_valid",
         "先收到伪造答复，再接收到正确签名答复（应接受后者）",
         0, "ok", "192.0.2.99"),
    ]
    for mode, label, want_rc, want_auth, want_ip in cases:
        set_rogue(mode)
        clear_cache(ROGUE_DB)
        rc, ans, src, auth = dns_query(ROGUE_RES_PORT)
        ok = rc == want_rc and auth == want_auth
        if want_ip:
            ok = ok and ans and ans[0][1] == want_ip and src == "upstream"
        else:
            ok = ok and not ans and get_cache_from(ROGUE_DB) is None
        check(f"H-{mode} {label}", ok,
              f"rcode={rc} ans={ans} src={src} auth={auth} "
              f"cache={get_cache_from(ROGUE_DB)}")

    # a replayed answer must not be able to refresh a cached A either
    set_rogue("valid")
    clear_cache(ROGUE_DB)
    rc, ans, src, auth = dns_query(ROGUE_RES_PORT)
    seeded = get_cache_from(ROGUE_DB)
    assert rc == 0 and seeded and seeded["a_record"] == "192.0.2.99", \
        f"seed failed: {rc} {ans} {seeded}"
    set_rogue("replay")
    sleep_until(seeded["fresh_until"] + 0.3)
    rc, ans, src, auth = dns_query(ROGUE_RES_PORT)
    after = get_cache_from(ROGUE_DB)
    check("H6a 重放答复不能刷新缓存，仅按 stale 窗口供旧 A",
          rc == 0 and src == "cache-stale" and ans[0][1] == "192.0.2.99"
          and auth == "bad-challenge"
          and after["fresh_until"] == seeded["fresh_until"],
          f"ans={ans} src={src} auth={auth}")
    sleep_until(seeded["stale_until"] + 0.5)
    rc, ans, src, auth = dns_query(ROGUE_RES_PORT)
    check("H6b 重放持续失败，超过原 stale 窗口即 SERVFAIL",
          rc == 2 and not ans and src == "none" and auth == "bad-challenge",
          f"rcode={rc} ans={ans} src={src} auth={auth}")

    stop("rogue_resolver")
    stop("rogue")


# --------------------------------------------------------------------------
# I. the shared key persists across restarts when not supplied via env
# --------------------------------------------------------------------------
KEY_PORT_AUTH = 35354
KEY_PORT_RES = 35353
KEY_DIR = os.path.join(TMP, "keytest")
KEY_DB = os.path.join(KEY_DIR, "app.db")
KEY_FILE = os.path.join(KEY_DIR, "hmac.key")


def scenario_i() -> None:
    print("I. 共享密钥持久化（重启后继续使用同一密钥）", flush=True)
    env_no_key = dict(DB_PATH=KEY_DB, HMAC_KEY_FILE=KEY_FILE,
                      DNS_HMAC_KEY=None,   # force key-file generation
                      AUTH_PORT=str(KEY_PORT_AUTH),
                      RESOLVER_PORT=str(KEY_PORT_RES),
                      AUTH_HOST="127.0.0.1")
    start("key_auth", "app.auth_server", env_no_key)
    start("key_res", "app.resolver", env_no_key)

    def query_key() -> tuple[int, list, str | None, str | None]:
        t0 = time.time()
        while time.time() - t0 < 20:
            try:
                return dns_query(KEY_PORT_RES)
            except Exception:
                time.sleep(0.3)
        raise RuntimeError("key-test resolver did not come up")

    rc, ans, src, auth = query_key()
    ok_file = os.path.exists(KEY_FILE)
    key_len = os.path.getsize(KEY_FILE) if ok_file else 0
    mode = oct(os.stat(KEY_FILE).st_mode & 0o777) if ok_file else "?"
    check("I1 未提供 env 密钥时自动生成共享密钥文件",
          ok_file and key_len == 32 and mode == "0o600",
          f"file={KEY_FILE} bytes={key_len} mode={mode}")
    check("I2 自动生成的密钥可用（认证通过）",
          rc == 0 and src == "upstream" and auth == "ok",
          f"rcode={rc} src={src} auth={auth}")

    # compare the fingerprints the running processes logged at startup
    fp_auth = logged_fingerprint("key_auth")
    fp_res = logged_fingerprint("key_res")
    check("I3 auth 与 resolver 使用同一密钥指纹",
          fp_auth is not None and fp_auth == fp_res,
          f"auth={fp_auth} resolver={fp_res}")

    stop("key_res")
    stop("key_auth")
    time.sleep(1)
    start("key_auth", "app.auth_server", env_no_key)
    start("key_res", "app.resolver", env_no_key)
    clear_cache(KEY_DB)
    rc, ans, src, auth = query_key()
    fp_after = logged_fingerprint("key_res")
    check("I4 重启后仍用同一密钥且认证通过",
          rc == 0 and src == "upstream" and auth == "ok" and fp_after == fp_res,
          f"rcode={rc} src={src} auth={auth} fp_before={fp_res} "
          f"fp_after={fp_after}")
    stop("key_res")
    stop("key_auth")


def logged_fingerprint(name: str) -> str | None:
    """Fingerprint a running process printed at startup (never the key)."""
    path = os.path.join(TMP, f"{name}.log")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    import re
    found = re.findall(r"fingerprint=([0-9a-f]{16})", text)
    return found[-1] if found else None


if __name__ == "__main__":
    sys.exit(main())

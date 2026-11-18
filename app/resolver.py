"""Caching UDP DNS resolver for one fixed internal domain.

Behaviour (all timings from app.common, defaults are the spec values):

  * a successful A answer is cached fresh for FRESH_TTL (5s) and served from
    cache with the remaining TTL;
  * after expiry the resolver re-fetches.  If the upstream times out (or its
    reply is unusable) the old A record may be served stale for at most
    STALE_WINDOW (20s) past expiry; beyond that the answer is SERVFAIL;
  * NXDOMAIN is cached fresh only -- it is never used as stale backup;
  * confirming NXDOMAIN purges the old A record durably (SQLite), so no later
    answer contains the old A again;
  * every upstream attempt uses a dedicated socket with a random transaction
    ID and matches the question section, so a late answer to an already
    timed-out query is never read and can never resurrect the old A;
  * every upstream attempt carries a fresh >=128-bit random challenge and the
    authoritative answer must carry a valid HMAC-SHA256 signature over the
    query name, transaction ID, rcode, A address, TTL and that challenge.
    Unsigned, tampered or replayed answers are treated exactly like an
    upstream timeout: they never refresh the cache and can never purge it.
    Only an authenticated A refreshes the cache; only an authenticated
    NXDOMAIN purges an old A;
  * cache deadlines are absolute epochs persisted in SQLite, so a restart does
    not extend the validity of an old A record.

The resolver reports where each answer came from in an additional-section TXT
record (_src.<domain> TXT "source=upstream|cache-fresh|cache-stale|none ...")
and logs every query to the query_log table for the web console.
"""
from __future__ import annotations

import random
import socket
import threading
import time
import traceback

from dnslib import A, CLASS, QTYPE, RCODE, RR, TXT, DNSHeader, DNSRecord

from . import common, message_auth


def _same_name(a, b) -> bool:
    return str(a).rstrip(".").lower() == str(b).rstrip(".").lower()


def upstream_query() -> tuple[DNSRecord | None, str, str]:
    """One-shot upstream A query for the fixed domain.

    Returns ``(answer, auth_outcome, auth_detail)``.  ``answer`` is None on
    timeout; it is also None when a reply arrived but failed authentication,
    because such a reply is not an authoritative result and must be treated
    exactly like an upstream outage.

    A dedicated UDP socket per attempt plus a random transaction ID means a
    late answer to an earlier, already timed-out query can never be read back
    (the socket is closed) and can never be mistaken for the answer to a later
    query (ID + question must match).  A fresh random challenge is embedded in
    every attempt; an answer that does not echo it is a replay and is rejected.
    """
    query = DNSRecord.question(common.FQDN, "A")
    query.header.id = random.randint(0, 0xFFFF)
    challenge = message_auth.new_challenge()
    message_auth.add_query_challenge(query, common.FIXED_DOMAIN, challenge)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # A forged/broken answer is not an authoritative result.  Record why and
    # keep listening until the deadline: a spoofed packet arriving first must
    # not prevent a genuine, correctly signed answer from being accepted.
    last_auth = message_auth.MISSING
    last_detail = "no answer"
    try:
        sock.sendto(query.pack(), (common.AUTH_HOST, common.AUTH_PORT))
        deadline = time.monotonic() + common.UPSTREAM_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None, last_auth, last_detail
            sock.settimeout(remaining)
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                return None, last_auth, last_detail
            try:
                resp = DNSRecord.parse(data)
            except Exception:
                continue  # unparsable stray datagram: keep waiting
            if resp.header.id != query.header.id:
                continue  # stray/late packet for someone else: ignore
            try:
                same_q = _same_name(resp.q.qname, query.q.qname)
            except Exception:
                continue
            if not same_q:
                continue
            auth, auth_detail = message_auth.verify(
                resp, common.FIXED_DOMAIN, common.hmac_secret(),
                common.HMAC_KEY_ID, challenge)
            if auth != message_auth.OK:
                last_auth, last_detail = auth, auth_detail
                continue  # unauthenticated: never an authoritative result
            return resp, auth, auth_detail
    except OSError as exc:
        return None, "error", f"upstream socket error: {exc}"
    finally:
        sock.close()


def _a_rr(ip: str, ttl: int) -> RR:
    return RR(common.FQDN, QTYPE.A, CLASS.IN, ttl, A(ip))


def _reply(query: DNSRecord, rcode: int, answers=(), source="none", detail="") -> DNSRecord:
    rep = DNSRecord(
        DNSHeader(
            id=query.header.id, qr=1, aa=0, ra=1, rd=query.header.rd, rcode=rcode
        ),
        q=query.q,
    )
    for rr in answers:
        rep.add_answer(rr)
    meta = f"source={source}" + (f" {detail}" if detail else "")
    rep.add_ar(RR(f"_src.{common.FQDN}", QTYPE.TXT, CLASS.IN, 0, TXT(meta)))
    return rep


def resolve_a(query: DNSRecord) -> tuple[DNSRecord, str, str, str]:
    """Resolve the fixed domain's A record.

    Returns (reply, source, detail, auth) where ``auth`` is the outcome of the
    authentication of the upstream answer used for this decision ("" when the
    answer came from cache).
    """
    now = time.time()
    row = common.get_cache()

    # 1) fresh cache hits
    if row and row["rcode"] == "NOERROR" and row["a_record"] and now < row["fresh_until"]:
        ttl = max(1, int(row["fresh_until"] - now + 0.999))
        return (
            _reply(query, RCODE.NOERROR, [_a_rr(row["a_record"], ttl)], "cache-fresh",
                   f"fresh_left={row['fresh_until'] - now:.1f}"),
            "cache-fresh",
            "fresh A from cache",
            "",
        )
    if row and row["rcode"] == "NXDOMAIN" and now < row["fresh_until"]:
        return (
            _reply(query, RCODE.NXDOMAIN, [], "cache-fresh",
                   f"fresh_left={row['fresh_until'] - now:.1f}"),
            "cache-fresh",
            "fresh NXDOMAIN from cache",
            "",
        )

    # 2) expired: ask the authoritative endpoint.  An answer that fails
    #    authentication comes back as None with the failure detail.
    resp, auth, auth_detail = upstream_query()
    now2 = time.time()

    if resp is not None and resp.header.rcode == RCODE.NOERROR:
        ips = [str(rr.rdata) for rr in resp.rr if rr.rtype == QTYPE.A]
        if len(ips) == 1:
            common.put_cache_a(ips[0], now2)
            return (
                _reply(query, RCODE.NOERROR, [_a_rr(ips[0], int(common.FRESH_TTL))],
                       "upstream", f"auth={auth}"),
                "upstream",
                f"authenticated A={ips[0]}",
                auth,
            )

    if resp is not None and resp.header.rcode == RCODE.NXDOMAIN:
        # Confirming NXDOMAIN purges the old A record (durably, in SQLite).
        # Only an authenticated NXDOMAIN may do this.
        common.put_cache_nxdomain(now2)
        return (
            _reply(query, RCODE.NXDOMAIN, [], "upstream",
                   f"nxdomain-confirmed auth={auth}"),
            "upstream",
            "authenticated NXDOMAIN confirmed; old A purged",
            auth,
        )

    # 3) upstream timeout / unauthenticated / unusable reply: treat as
    #    upstream unavailable.  Maybe serve the stale A record (NXDOMAIN is
    #    never served stale); the cache is never changed here.
    row = common.get_cache()
    if (
        row
        and row["rcode"] == "NOERROR"
        and row["a_record"]
        and row["stale_until"]
        and now2 < row["stale_until"]
    ):
        ttl = max(1, int(row["stale_until"] - now2 + 0.999))
        return (
            _reply(query, RCODE.NOERROR, [_a_rr(row["a_record"], ttl)], "cache-stale",
                   f"stale_left={row['stale_until'] - now2:.1f} auth={auth}"),
            "cache-stale",
            f"upstream auth={auth} ({auth_detail}); serving stale A",
            auth,
        )

    return (
        _reply(query, RCODE.SERVFAIL, [], "none",
               f"upstream-unavailable auth={auth}"),
        "none",
        f"upstream auth={auth} ({auth_detail}); no usable cache",
        auth,
    )


def handle_packet(data: bytes, addr, sock: socket.socket) -> None:
    qname = qtype = "?"
    try:
        query = DNSRecord.parse(data)
        qname = str(query.q.qname)
        qtype = QTYPE[query.q.qtype]
        auth = ""
        if not _same_name(query.q.qname, common.FQDN):
            rep = _reply(query, RCODE.REFUSED, [], "none", "out-of-scope")
            source, detail = "none", "out-of-scope"
        elif query.q.qtype == QTYPE.A:
            rep, source, detail, auth = resolve_a(query)
        else:
            rep = _reply(query, RCODE.NOERROR, [], "none", "nodata")
            source, detail = "none", "nodata"
        sock.sendto(rep.pack(), addr)
        answers = ";".join(
            f"{QTYPE[rr.rtype]}={rr.rdata}(ttl={rr.ttl})" for rr in rep.rr
        ) or "-"
        common.log_query(qname, qtype, source, RCODE[rep.header.rcode], answers,
                         detail, auth)
    except Exception:
        common.log_query(qname, qtype, "error", "SERVFAIL", "-",
                         traceback.format_exc(limit=3))


def main() -> None:
    common.init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", common.RESOLVER_PORT))
    print(
        f"[resolver] {common.FQDN} on udp/{common.RESOLVER_PORT}, "
        f"upstream {common.AUTH_HOST}:{common.AUTH_PORT}, "
        f"fresh={common.FRESH_TTL}s stale={common.STALE_WINDOW}s "
        f"timeout={common.UPSTREAM_TIMEOUT}s, "
        f"answer-auth HMAC-SHA256 kid={common.HMAC_KEY_ID} "
        f"fingerprint={common.hmac_key_fingerprint()}",
        flush=True,
    )
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_packet, args=(data, addr, sock),
                         daemon=True).start()


if __name__ == "__main__":
    main()

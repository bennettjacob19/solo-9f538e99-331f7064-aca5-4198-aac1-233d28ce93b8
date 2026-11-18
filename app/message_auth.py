"""HMAC-SHA256 answer authentication for the upstream (recursive fetch) path.

Threat model: the resolver reaches its authoritative endpoint over an
untrusted network.  An off-path attacker can forge an A answer (cache
poisoning) or an NXDOMAIN (denial / stale purge).  A shared secret turns every
upstream answer into a verifiable statement.

Protocol (one TXT RR in the additional section, name ``_auth.<fixed-domain>``)::

    hmac-v1;kid=<key-id>;challenge=<hex>;sig=<hex>

The resolver puts a fresh random challenge (>= 128 bits) in an additional
section TXT of the query; the authoritative endpoint echoes it and signs::

    sig = HMAC-SHA256(key,
            "DNSAUTH1\\n" + domain + "\\n" + qname + "\\n" + txn_id_hex +
            "\\n" + qtype + "\\n" + rcode + "\\n" + answer_a + "\\n" +
            answer_ttl + "\\n" + challenge)

so the signature binds the query name, transaction ID, result code, A address
and TTL (and the per-query challenge).  The challenge is what makes replays
useless: the resolver only accepts an answer that carries the challenge it
generated for this very attempt, and each attempt uses a new random one.

Verification is constant-time; a missing, truncated, wrong-key, wrong-challenge
or altered answer is rejected exactly like a timeout (upstream unavailable).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from dnslib import CLASS, DNSRecord, QTYPE, RR, TXT

VERSION = "hmac-v1"
CHALLENGE_BYTES = 16          # 128 bits
CHALLENGE_ATTR = "_auth"      # owner name is _auth.<fixed-domain>
SIG_PREFIX = "DNSAUTH1\n"

# Verification outcomes (kept as short strings: they are logged/displayed).
OK = "ok"
MISSING = "missing"          # no auth TXT record at all
MALFORMED = "malformed"      # TXT present but not our format
BAD_KEY = "bad-key"          # key-id unknown
BAD_CHALLENGE = "bad-challenge"  # answer does not echo our challenge (replay/forged)
BAD_SIG = "bad-signature"    # HMAC mismatch (tampered content / wrong key)

def auth_name(domain: str) -> str:
    return f"{CHALLENGE_ATTR}.{domain.rstrip('.')}."


def new_challenge() -> str:
    return secrets.token_hex(CHALLENGE_BYTES)


def _canonical(domain: str, qname: str, txn_id: int, qtype: str, rcode: int,
               ip: str, ttl: int, challenge: str) -> bytes:
    lines = [
        domain.rstrip(".").lower(),
        qname.rstrip(".").lower(),
        f"{txn_id & 0xFFFF:04x}",
        qtype.upper(),
        str(rcode),
        ip or "-",
        str(int(ttl)),
        challenge,
    ]
    return (SIG_PREFIX + "\n".join(lines)).encode()


def sign(secret: bytes, domain: str, qname: str, txn_id: int, qtype: str,
         rcode: int, ip: str, ttl: int, challenge: str) -> str:
    return hmac.new(
        secret,
        _canonical(domain, qname, txn_id, qtype, rcode, ip, ttl, challenge),
        hashlib.sha256,
    ).hexdigest()


def auth_txt(challenge: str, signature: str, key_id: str) -> str:
    return f"{VERSION};kid={key_id};challenge={challenge};sig={signature}"


def add_query_challenge(query: DNSRecord, domain: str, challenge: str) -> None:
    """Attach the per-attempt challenge to an upstream query."""
    query.add_ar(
        RR(auth_name(domain), QTYPE.TXT, CLASS.IN, 0, TXT(challenge))
    )


def query_challenge(query: DNSRecord, domain: str) -> str | None:
    """Extract the challenge from an upstream query (authoritative side)."""
    for rr in query.ar:
        if rr.rtype == QTYPE.TXT and _same_name(rr.rname, auth_name(domain)):
            return _txt_text(rr)
    return None


def _txt_text(rr) -> str:
    data = rr.rdata.data
    if isinstance(data, (list, tuple)):
        data = b"".join(data)
    if isinstance(data, bytes):
        return data.decode("ascii", "replace")
    return str(data)


def _same_name(a, b) -> bool:
    return str(a).rstrip(".").lower() == str(b).rstrip(".").lower()


def parse_auth_txt(text: str) -> dict | None:
    parts = {}
    chunks = text.split(";")
    if not chunks or chunks[0] != VERSION:
        return None
    for chunk in chunks[1:]:
        if "=" not in chunk:
            return None
        key, value = chunk.split("=", 1)
        parts[key.strip()] = value.strip()
    if not {"kid", "challenge", "sig"} <= parts.keys():
        return None
    return parts


def find_auth_txt(resp: DNSRecord, domain: str) -> RR | None:
    for rr in resp.ar:
        if rr.rtype == QTYPE.TXT and _same_name(rr.rname, auth_name(domain)):
            return rr
    return None


def answer_fields(resp: DNSRecord) -> tuple[str, int]:
    """The single A address and TTL that the signature covers.

    The resolver only ever accepts answers with exactly one A RR (anything
    else is rejected as unusable), so binding that one RR is sufficient --
    an attacker cannot smuggle in a second A record.

    Returns ("", 0) when there is no A RR (NXDOMAIN).
    """
    ips = [rr for rr in resp.rr if rr.rtype == QTYPE.A]
    if not ips:
        return "", 0
    return str(ips[0].rdata), int(ips[0].ttl)


def build_answer(resp: DNSRecord, domain: str, secret: bytes, key_id: str,
                 challenge: str, signing_enabled: bool) -> bytes:
    """Add the authentication TXT to an authoritative answer and pack it.

    ``signing_enabled`` False simulates a broken / unsigned upstream: the
    answer is sent without a signature (or, for negative tests selected in
    the console, with a signature over the wrong content).
    """
    ip, ttl = answer_fields(resp)
    challenge = challenge or ""
    if signing_enabled:
        sig = sign(secret, domain, str(resp.q.qname), resp.header.id,
                   QTYPE[resp.q.qtype], resp.header.rcode, ip, ttl, challenge)
        resp.add_ar(RR(auth_name(domain), QTYPE.TXT, CLASS.IN, 0,
                       TXT(auth_txt(challenge, sig, key_id))))
    return resp.pack()


def verify(resp: DNSRecord, domain: str, secret: bytes, key_id: str,
           challenge: str) -> tuple[str, str]:
    """Verify an upstream answer.  Returns (outcome, detail)."""
    rr = find_auth_txt(resp, domain)
    if rr is None:
        return MISSING, "no _auth TXT in answer"
    parts = parse_auth_txt(_txt_text(rr))
    if parts is None:
        return MALFORMED, "unparsable _auth TXT"
    if parts["kid"] != key_id:
        return BAD_KEY, f"unknown kid {parts['kid']!r}"
    if not challenge or not hmac.compare_digest(parts["challenge"], challenge):
        return BAD_CHALLENGE, "challenge mismatch (replay/forgery)"
    ip, ttl = answer_fields(resp)
    expected = sign(secret, domain, str(resp.q.qname), resp.header.id,
                    QTYPE[resp.q.qtype], resp.header.rcode, ip, ttl, challenge)
    if not hmac.compare_digest(parts["sig"], expected):
        return BAD_SIG, "HMAC mismatch (tampered or wrong key)"
    return OK, f"kid={key_id}"

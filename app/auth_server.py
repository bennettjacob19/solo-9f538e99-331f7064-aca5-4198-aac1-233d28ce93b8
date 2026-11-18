"""Local authoritative endpoint for the fixed domain.

Its behaviour is switched at runtime from the web console via the shared
control table (read on every query, so changes take effect immediately):

  a        -- answer the configured A record (TTL = FRESH_TTL)
  nxdomain -- answer NXDOMAIN
  delay    -- answer the A record only after `delay_seconds` (longer than the
              resolver's upstream timeout, to exercise late-answer handling)
  timeout  -- never answer (simulates the authoritative endpoint being lost)

Independently, `auth_state` decides how answers are authenticated:

  ok      -- sign the answer with HMAC-SHA256 over the resolver's challenge,
             the query name, transaction ID, rcode, A address and TTL
  badsig  -- sign, then tamper with the answer content (signature no longer
             matches) -- exercises tamper detection
  noauth  -- send the answer with no signature at all -- exercises missing
             signature handling

Every received query is logged to auth_log so the console can show what the
upstream actually saw and did.
"""
from __future__ import annotations

import socket
import threading
import time
import traceback

from dnslib import A, QTYPE, RCODE, RR, DNSRecord

from . import common, message_auth


def _send_answer(query: DNSRecord, rep: DNSRecord, addr, sock: socket.socket,
                 action: str, detail: str, mode: str, auth_state: str) -> None:
    """Sign (or deliberately fail to sign) an answer and log what happened."""
    challenge = message_auth.query_challenge(query, common.FIXED_DOMAIN) or ""
    if auth_state == "noauth":
        data = rep.pack()
        detail = f"{detail}; sent UNSIGNED (auth_state=noauth)"
    elif auth_state == "badsig":
        # Sign the genuine content, then tamper with the answer so the
        # signature no longer matches -- exactly what a forger would produce.
        data = message_auth.build_answer(
            rep, common.FIXED_DOMAIN, common.hmac_secret(), common.HMAC_KEY_ID,
            challenge, signing_enabled=True)
        tampered = DNSRecord.parse(data)
        ips = [rr for rr in tampered.rr if rr.rtype == QTYPE.A]
        if ips:
            ips[0].rdata = A("203.0.113.66")
        else:  # NXDOMAIN: tamper the rcode instead
            tampered.header.rcode = RCODE.NOERROR
        data = tampered.pack()
        detail = f"{detail}; sent with BAD signature (auth_state=badsig)"
    else:
        data = message_auth.build_answer(
            rep, common.FIXED_DOMAIN, common.hmac_secret(), common.HMAC_KEY_ID,
            challenge, signing_enabled=True)
        detail = f"{detail}; signed kid={common.HMAC_KEY_ID}"
    sock.sendto(data, addr)
    common.log_auth(str(query.q.qname), QTYPE[query.q.qtype], mode, action, detail)


def handle(data: bytes, addr, sock: socket.socket) -> None:
    qname = qtype = "?"
    mode = "?"
    try:
        query = DNSRecord.parse(data)
        qname = str(query.q.qname)
        qtype = QTYPE[query.q.qtype]
        ctl = common.get_control() or {
            "mode": "a", "ip": common.DEFAULT_IP,
            "delay_seconds": common.DEFAULT_DELAY, "auth_state": "ok",
        }
        mode = ctl["mode"]
        auth_state = ctl.get("auth_state") or "ok"

        in_scope = (
            str(query.q.qname).rstrip(".").lower() == common.FIXED_DOMAIN.lower()
            and query.q.qtype in (QTYPE.A, QTYPE.ANY)
        )
        if not in_scope:
            rep = query.reply()
            rep.header.rcode = RCODE.NXDOMAIN
            _send_answer(query, rep, addr, sock, "nxdomain",
                         "out-of-scope name/qtype", mode, auth_state)
            return

        if mode == "timeout":
            common.log_auth(qname, qtype, mode, "dropped",
                            "simulating lost authoritative endpoint")
            return  # no answer at all -> the resolver's upstream times out

        if mode == "delay":
            time.sleep(max(0.0, float(ctl["delay_seconds"])))

        if mode == "nxdomain":
            rep = query.reply()
            rep.header.rcode = RCODE.NXDOMAIN
            _send_answer(query, rep, addr, sock, "nxdomain", "confirmed negative",
                         mode, auth_state)
            return

        # modes "a" and "delay": answer the configured A record
        rep = query.reply()
        rep.add_answer(
            RR(common.FQDN, QTYPE.A, rdata=A(ctl["ip"]), ttl=int(common.FRESH_TTL))
        )
        suffix = (f" after {ctl['delay_seconds']}s delay" if mode == "delay" else "")
        _send_answer(query, rep, addr, sock, "answered",
                     f"A={ctl['ip']}{suffix}", mode, auth_state)
    except Exception:
        common.log_auth(qname, qtype, mode, "error", traceback.format_exc(limit=3))


def main() -> None:
    common.init_db()
    key = common.hmac_secret()
    print(f"[auth] authoritative for {common.FQDN} on udp/{common.AUTH_PORT}, "
          f"HMAC kid={common.HMAC_KEY_ID} fingerprint={common.hmac_key_fingerprint()} "
          f"({len(key) * 8}-bit key)", flush=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", common.AUTH_PORT))
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle, args=(data, addr, sock), daemon=True).start()


if __name__ == "__main__":
    main()

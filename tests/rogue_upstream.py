"""Rogue upstream used only by the self-test.

Listens on its own UDP port and answers every A query for the fixed domain as
if it were the authoritative endpoint, so the test can replay/tamper answers.
Modes are switched by writing a JSON file (re-read per query):

  valid      -- correctly signed answer (same shared key)   [positive control]
  tampered   -- correctly signed, then A address altered
  unsigned   -- no _auth TXT at all
  replay     -- correctly signed but with a *previous* challenge echoed
  wrongkey   -- signed with a different key
  forge_then_valid -- first emit a forged (wrong-key) answer, then the genuine
               correctly signed one: the forged packet must not stop the
               resolver from accepting the genuine answer.
"""
from __future__ import annotations

import json
import socket
import sys

from dnslib import A, CLASS, QTYPE, RR, DNSRecord

from app import message_auth

PORT = int(sys.argv[1])
CONF = sys.argv[2]
DOMAIN = sys.argv[3]
SECRET = sys.argv[4].encode()
KEY_ID = sys.argv[5]
REPLAY_CHALLENGE = "0" * 32   # not the fresh challenge the resolver sent


def conf() -> str:
    try:
        with open(CONF, "r", encoding="utf-8") as fh:
            return json.load(fh)["mode"]
    except Exception:
        return "valid"


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", PORT))
    print(f"[rogue] udp/{PORT}", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            q = DNSRecord.parse(data)
        except Exception:
            continue
        mode = conf()
        if mode == "forge_then_valid":
            forged = q.reply()
            forged.add_answer(RR(DOMAIN + ".", QTYPE.A, CLASS.IN, 5,
                                 A("198.51.100.66")))
            sock.sendto(message_auth.build_answer(
                forged, DOMAIN, b"wrong-key", KEY_ID,
                message_auth.query_challenge(q, DOMAIN) or "", True), addr)
        rep = q.reply()
        rep.add_answer(RR(DOMAIN + ".", QTYPE.A, CLASS.IN, 5, A("192.0.2.99")))
        real_challenge = message_auth.query_challenge(q, DOMAIN) or ""
        challenge = REPLAY_CHALLENGE if mode == "replay" else real_challenge
        if mode == "unsigned":
            sock.sendto(rep.pack(), addr)
            continue
        secret = b"a-completely-different-key" if mode == "wrongkey" else SECRET
        data_out = message_auth.build_answer(
            rep, DOMAIN, secret, KEY_ID, challenge, signing_enabled=True)
        out = DNSRecord.parse(data_out)
        if mode == "tampered":
            out.rr[0].rdata = A("198.51.100.7")
            out.rr[0].ttl = 999
            data_out = out.pack()
        sock.sendto(data_out, addr)


if __name__ == "__main__":
    main()

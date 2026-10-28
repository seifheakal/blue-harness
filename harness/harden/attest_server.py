#!/usr/bin/env python3
# Carapace — reference server-side attestation verifier (Slice D).
#
# Models the OPERATOR'S SERVER, which is where the trust decision actually lives.
# The client (carapace_integrity.c) returns HMAC(key, nonce || live_checksum).
# The server holds the shared key AND the known-good checksum, issues a fresh
# random nonce per challenge, recomputes the expected MAC, and compares in
# constant time. This defeats:
#   - a PATCHED binary  : live_checksum != good_checksum -> MAC mismatch -> REJECT
#   - a REPLAYED response: the nonce changes every challenge -> REJECT
#
# Honest limits (CLAUDE.md §3): a client-side key can be extracted, so secrecy
# rests on the server nonce + the server holding the good checksum, not on client
# key secrecy. A live, sustained hook that recomputes the pristine checksum on
# every challenge still defeats this — hence Meaningful→Strong, never unbreakable.
# This is stdlib-only (hmac/hashlib) so it is dependency-free and auditable.

import os
import sys
import hmac
import json
import hashlib
import argparse

DEMO_KEY_HEX = "7c9e6a5f1b2d4e8a0c3f6b9d2e5a8c1f4b7e0a3d6c9f2b5e8a1d4c7f0b3e6a9d"


def issue_nonce(nbytes=16):
    return os.urandom(nbytes).hex()


def expected_mac(key_hex, good_checksum_hex, nonce_hex):
    key = bytes.fromhex(key_hex)
    msg = bytes.fromhex(nonce_hex) + bytes.fromhex(good_checksum_hex)
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify(key_hex, good_checksum_hex, nonce_hex, client_mac_hex):
    exp = expected_mac(key_hex, good_checksum_hex, nonce_hex)
    return hmac.compare_digest(exp, client_mac_hex.strip().lower())


def main(argv=None):
    ap = argparse.ArgumentParser(description="Carapace reference attestation verifier.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    n = sub.add_parser("nonce", help="issue a fresh random nonce (hex)")
    n.add_argument("--bytes", type=int, default=16)

    v = sub.add_parser("verify", help="accept/reject a client attestation response")
    v.add_argument("--key", default=DEMO_KEY_HEX)
    v.add_argument("--good", required=True, help="known-good hot-fn checksum (hex)")
    v.add_argument("--nonce", required=True)
    v.add_argument("--mac", required=True, help="client response MAC (hex)")
    v.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)
    if args.cmd == "nonce":
        print(issue_nonce(args.bytes))
        return 0
    if args.cmd == "verify":
        accepted = verify(args.key, args.good, args.nonce, args.mac)
        if args.json:
            print(json.dumps({"accepted": accepted}))
        else:
            print("ACCEPT" if accepted else "REJECT")
        return 0 if accepted else 1


if __name__ == "__main__":
    sys.exit(main())

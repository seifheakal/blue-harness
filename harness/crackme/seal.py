#!/usr/bin/env python3
# Carapace CrackMe — seal + verify.
#
# `seal`   writes SEAL.json = { sha256(flag), len, built_at, note } — the DIGEST
#          only. The plaintext flag is never written to the repo; a solver proves
#          a crack by presenting a string whose SHA-256 matches.
# `verify` checks a claimed flag against SEAL.json and prints GRANTED / REJECTED.
#
# This is what makes the CrackMe publishable: anyone can attempt it and verify
# their own solution, and we never ship the answer.

import sys
import json
import hashlib
import argparse
from datetime import datetime, timezone


def seal(flag, out):
    doc = {
        "sha256": hashlib.sha256(flag.encode()).hexdigest(),
        "len": len(flag),
        "built_at": datetime.now(timezone.utc).isoformat(),
        "note": "Carapace CrackMe — recover the flag whose SHA-256 equals 'sha256'. "
                "The plaintext is not published. Verify with seal.py verify.",
    }
    with open(out, "w") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
    return doc


def verify(seal_path, guess):
    with open(seal_path) as f:
        doc = json.load(f)
    return hashlib.sha256(guess.encode()).hexdigest() == doc["sha256"]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Carapace CrackMe seal/verify (digest only).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("seal", help="write SEAL.json (digest of the flag)")
    s.add_argument("--flag", required=True)
    s.add_argument("--out", required=True)

    v = sub.add_parser("verify", help="check a claimed flag against SEAL.json")
    v.add_argument("--seal", required=True)
    v.add_argument("guess")

    a = ap.parse_args(argv)
    if a.cmd == "seal":
        doc = seal(a.flag, a.out)
        print(f"sealed -> {a.out}  sha256={doc['sha256']}  len={doc['len']}")
        return 0
    if a.cmd == "verify":
        if verify(a.seal, a.guess):
            print("ACCESS GRANTED — the guess matches the sealed flag")
            return 0
        print("REJECTED — the guess does not match the sealed flag")
        return 1


if __name__ == "__main__":
    sys.exit(main())

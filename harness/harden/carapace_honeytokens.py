#!/usr/bin/env python3
# Carapace — HONEYTOKENS / canaries (Slice J): the Poison + Hallucinate play.
#
# WHAT THIS IS
#   Plants plausible, format-valid FAKE secrets (AWS-style keys, bearer tokens,
#   internal URLs, DB creds) into the compiled ELF. A naive AI-RE agent mines
#   strings and reports these as real "findings" — so it POISONS the agent's
#   output and, per Quarkslab's observation that agents confidently report
#   plausible-but-wrong results, amplifies a HALLUCINATED conclusion the attacker
#   then wastes time acting on.
#
#   Every planted token is UNIQUE per build and recorded in a PRIVATE ledger
#   (kept out of the shipped artifact). So the tokens are also an ATTRIBUTION
#   TRIPWIRE: if one ever surfaces in a leaked crack, a paste, or telemetry,
#   `check` matches it back to the exact build that leaked (canary-token pattern).
#
# PLACEMENT (post-build, binutils): a non-allocated section (default
#   .carapace_honey) — never mapped at runtime, so the program is byte-identical
#   and the tokens are provably unreferenced (pure decoys, not logic). They remain
#   visible to a whole-file `strings` / list_strings scan, which is exactly the
#   naive agent's mining path.
#
# HONESTY (CLAUDE.md §3): this DETECTS/attributes and poisons; it does NOT prevent.
#   Tier (poison / time-waste): Speed-bump — a careful analyst validates a "secret"
#     by xref/value-flow and discards one nothing references.
#   Tier (attribution tripwire): Meaningful FOR DETECTION — a unique token leaking
#     is strong evidence the build was reversed and identifies which build; but it
#     is after-the-fact, never prevention.
#   NAMED BYPASS: behavioural validation drops unreferenced tokens; and the default
#     section name is a tell, so an attacker who lists section names can skip it —
#     production should rename/randomise the section (`--section`) and, for the
#     strongest blend, compile decoys into real .rodata at build time (follow-on).
#   We NEVER claim it stops analysis, and a honeytoken is not a real secret.

import os
import sys
import json
import shutil
import random
import string
import argparse
import tempfile
import hashlib
from datetime import datetime, timezone

DEFAULT_SECTION = ".carapace_honey"
_ALNUM_UP = string.ascii_uppercase + string.digits
_B64 = string.ascii_letters + string.digits + "+/"


def _run(cmd):
    import subprocess
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed: {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout


# ---- plausible token generators (the UNIQUE body is what the ledger tracks) ---
def _aws_key(rnd):
    return "AKIA" + "".join(rnd.choice(_ALNUM_UP) for _ in range(16))


def _bearer(rnd):
    return "Bearer " + "".join(rnd.choice(_B64) for _ in range(40))


def _url(rnd):
    sub = "".join(rnd.choice(string.ascii_lowercase) for _ in range(6))
    return f"https://{sub}.internal.svc.local/v2/license/validate"


def _db(rnd):
    pw = "".join(rnd.choice(_B64.replace("/", "")) for _ in range(18))
    return f"postgres://svc_ro:{pw}@db-prod-01.internal:5432/licensing"


def _secret(rnd):
    return "sk_live_" + "".join(rnd.choice(_B64) for _ in range(32))


_KINDS = {
    "aws_key": _aws_key, "bearer": _bearer, "url": _url, "db": _db, "secret": _secret,
}
_ROTATION = ["aws_key", "url", "secret", "db", "bearer"]


def generate(count, seed, build_tag):
    rnd = random.Random(f"{seed}:{build_tag}")
    tokens = []
    for i in range(count):
        kind = _ROTATION[i % len(_ROTATION)]
        value = _KINDS[kind](rnd)
        tokens.append({
            "id": f"ht_{i:04d}",
            "kind": kind,
            "value": value,
            "sha256": hashlib.sha256(value.encode()).hexdigest(),
        })
    return tokens


def plant(src, dst, ledger_path, count, seed, build_tag, section, objcopy="objcopy"):
    tokens = generate(count, seed, build_tag)
    blob = ("\n".join(t["value"] for t in tokens) + "\n").encode()

    shutil.copy2(src, dst)      # preserve mode (+x)
    tmpdir = tempfile.mkdtemp(prefix="carapace_honey_")
    try:
        blobpath = os.path.join(tmpdir, "honey.bin")
        with open(blobpath, "wb") as f:
            f.write(blob)
        _run([objcopy, "--add-section", f"{section}={blobpath}",
              "--set-section-flags", f"{section}=noload,readonly", dst, dst])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    ledger = {
        "build_tag": build_tag,
        "planted_at": datetime.now(timezone.utc).isoformat(),
        "section": section,
        "seed": seed,
        "tokens": tokens,
    }
    with open(ledger_path, "w") as f:
        json.dump(ledger, f, indent=2, sort_keys=True)
    return ledger


def check(ledger_path, data):
    """Return the ledger tokens whose value or sha256 appears in `data`."""
    with open(ledger_path) as f:
        ledger = json.load(f)
    text = data if isinstance(data, str) else data.decode("utf-8", "replace")
    hits = []
    for t in ledger["tokens"]:
        if t["value"] in text or t["sha256"] in text:
            hits.append({"id": t["id"], "kind": t["kind"],
                         "build_tag": ledger["build_tag"]})
    return hits


def _cmd_plant(a):
    if not os.path.exists(a.src):
        raise SystemExit(f"input not found: {a.src}")
    ledger = plant(a.src, a.dst, a.ledger, a.count, a.seed, a.build_tag,
                   a.section, a.objcopy)
    print(f"[carapace-honeytokens] {a.src} -> {a.dst}")
    print(f"  planted .......... {len(ledger['tokens'])} tokens into {a.section} "
          f"(non-alloc; never mapped at runtime)")
    print(f"  private ledger ... {a.ledger}  (KEEP OUT OF THE SHIP — it is the key)")
    print(f"  build tag ........ {ledger['build_tag']}")
    print("  tier: Speed-bump (poison) / Meaningful FOR DETECTION (attribution). "
          "bypass: xref-validate + rename the section. Not prevention (CLAUDE.md §3).")
    return 0


def _cmd_check(a):
    if a.input == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(a.input, "rb") as f:
            data = f.read()
    hits = check(a.ledger, data)
    if hits:
        print(f"LEAK DETECTED — {len(hits)} honeytoken(s) from this build surfaced:")
        for h in hits:
            print(f"  {h['id']} ({h['kind']}) — build_tag={h['build_tag']}")
        return 7
    print("no honeytoken from this ledger found in the input")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Carapace honeytokens — plant plausible decoy secrets + a private "
                    "attribution ledger (poison + canary; not prevention).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plant", help="plant honeytokens into an ELF")
    p.add_argument("src"); p.add_argument("dst")
    p.add_argument("--ledger", required=True, help="private ledger JSON to write (keep out of ship)")
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--seed", default="carapace")
    p.add_argument("--build-tag", default="dev-build")
    p.add_argument("--section", default=DEFAULT_SECTION)
    p.add_argument("--objcopy", default="objcopy")
    p.set_defaults(func=_cmd_plant)

    c = sub.add_parser("check", help="did a honeytoken from a ledger leak into some data?")
    c.add_argument("--ledger", required=True)
    c.add_argument("--input", required=True, help="file to scan, or - for stdin")
    c.set_defaults(func=_cmd_check)

    a = ap.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())

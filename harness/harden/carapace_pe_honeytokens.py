#!/usr/bin/env python3
# Carapace — PE HONEYTOKENS / canaries (Slice P): the Poison + Attribution play.
#
# WHAT THIS IS
#   The PE analog of the ELF honeytoken pass (Slice J). It plants plausible,
#   format-valid FAKE secrets (AWS-style keys, bearer tokens, internal URLs, DB
#   creds) into the PE OVERLAY — in the file, never mapped into the image (see
#   carapace_pe_exhaust.py for why the overlay is the provably-non-mapped home in
#   PE). A naive AI-RE agent mines whole-file strings and reports these as real
#   "findings", POISONING its output; and because every token is UNIQUE per build
#   and recorded in a PRIVATE ledger, a token that later surfaces in a leaked crack
#   or a paste is an ATTRIBUTION tripwire back to the exact build (`check`).
#
#   The token generators are SHARED with the ELF honeytoken pass
#   (carapace_honeytokens.generate/check) so both formats agree on shape + ledger.
#
# PROOF (harness/verify/test_slice_p.sh), with NO Windows host:
#   append-only (original file is a byte-identical PREFIX; sections + SizeOfImage
#   untouched); tokens are UNIQUE + plausible (AKIA shape) + whole-file-strings
#   visible; `check` attributes a leaked token to its build and does not false-fire.
#
# HONESTY (CLAUDE.md §3): this DETECTS/attributes and poisons; it does NOT prevent.
#   Tier (poison): Speed-bump — a careful analyst xref/value-flow-validates a
#     "secret" and discards one nothing references.
#   Tier (attribution): Meaningful FOR DETECTION — a unique token leaking is strong
#     evidence a build was reversed and says which one; after-the-fact, not prevention.
#   NAMED BYPASS: behavioural validation drops unreferenced tokens; and the default
#     footer marker (__CARAPACE_PE_HONEY__, how the audit DETECTS the pass) is a tell
#     — production should rename/remove it (`--marker ""`). A honeytoken is not a
#     real secret. Appending to a SIGNED PE invalidates its signature (we WARN).

import os
import sys
import json
import argparse
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from carapace_honeytokens import generate, check as _check_tokens  # noqa: E402  (shared generators)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "audit"))
from pe_exposure_audit import PE, PEError  # noqa: E402

DEFAULT_MARKER = "__CARAPACE_PE_HONEY__"


def plant(src, dst, ledger_path, count, seed, build_tag, marker=DEFAULT_MARKER):
    pe = PE(src)                      # raises PEError on a non-PE
    with open(src, "rb") as f:
        data = f.read()
    decoy_offset = len(data)

    tokens = generate(count, seed, build_tag)
    body = "\n" + "\n".join(t["value"] for t in tokens) + "\n"
    if marker:
        body += marker + "\n"
    out = data + body.encode()

    with open(dst, "wb") as f:
        f.write(out)
    if src != dst:
        import shutil
        shutil.copymode(src, dst)

    ledger = {
        "build_tag": build_tag,
        "planted_at": datetime.now(timezone.utc).isoformat(),
        "format": "PE",
        "placement": "overlay (non-mapped)",
        "marker": marker,
        "offset": decoy_offset,
        "seed": seed,
        "tokens": tokens,
    }
    with open(ledger_path, "w") as f:
        json.dump(ledger, f, indent=2, sort_keys=True)
    ledger["_authenticode_present"] = pe.dir(4)[1] > 0
    return ledger


def _cmd_plant(a):
    if not os.path.exists(a.src):
        raise SystemExit(f"input not found: {a.src}")
    try:
        ledger = plant(a.src, a.dst, a.ledger, a.count, a.seed, a.build_tag, a.marker)
    except (PEError, IsADirectoryError) as e:
        print(f"carapace-pe-honeytokens error: {e}", file=sys.stderr)
        return 2
    print(f"[carapace-pe-honeytokens] {a.src} -> {a.dst}")
    print(f"  planted .......... {len(ledger['tokens'])} tokens into the OVERLAY at offset "
          f"{ledger['offset']} (never mapped at runtime)")
    print(f"  private ledger ... {a.ledger}  (KEEP OUT OF THE SHIP — it is the key)")
    print(f"  build tag ........ {ledger['build_tag']}")
    if ledger.get("_authenticode_present"):
        print("  WARNING: input is Authenticode-signed — appending overlay invalidates the "
              "signature. Re-sign after.")
    print("  tier: Speed-bump (poison) / Meaningful FOR DETECTION (attribution). bypass: "
          "xref-validate + rename the marker. Not prevention (CLAUDE.md §3).")
    return 0


def _cmd_check(a):
    if a.input == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(a.input, "rb") as f:
            data = f.read()
    hits = _check_tokens(a.ledger, data)
    if hits:
        print(f"LEAK DETECTED — {len(hits)} honeytoken(s) from this build surfaced:")
        for h in hits:
            print(f"  {h['id']} ({h['kind']}) — build_tag={h['build_tag']}")
        return 7
    print("no honeytoken from this ledger found in the input")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Carapace PE honeytokens — plant plausible decoy secrets into the overlay "
                    "+ a private attribution ledger (poison + canary; not prevention).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plant", help="plant honeytokens into a PE overlay")
    p.add_argument("src"); p.add_argument("dst")
    p.add_argument("--ledger", required=True, help="private ledger JSON to write (keep out of ship)")
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--seed", default="carapace")
    p.add_argument("--build-tag", default="dev-build")
    p.add_argument("--marker", default=DEFAULT_MARKER,
                   help="audit-detection footer marker; set empty for production")
    p.set_defaults(func=_cmd_plant)

    c = sub.add_parser("check", help="did a honeytoken from a ledger leak into some data?")
    c.add_argument("--ledger", required=True)
    c.add_argument("--input", required=True, help="file to scan, or - for stdin")
    c.set_defaults(func=_cmd_check)

    a = ap.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())

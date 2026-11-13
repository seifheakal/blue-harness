#!/usr/bin/env python3
# Carapace — Mach-O HONEYTOKENS / canaries (Slice Q): the Poison + Attribution play.
#
# WHAT THIS IS
#   The Mach-O analog of the ELF honeytoken pass (Slice J) and the PE one (Slice P). It
#   plants plausible, format-valid FAKE secrets (AWS-style keys, bearer tokens, internal
#   URLs, DB creds) into the Mach-O file TRAILER — past every segment/section/table the
#   file declares, so dyld never maps them (see carapace_macho_segment.py for why the
#   trailer is the provably-non-mapped home in Mach-O). A naive AI-RE agent mines
#   whole-file strings and reports these as real "findings", POISONING its output; and
#   because every token is UNIQUE per build and recorded in a PRIVATE ledger, a token
#   that later surfaces in a leaked crack or a paste is an ATTRIBUTION tripwire back to
#   the exact build (`check`).
#
#   The token generators are SHARED with the ELF + PE honeytoken passes
#   (carapace_honeytokens.generate/check) so every format agrees on shape + ledger.
#
# PROOF (harness/verify/test_slice_q.sh), with NO macOS host:
#   append-only (original file is a byte-identical PREFIX; load commands + segments
#   untouched); tokens UNIQUE + plausible (AKIA shape) + whole-file-strings visible;
#   trailer >= mapped_end (non-mapped); `check` attributes a leaked token to its build
#   and does not false-fire; unique per build.
#
# HONESTY (CLAUDE.md §3): this DETECTS/attributes and poisons; it does NOT prevent.
#   Tier (poison): Speed-bump — a careful analyst xref/value-flow-validates a "secret"
#     and discards one nothing references.
#   Tier (attribution): Meaningful FOR DETECTION — a unique token leaking is strong
#     evidence a build was reversed and says which one; after-the-fact, not prevention.
#   NAMED BYPASS: behavioural validation drops unreferenced tokens; and the default
#     footer marker (__CARAPACE_MACHO_HONEY__, how the audit DETECTS the pass) is a tell
#     — production should rename/remove it (--marker ""). A honeytoken is not a real
#     secret. Appending to a SIGNED Mach-O invalidates its signature (we WARN).

import os
import sys
import json
import argparse
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from carapace_honeytokens import generate, check as _check_tokens  # noqa: E402  (shared generators)
from carapace_macho_segment import append_trailer, SegError        # noqa: E402

DEFAULT_MARKER = "__CARAPACE_MACHO_HONEY__"


def plant(src, dst, ledger_path, count, seed, build_tag, marker=DEFAULT_MARKER):
    with open(src, "rb") as f:
        data = f.read()
    tokens = generate(count, seed, build_tag)
    body = "\n" + "\n".join(t["value"] for t in tokens) + "\n"
    if marker:
        body += marker + "\n"
    out, tinfo = append_trailer(data, body.encode())   # raises SegError on a non/fat/32-bit Mach-O

    with open(dst, "wb") as f:
        f.write(out)
    if src != dst:
        import shutil
        shutil.copymode(src, dst)

    ledger = {
        "build_tag": build_tag,
        "planted_at": datetime.now(timezone.utc).isoformat(),
        "format": "Mach-O",
        "placement": "trailer (non-mapped)",
        "marker": marker,
        "offset": tinfo["trailer_off"],
        "mapped_end": tinfo["mapped_end"],
        "non_mapped": tinfo["non_mapped"],
        "seed": seed,
        "tokens": tokens,
    }
    with open(ledger_path, "w") as f:
        json.dump(ledger, f, indent=2, sort_keys=True)
    ledger["_code_signed"] = tinfo["code_signed"]
    return ledger


def _cmd_plant(a):
    if not os.path.exists(a.src):
        raise SystemExit(f"input not found: {a.src}")
    try:
        ledger = plant(a.src, a.dst, a.ledger, a.count, a.seed, a.build_tag, a.marker)
    except (SegError, IsADirectoryError) as e:
        print(f"carapace-macho-honeytokens error: {e}", file=sys.stderr)
        return 2
    print(f"[carapace-macho-honeytokens] {a.src} -> {a.dst}")
    print(f"  planted .......... {len(ledger['tokens'])} tokens into the TRAILER at offset "
          f"{ledger['offset']} (>= mapped_end {ledger['mapped_end']} -> non-mapped={ledger['non_mapped']})")
    print(f"  private ledger ... {a.ledger}  (KEEP OUT OF THE SHIP — it is the key)")
    print(f"  build tag ........ {ledger['build_tag']}")
    if ledger.get("_code_signed"):
        print("  WARNING: input carries a code signature — appending invalidates it. "
              "Re-sign on the build host.")
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
        description="Carapace Mach-O honeytokens — plant plausible decoy secrets into the trailer "
                    "+ a private attribution ledger (poison + canary; not prevention).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plant", help="plant honeytokens into a Mach-O trailer")
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

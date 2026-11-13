#!/usr/bin/env python3
# Carapace — Slice S: the ONE-COMMAND empirical re-run driver.
#
# WHAT THIS IS
#   The 2026-11-11 Slice-K run was a parked, manual procedure (build on the scoring
#   box, hand-copy binaries into a VM, drive a throwaway agent, hand-fill JSON, then
#   score). This turns it into ONE command: drive an attacker agent against the
#   sealed CrackMe's baseline AND hardened builds, record each run, and emit the
#   honest before/after the Slice-K scorer (rea_measure.py) already defines.
#
#   It fixes the friction that blocked the 2026-11-11 run (commodity local models
#   emit tool calls as plain JSON text) by driving the agent through
#   attacker_agent.py, whose shim parses those calls (and prefers a model's native
#   tool_calls when it supplies them).
#
# HONEST BY CONSTRUCTION (CLAUDE.md §3; same gating class as the Slice-K VM note)
#   - A REAL run is OPERATOR-GATED. It needs an isolated, operator-owned VM, the
#     operator's chosen model, and the operator's hardware. This tool does NOT
#     download, serve, or bundle any model; --backend ollama only POSTs to an
#     endpoint the operator points it at, and is meant to run INSIDE that VM.
#   - --backend mock is a DETERMINISTIC, scripted brain over a REAL tool executor.
#     It proves the whole pipeline end-to-end with NO model, NO network, NO VM —
#     and it is loudly stamped "NOT A MEASUREMENT". It reports no token/wall figure,
#     so no cost number can be fabricated from it.
#   - Numbers are only ever what the agent reported; absent ones stay "not measured"
#     (the scorer never estimates). We do not fabricate.

import os
import sys
import json
import argparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import attacker_agent as aa          # noqa: E402
import rea_measure                   # noqa: E402

VARIANTS = ("baseline", "hardened")

_GATING = (
    "REAL numbers require the operator's isolated VM + chosen attacker model + "
    "hardware (same gating class as the Slice K VM note). This driver does not "
    "download or run any model; the live path POSTs to an endpoint you point it at."
)


def _make_backend(args, binary):
    if args.backend == "mock":
        return aa.MockBackend(binary)
    if args.backend == "ollama":
        return aa.OllamaBackend(args.model, endpoint=args.target)
    raise SystemExit(f"unknown backend: {args.backend}")


def _run_variant(args, variant, binary):
    backend = _make_backend(args, binary)
    rec = aa.run_agent(backend, binary, cwd=os.path.dirname(binary) or ".",
                       max_steps=args.max_steps, step_timeout=args.step_timeout)
    rec["variant"] = variant

    # Persist the transcript to a file so the scorer can scan it for honeytokens.
    tpath = os.path.join(args.out_dir, f"transcript_{variant}.txt")
    with open(tpath, "w", encoding="utf-8", errors="replace") as f:
        f.write(rec.pop("transcript"))
    rec["transcript_file"] = tpath

    rpath = os.path.join(args.out_dir, f"run_{variant}.json")
    with open(rpath, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2)
    return rpath, rec


def _dry_run(args):
    print("=" * 66)
    print("  Carapace Slice S — DRY RUN (no agent launched, no network touched)")
    print("=" * 66)
    print(f"  backend ........ {args.backend}")
    if args.backend == "ollama":
        print(f"  model .......... {args.model or '(required: --model)'}")
        print(f"  target ......... {args.target}")
        print("  tool-call path . native message.tool_calls preferred; a model that")
        print("                   only emits JSON text in `content` is handled by")
        print("                   attacker_agent.extract_tool_calls (the 2026-11-11 fix).")
    print(f"  baseline bin ... {args.baseline_bin}")
    print(f"  hardened bin ... {args.hardened_bin}")
    print(f"  seal ........... {args.seal}")
    print(f"  ledger ......... {args.ledger or '(none — honeytoken attribution off)'}")
    print(f"  out dir ........ {args.out_dir}")
    print("  " + _GATING)
    print("=" * 66)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Carapace Slice S — one-command empirical re-run (honest).")
    ap.add_argument("--backend", choices=("mock", "ollama"), default="mock")
    ap.add_argument("--model", help="attacker model name (ollama backend)")
    ap.add_argument("--target", default="http://127.0.0.1:11434",
                    help="model endpoint (ollama backend)")
    ap.add_argument("--baseline-bin", dest="baseline_bin")
    ap.add_argument("--hardened-bin", dest="hardened_bin")
    ap.add_argument("--seal", help="the CrackMe SEAL.json")
    ap.add_argument("--ledger", help="PRIVATE honeytoken ledger (attribution)")
    ap.add_argument("--out-dir", dest="out_dir", default=".")
    ap.add_argument("--max-steps", dest="max_steps", type=int, default=20)
    ap.add_argument("--step-timeout", dest="step_timeout", type=int, default=60)
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan and exit; launch nothing, touch no network")
    ap.add_argument("--json", action="store_true", help="emit the scored report as JSON")
    a = ap.parse_args(argv)

    if a.backend == "ollama" and not a.dry_run and not a.model:
        ap.error("--backend ollama requires --model")
    if a.dry_run:
        return _dry_run(a)

    for need, val in (("--baseline-bin", a.baseline_bin),
                      ("--hardened-bin", a.hardened_bin), ("--seal", a.seal)):
        if not val:
            ap.error(f"{need} is required")
    os.makedirs(a.out_dir, exist_ok=True)

    runs = []
    for variant, binary in (("baseline", a.baseline_bin),
                            ("hardened", a.hardened_bin)):
        _, rec = _run_variant(a, variant, binary)
        runs.append(rec)

    with open(a.seal) as f:
        seal = json.load(f)
    report = rea_measure.build_report(seal, runs, a.ledger)
    report["measurement_grade"] = runs[0].get("measurement_grade", "unknown")

    if a.json:
        print(json.dumps(report, indent=2))
    else:
        print(rea_measure.render(report, seal))

    # Honesty banner — always, and un-missable for a mock.
    print()
    if report["measurement_grade"] == "mock":
        print("  *** MOCK RUN — NOT A MEASUREMENT ***")
        print("  This proved the pipeline plumbing with a scripted brain over real")
        print("  tools and the real binaries. It yields NO cost numbers by design.")
    print("  " + _GATING)
    return 0


if __name__ == "__main__":
    sys.exit(main())

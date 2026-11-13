#!/usr/bin/env python3
# Carapace — Slice K empirical SCORER (honest by construction).
#
# WHAT THIS IS
#   The operator runs an AI-RE agent (e.g. rea) against the CrackMe's baseline and
#   hardened binaries on THEIR OWN sandboxed VM, records each run into a small JSON
#   (see run-template.json), and this tool turns those real artifacts into an
#   honest before/after comparison.
#
# HONEST BY CONSTRUCTION (the point of Slice K, cf. the competitive finding):
#   - It NEVER invents numbers. Token / wall-clock figures are whatever the
#     operator recorded from the agent; if a field is absent, it prints
#     "not measured" and computes no multiplier from it.
#   - It does NOT trust the agent's "I found the flag." A claimed flag is VERIFIED
#     against SEAL.json (SHA-256) — a crack counts only if it actually hashes right.
#   - It scans the agent's output for honeytokens via the PRIVATE ledger, so a
#     decoy the agent reported as a "secret" shows up as poison/attribution, not as
#     a real find.
#   - Caveats are printed, not buried: agent-reported, single VM, small-N, one
#     model — this is a measurement, not a benchmark.

import os
import sys
import json
import hashlib
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "harden"))
try:
    from carapace_honeytokens import check as honey_check  # noqa: E402
except Exception:   # pragma: no cover - honeytokens optional
    honey_check = None


def _verify(seal, guess):
    if guess is None:
        return False
    return hashlib.sha256(guess.encode()).hexdigest() == seal["sha256"]


def _text_of(run):
    parts = []
    rs = run.get("recovered_secret")
    if isinstance(rs, str):
        parts.append(rs)
    tf = run.get("transcript_file")
    if tf and os.path.exists(tf):
        with open(tf, "r", errors="replace") as f:
            parts.append(f.read())
    return "\n".join(parts)


def score_run(run, seal, ledger_path):
    cracked = _verify(seal, run.get("recovered_secret"))
    hits = []
    if ledger_path and honey_check and os.path.exists(ledger_path):
        hits = honey_check(ledger_path, _text_of(run))
    return {
        "variant": run.get("variant"),
        "agent": run.get("agent"),
        "model": run.get("model"),
        "cracked": cracked,                      # VERIFIED against the seal
        "tokens": run.get("tokens"),             # agent-reported or None
        "wall_clock_s": run.get("wall_clock_s"), # agent/operator-reported or None
        "honeytoken_hits": hits,
        # 'live' = a real agent run; 'mock' = a scripted-brain plumbing run (NOT a
        # measurement). Absent on hand-filled artifacts -> None. See slice_k_run.py.
        "measurement_grade": run.get("measurement_grade"),
    }


def _ratio(hard, base):
    if hard is None or base is None or base in (0, None):
        return None
    return round(hard / base, 1)


def build_report(seal, runs, ledger_path):
    scored = {r["variant"]: score_run(r, seal, ledger_path)
              for r in runs if r.get("variant") in ("baseline", "hardened")}
    b = scored.get("baseline")
    h = scored.get("hardened")
    deltas = {}
    if b and h:
        deltas["token_multiplier"] = _ratio(h["tokens"], b["tokens"])
        deltas["wall_multiplier"] = _ratio(h["wall_clock_s"], b["wall_clock_s"])
        deltas["cracked_baseline"] = b["cracked"]
        deltas["cracked_hardened"] = h["cracked"]
        # Slice J: attribution events recorded in the before/after (the 2026-11-11
        # 7B run never reached this — the agent was blocked upstream).
        deltas["honeytoken_attributions"] = len(h["honeytoken_hits"])
    # If any run declares itself a mock, the whole report is a plumbing run, not a
    # measurement — surfaced loudly so a cost number can never be read off it.
    grades = {s.get("measurement_grade") for s in scored.values()}
    grade = "mock" if "mock" in grades else (
        "live" if grades == {"live"} else None)
    return {"scored": scored, "deltas": deltas, "measurement_grade": grade}


def _fmt_num(x, unit=""):
    return "not measured" if x is None else f"{x}{unit}"


def render(report, seal):
    L = []
    L.append("=" * 66)
    L.append("  Carapace — empirical RE-resistance measurement (Slice K)")
    L.append(f"  flag SHA-256: {seal['sha256'][:16]}…  (len {seal.get('len','?')})")
    if report.get("measurement_grade") == "mock":
        L.append("  *** MOCK — scripted plumbing run, NOT A MEASUREMENT ***")
    L.append("=" * 66)
    sc = report["scored"]
    if not sc:
        L.append("  NO RUN ARTIFACTS YET.")
        L.append("  This harness is ready; it has nothing to report until you run an")
        L.append("  agent on a sandboxed, operator-owned VM and record the result.")
        L.append("  See docs/workflow/slice-k-empirical-runbook.md and fill")
        L.append("  harness/measure/run-template.json for each variant.")
        L.append("=" * 66)
        return "\n".join(L)
    for variant in ("baseline", "hardened"):
        r = sc.get(variant)
        if not r:
            L.append(f"  [{variant}]  (no artifact provided)")
            continue
        L.append(f"  [{variant}]  agent={r.get('agent') or '?'} model={r.get('model') or '?'}")
        L.append(f"      cracked (verified vs seal) : {'YES' if r['cracked'] else 'no'}")
        L.append(f"      tokens (agent-reported)    : {_fmt_num(r['tokens'])}")
        L.append(f"      wall-clock                 : {_fmt_num(r['wall_clock_s'],'s')}")
        if r["honeytoken_hits"]:
            ids = ", ".join(f"{x['id']}({x['kind']})" for x in r["honeytoken_hits"])
            L.append(f"      honeytokens surfaced       : {len(r['honeytoken_hits'])}  [{ids}]")
            L.append(f"          -> attributed to build  : {r['honeytoken_hits'][0]['build_tag']}")
        else:
            L.append("      honeytokens surfaced       : 0")
        L.append("")
    d = report["deltas"]
    if d:
        L.append("  DELTA (hardened vs baseline) — measured only:")
        tm = d.get("token_multiplier")
        wm = d.get("wall_multiplier")
        L.append(f"      token cost multiplier      : "
                 + ("not measured (need both token counts)" if tm is None else f"{tm}x"))
        L.append(f"      wall-clock multiplier      : "
                 + ("not measured (need both wall times)" if wm is None else f"{wm}x"))
        L.append(f"      outcome                    : baseline "
                 + ("CRACKED" if d.get("cracked_baseline") else "not cracked")
                 + " | hardened "
                 + ("CRACKED" if d.get("cracked_hardened") else "not cracked"))
        if "honeytoken_attributions" in d:
            L.append(f"      honeytoken attributions    : {d['honeytoken_attributions']}"
                     "  (Slice J — surfaced in the hardened run)")
        L.append("")
    L.append("  HONEST CAVEATS: token/wall figures are AGENT-REPORTED, from a single")
    L.append("  VM, one model, small-N — a measurement, not a benchmark. Absent data")
    L.append("  is shown as 'not measured', never estimated. A 'crack' counts only if")
    L.append("  it hashes to the sealed flag; a honeytoken reported as a secret is")
    L.append("  poison, not a find.")
    L.append("=" * 66)
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Carapace Slice K scorer — honest before/after.")
    ap.add_argument("--seal", required=True, help="the CrackMe SEAL.json")
    ap.add_argument("--ledger", help="PRIVATE honeytoken ledger (for attribution scoring)")
    ap.add_argument("--baseline", help="baseline run artifact JSON")
    ap.add_argument("--hardened", help="hardened run artifact JSON")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    with open(a.seal) as f:
        seal = json.load(f)
    runs = []
    for path in (a.baseline, a.hardened):
        if path:
            with open(path) as f:
                runs.append(json.load(f))
    report = build_report(seal, runs, a.ledger)
    if a.json:
        print(json.dumps(report, indent=2))
    else:
        print(render(report, seal))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice S (empirical re-run PACKAGING).
#
# WHAT THIS PROVES (and, honestly, what it does NOT)
#   Slice S turns the parked, manual Slice-K empirical run into ONE scored command
#   and fixes the tool-call friction that blocked the 2026-11-11 run. This test
#   proves that PACKAGING end-to-end with a DETERMINISTIC MOCK attacker — NO real
#   model, NO network, NO operator VM:
#     (A) the tool-call SHIM parses the exact JSON-as-text shape the 2026-11-11 run
#         choked on, plus format variants, prefers native tool_calls, and refuses
#         unknown tool names / injected tool-call text (pure Python — runs anywhere);
#     (B) the sealed CrackMe pair builds (ELF; CI/Linux);
#     (C) `slice_k_run.py --backend mock` drives the agent loop against the REAL
#         binaries end-to-end: baseline CRACKED (real flag lifted from the real
#         binary, verified vs the seal), hardened NOT, and the hardened run surfaces
#         a honeytoken that the scorer ATTRIBUTES — exercising Slice J, which the
#         7B run never reached;
#     (D) HONESTY guardrails fire: the output is loudly marked NOT A MEASUREMENT,
#         no cost multiplier is fabricated, and the real-run gating is stated;
#     (E) the LIVE operator path (Ollama / a reliably-tool-calling model) is wired,
#         proven statically via --dry-run (contacts nothing).
#
#   It does NOT produce an effectiveness number — that needs the operator's isolated
#   VM + chosen model + hardware (same gating as the Slice K VM note). We never
#   fabricate numbers. See docs/workflow/slice-k-empirical-runbook.md.
#
# Exit 0 = all hard assertions passed (SKIPs are non-fatal; the build-gated blocks
# SKIP on a non-ELF toolchain and run on CI/Linux).
set -u
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
CRACKME="$REPO/harness/crackme"
MEASURE="$REPO/harness/measure"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PY=python3

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP  $*"; SKIP=$((SKIP+1)); }
hdr()  { echo; echo "== $* =="; }

# --------------------------------------------------------------------------- #
hdr "(A) tool-call SHIM — parses the 2026-11-11 JSON-as-text case + variants"
cat > "$WORK/shim_test.py" <<'PYEOF'
import sys, os
sys.path.insert(0, os.environ["MEASURE"])
import attacker_agent as aa

def case(desc, got, want):
    print(("PASS" if got == want else "FAIL"),
          desc + ("" if got == want else f"  (got={got!r} want={want!r})"))

# the exact 2026-11-11 failure: a tool call as plain content, no tool_calls field
case("shim: JSON tool call as plain text (the 2026-11-11 blocker)",
     [c["command"] for c in aa.extract_tool_calls(
        {"content": 'Let me look.\n{"name":"run_shell","arguments":{"command":"strings x"}}',
         "tool_calls": None})],
     ["strings x"])
# fenced ```json block
case("shim: fenced ```json block",
     [c["command"] for c in aa.extract_tool_calls('```json\n{"name":"shell","arguments":{"command":"nm a"}}\n```')],
     ["nm a"])
# native tool_calls win (OpenAI shape, arguments as a JSON string)
case("shim: native tool_calls preferred (args-as-string)",
     [c["command"] for c in aa.extract_tool_calls(
        {"content": "", "tool_calls": [{"type":"function","function":{"name":"shell","arguments":"{\"command\":\"file a\"}"}}]})],
     ["file a"])
# <tool_call> XML wrapper (Qwen/Hermes) around JSON
case("shim: <tool_call>-wrapped JSON",
     [c["command"] for c in aa.extract_tool_calls('<tool_call>{"name":"shell","arguments":{"command":"objdump -d a"}}</tool_call>')],
     ["objdump -d a"])
# tool+parameters+cmd synonyms, embedded in prose
case("shim: tool/parameters/cmd synonyms, mid-prose",
     [c["command"] for c in aa.extract_tool_calls('I run {"tool":"bash","parameters":{"cmd":"readelf -h a"}} now')],
     ["readelf -h a"])
# an unknown tool NAME is dropped (declared-tools allowlist, per the research note)
case("shim: unknown tool name dropped (allowlist)",
     aa.extract_tool_calls('{"name":"search_web","arguments":{"query":"x"}}'),
     [])
# injection-safety: a bare honeytoken-looking string is not a command
case("shim: honeytoken-shaped text is not a tool call",
     aa.extract_tool_calls("AKIAABCDEFGHIJKLMNOP is a key"),
     [])
# final-answer extraction
case("shim: final FLAG= extraction",
     aa.extract_final_answer("done. FLAG=CARA{abc}"), "CARA{abc}")
PYEOF
MEASURE="$MEASURE" "$PY" "$WORK/shim_test.py" > "$WORK/shim.out" 2>&1 || true
if grep -q Traceback "$WORK/shim.out"; then
    bad "shim test crashed"; cat "$WORK/shim.out" | sed 's/^/      /'
else
    while IFS= read -r line; do
        case "$line" in
            PASS\ *) ok "${line#PASS }";;
            FAIL\ *) bad "${line#FAIL }";;
        esac
    done < "$WORK/shim.out"
fi

# --------------------------------------------------------------------------- #
hdr "(B) build the sealed CrackMe pair (ELF; CI/Linux)"
FLAG='CARA{verify-s-7e3a-not-a-real-secret}'
BD="$CRACKME/build"
BUILT=0
rm -rf "$BD"
if CARAPACE_CRACKME_SECRET="$FLAG" bash "$CRACKME/build_crackme.sh" > "$WORK/build.log" 2>&1; then
    BASE="$BD/crackme_baseline"; HARD="$BD/crackme_hardened"
    if [ -x "$BASE" ] && [ -x "$HARD" ] && \
       "$PY" -c "import sys;sys.exit(0 if open(sys.argv[1],'rb').read(4)==b'\x7fELF' else 1)" "$BASE"; then
        ok "built baseline + hardened pair (ELF) + seal"
        BUILT=1
    else
        skip "build produced a non-ELF (local toolchain, e.g. MinGW PE) — (C)/(D) are CI-only"
    fi
else
    skip "crackme build unavailable here (needs cc) — (C)/(D) are CI-only"
fi

# --------------------------------------------------------------------------- #
hdr "(C) MOCK pipeline end-to-end — no model, no network, no VM"
if [ "$BUILT" = 1 ]; then
    SEAL="$BD/SEAL.json"; LEDGER="$BD/crackme_hardened.honey-ledger.json"
    OUT="$WORK/out"
    "$PY" "$MEASURE/slice_k_run.py" --backend mock \
        --baseline-bin "$BASE" --hardened-bin "$HARD" \
        --seal "$SEAL" --ledger "$LEDGER" --out-dir "$OUT" > "$WORK/report.txt" 2>&1 \
        && ok "slice_k_run.py --backend mock ran the full before/after" \
        || { bad "mock runner failed"; cat "$WORK/report.txt" | sed 's/^/      /'; }
    [ -f "$OUT/run_baseline.json" ] && [ -f "$OUT/run_hardened.json" ] \
        && ok "wrote run_baseline.json + run_hardened.json" || bad "run artifacts missing"
    grep -q "baseline CRACKED | hardened not cracked" "$WORK/report.txt" \
        && ok "baseline CRACKED, hardened NOT (verified vs the seal)" || bad "wrong crack outcome"
    # the baseline 'crack' is real: the recovered string hashes to the sealed flag
    "$PY" - "$OUT/run_baseline.json" "$SEAL" <<'PY2' && ok "baseline recovered_secret hashes to SEAL.json (a genuine crack)" || bad "baseline recovered_secret does not match the seal"
import json,hashlib,sys
run=json.load(open(sys.argv[1])); seal=json.load(open(sys.argv[2]))
sys.exit(0 if run.get("recovered_secret") and
         hashlib.sha256(run["recovered_secret"].encode()).hexdigest()==seal["sha256"] else 1)
PY2
    # Slice J: the hardened run surfaced a honeytoken the scorer attributed
    grep -Eq "honeytoken attributions    : [1-9]" "$WORK/report.txt" \
        && ok "Slice J: honeytoken surfaced in the hardened run + attributed (the 7B run never reached this)" \
        || bad "no honeytoken attribution recorded"
    # and the hardened 'find' is a decoy, NOT the real flag
    "$PY" - "$OUT/run_hardened.json" "$SEAL" <<'PY3' && ok "hardened 'find' is a decoy (does NOT hash to the seal)" || bad "hardened find unexpectedly matched the seal"
import json,hashlib,sys
run=json.load(open(sys.argv[1])); seal=json.load(open(sys.argv[2]))
rs=run.get("recovered_secret")
sys.exit(0 if (rs is None or hashlib.sha256(rs.encode()).hexdigest()!=seal["sha256"]) else 1)
PY3
else
    skip "(C) pipeline — build-gated (CI/Linux)"; skip "(C) artifacts — build-gated"
    skip "(C) crack outcome — build-gated"; skip "(C) real crack vs seal — build-gated"
    skip "(C) Slice J attribution — build-gated"; skip "(C) decoy-not-seal — build-gated"
fi

# --------------------------------------------------------------------------- #
hdr "(D) HONESTY guardrails — never a fabricated number"
if [ "$BUILT" = 1 ]; then
    grep -q "NOT A MEASUREMENT" "$WORK/report.txt" \
        && ok "output is loudly marked NOT A MEASUREMENT" || bad "mock output not marked"
    grep -q "not measured (need both token counts)" "$WORK/report.txt" \
        && ok "no cost multiplier fabricated — prints 'not measured'" || bad "a multiplier was fabricated"
    grep -q "require the operator's isolated VM" "$WORK/report.txt" \
        && ok "states real numbers need the operator VM + model + hardware" || bad "missing real-run gating"
    "$PY" - "$WORK/out/run_baseline.json" <<'PY4' && ok "run JSON carries measurement_grade=mock + null tokens (not a measurement)" || bad "mock run JSON not honestly stamped"
import json,sys
r=json.load(open(sys.argv[1]))
sys.exit(0 if r.get("measurement_grade")=="mock" and r.get("tokens") is None and r.get("wall_clock_s") is None else 1)
PY4
else
    skip "(D) NOT-A-MEASUREMENT mark — build-gated"; skip "(D) no fabricated multiplier — build-gated"
    skip "(D) real-run gating — build-gated"; skip "(D) honest run-JSON stamp — build-gated"
fi

# --------------------------------------------------------------------------- #
hdr "(E) the LIVE operator path is wired (static; no model, no network)"
"$PY" "$MEASURE/slice_k_run.py" --backend ollama --model qwen2.5-coder:7b \
    --target http://127.0.0.1:1 --dry-run > "$WORK/dry.txt" 2>&1 \
    && ok "ollama --dry-run exits 0 and contacts nothing" || bad "dry-run failed"
grep -q "native message.tool_calls preferred" "$WORK/dry.txt" \
    && ok "dry-run documents native-first + shim tool-call path (the 2026-11-11 fix)" || bad "no tool-call path note"
grep -q "require the operator's isolated VM" "$WORK/dry.txt" \
    && ok "dry-run states the real run is operator-VM-gated" || bad "no gating note in dry-run"
MEASURE="$MEASURE" "$PY" -c "import os,sys;sys.path.insert(0,os.environ['MEASURE']);import attacker_agent as a;sys.exit(0 if hasattr(a,'OllamaBackend') and a.OllamaBackend.grade=='live' else 1)" \
    && ok "OllamaBackend present (live grade; prefers native tool_calls)" || bad "OllamaBackend missing"

rm -rf "$BD"   # keep the tree clean

hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
echo "  (packaging + friction fix proven with a MOCK attacker; the effectiveness"
echo "   number still needs the operator VM run — runbook. We never fabricate it.)"
[ "$FAIL" -eq 0 ] && { echo "  SLICE S VERIFIED"; exit 0; } || { echo "  SLICE S HAS FAILURES"; exit 1; }

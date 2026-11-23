#!/usr/bin/env bash
# blue-harness — VERIFY harness for Slice S (empirical re-run PACKAGING).
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
#         proven statically via --dry-run (contacts nothing);
#     (F) ISOLATION: the attacker's shell never sees BH_CRACKME_SECRET (scrubbed,
#         allowlisted env) and starts in a private arena holding ONLY its binary —
#         SEAL.json and the private honey-ledger are not reachable from its cwd;
#     (G) REPEATS: --runs N writes each before/after to its own run-NN/ dir (no
#         overwrite) plus a counts-only summary.json.
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
if BH_CRACKME_SECRET="$FLAG" bash "$CRACKME/build_crackme.sh" > "$WORK/build.log" 2>&1; then
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
    "$PY" "$MEASURE/slice_k_run.py" --backend mock --json \
        --baseline-bin "$BASE" --hardened-bin "$HARD" \
        --seal "$SEAL" --ledger "$LEDGER" --out-dir "$WORK/out_json" \
        > "$WORK/json.out" 2> "$WORK/json.err" \
        && "$PY" -c 'import json,sys; json.load(open(sys.argv[1]))' "$WORK/json.out" \
        && grep -q "NOT A MEASUREMENT" "$WORK/json.err" \
        && ok "--json: stdout is pure JSON; the NOT A MEASUREMENT banner moves to stderr" \
        || bad "--json stdout is not parseable JSON, or the banner was dropped"
else
    skip "(D) NOT-A-MEASUREMENT mark — build-gated"; skip "(D) no fabricated multiplier — build-gated"
    skip "(D) real-run gating — build-gated"; skip "(D) honest run-JSON stamp — build-gated"
    skip "(D) --json stays parseable — build-gated"
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

# --------------------------------------------------------------------------- #
hdr "(F) ISOLATION — no flag in the agent env, no seal/ledger in its arena"
cat > "$WORK/iso_test.py" <<'PYEOF'
import os, sys, stat
sys.path.insert(0, os.environ["MEASURE"])
import attacker_agent as aa
import slice_k_run as skr

SECRET = "CARA{iso-probe-not-a-real-secret}"
os.environ["BH_CRACKME_SECRET"] = SECRET
os.environ["BH_SOME_TOKEN"] = "tok-should-not-leak"

def case(desc, cond):
    print(("PASS " if cond else "FAIL ") + desc)

env = aa.agent_env("/tmp/x")
case("agent_env drops BH_CRACKME_SECRET", "BH_CRACKME_SECRET" not in env)
case("agent_env is an allowlist (unknown vars dropped)", "BH_SOME_TOKEN" not in env)
case("agent_env points HOME at the arena", env.get("HOME") == "/tmp/x")
r = aa.run_shell("env")
case("run_shell default env hides the flag even when exported", SECRET not in r["output"])

# a fake build dir: binary + seal + PRIVATE ledger side by side (as build/ is)
build = os.path.join(os.environ["WORK"], "fakebuild")
os.makedirs(build)
for n in ("crackme_hardened", "SEAL.json", "crackme_hardened.honey-ledger.json"):
    open(os.path.join(build, n), "w").write("x")
arena, staged = skr._stage_arena(os.path.join(build, "crackme_hardened"),
                                 os.environ["WORK"])
case("arena holds ONLY the staged binary", os.listdir(arena) == ["crackme_hardened"])
case("arena is private (0700)", stat.S_IMODE(os.stat(arena).st_mode) == 0o700)

class Probe:
    """Scripted brain that does what a curious strong model would: dump env, list
    the cwd and home. The loop runs these for real inside the arena."""
    grade = "mock"
    def __init__(self): self.n = 0
    def chat(self, messages, tools=None):
        self.n += 1
        if self.n == 1:
            return {"content": '{"name":"shell","arguments":{"command":"env; ls -A; ls -A ~"}}',
                    "tool_calls": None, "usage": None}
        return {"content": "FLAG=none", "tool_calls": None, "usage": None}

rec = aa.run_agent(Probe(), staged, cwd=arena, env=aa.agent_env(arena), max_steps=3)
t = rec["transcript"]
case("probe agent: flag absent from its env dump", SECRET not in t)
case("probe agent: ledger not visible from its cwd/home", "honey-ledger" not in t)
case("probe agent: SEAL.json not visible from its cwd/home", "SEAL.json" not in t)
case("probe agent: it did see its own binary", "crackme_hardened" in t)
PYEOF
MEASURE="$MEASURE" WORK="$WORK" "$PY" "$WORK/iso_test.py" > "$WORK/iso.out" 2>&1 || true
if grep -q Traceback "$WORK/iso.out"; then
    bad "isolation test crashed"; sed 's/^/      /' "$WORK/iso.out"
else
    while IFS= read -r line; do
        case "$line" in
            PASS\ *) ok "${line#PASS }";;
            FAIL\ *) bad "${line#FAIL }";;
        esac
    done < "$WORK/iso.out"
fi

# --------------------------------------------------------------------------- #
hdr "(G) REPEATS — --runs 2 keeps every run's artifacts"
if [ "$BUILT" = 1 ]; then
    OUT2="$WORK/out2"
    BH_CRACKME_SECRET="$FLAG" "$PY" "$MEASURE/slice_k_run.py" --backend mock --runs 2 \
        --baseline-bin "$BASE" --hardened-bin "$HARD" \
        --seal "$SEAL" --ledger "$LEDGER" --out-dir "$OUT2" > "$WORK/report2.txt" 2>&1 \
        && ok "--runs 2 completed" \
        || { bad "--runs 2 failed"; sed 's/^/      /' "$WORK/report2.txt"; }
    for i in 01 02; do
        [ -f "$OUT2/run-$i/run_baseline.json" ] && [ -f "$OUT2/run-$i/run_hardened.json" ] \
            && [ -f "$OUT2/run-$i/report.json" ] \
            && ok "run-$i/ has its own run_*.json + report.json" || bad "run-$i artifacts missing"
    done
    [ -f "$OUT2/summary.json" ] && grep -q "SUMMARY across 2 runs" "$WORK/report2.txt" \
        && ok "summary.json written + summary printed" || bad "no multi-run summary"
    grep -q "baseline cracked ............ 2/2" "$WORK/report2.txt" \
        && grep -q "hardened cracked ............ 0/2" "$WORK/report2.txt" \
        && ok "summary counts: baseline 2/2, hardened 0/2 (verified vs the seal)" \
        || bad "wrong summary counts"
    ! grep -q "$FLAG" "$OUT2/run-01/transcript_hardened.txt" \
        && ok "hardened transcript never contains the real flag (env scrubbed)" \
        || bad "real flag leaked into the hardened transcript"
else
    skip "(G) --runs 2 — build-gated"; skip "(G) run-01 — build-gated"
    skip "(G) run-02 — build-gated"; skip "(G) summary — build-gated"
    skip "(G) summary counts — build-gated"; skip "(G) no flag leak — build-gated"
fi

rm -rf "$BD"   # keep the tree clean

hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
echo "  (packaging + friction fix proven with a MOCK attacker; the effectiveness"
echo "   number still needs the operator VM run — runbook. We never fabricate it.)"
[ "$FAIL" -eq 0 ] && { echo "  SLICE S VERIFIED"; exit 0; } || { echo "  SLICE S HAS FAILURES"; exit 1; }

#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice K (empirical measurement PLUMBING).
#
# IMPORTANT: this proves the harness MECHANICS, NOT the AI-layer effectiveness
# claim. No agent and no `rea` run here (that is operator-gated — a sandboxed,
# operator-owned VM; see docs/workflow/slice-k-empirical-runbook.md). We verify:
#   (A) the CrackMe builds a matched pair and both enforce the flag correctly;
#   (B) the SEAL is digest-only and seal/verify round-trips (crack verifiable
#       without shipping the plaintext);
#   (C) the hardening actually took: flag plaintext is in the BASELINE static view
#       but GONE from the HARDENED one, which also carries honeytokens + exhaustion;
#   (D) the scorer is HONEST: it verifies a crack against the seal (a honeytoken is
#       NOT a crack), attributes a surfaced honeytoken, computes multipliers only
#       from real inputs, and prints "not measured" for absent data.
#
# Exit 0 = all hard assertions passed.
set -u
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
CRACKME="$REPO/harness/crackme"
MEASURE="$REPO/harness/measure"
AUDIT="$REPO/harness/audit/elf_exposure_audit.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()  { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "== $* =="; }

FLAG='CARA{verify-k-9d2c}'
BD="$CRACKME/build"

hdr "(A) BUILD the matched pair + flag enforcement"
rm -rf "$BD"
CARAPACE_CRACKME_SECRET="$FLAG" bash "$CRACKME/build_crackme.sh" >/dev/null 2>&1 \
    && ok "build_crackme.sh produced the pair + seal" || { bad "crackme build failed"; exit 1; }
BASE="$BD/crackme_baseline"; HARD="$BD/crackme_hardened"
[ -x "$BASE" ] && [ -x "$HARD" ] && ok "baseline + hardened binaries present" || bad "a crackme binary is missing"
"$BASE" "$FLAG"  | grep -q GRANTED && ok "baseline GRANTS the correct flag" || bad "baseline rejected the correct flag"
"$BASE" "wrong"  | grep -q DENIED  && ok "baseline DENIES a wrong flag"      || bad "baseline accepted a wrong flag"
"$HARD" "$FLAG"  | grep -q GRANTED && ok "hardened GRANTS the correct flag (behaviour preserved)" || bad "hardened rejected the correct flag"
"$HARD" "wrong"  | grep -q DENIED  && ok "hardened DENIES a wrong flag"      || bad "hardened accepted a wrong flag"

hdr "(B) SEAL is digest-only + seal/verify round-trips"
python3 -c "import json,hashlib,sys; d=json.load(open('$BD/SEAL.json')); sys.exit(0 if d['sha256']==hashlib.sha256('$FLAG'.encode()).hexdigest() else 1)" \
    && ok "SEAL.json sha256 == sha256(flag)" || bad "seal digest mismatch"
grep -aqF "$FLAG" "$BD/SEAL.json" && bad "plaintext flag leaked into SEAL.json" || ok "SEAL.json carries no plaintext flag"
python3 "$CRACKME/seal.py" verify --seal "$BD/SEAL.json" "$FLAG"  >/dev/null 2>&1 && ok "seal verify GRANTS the real flag" || bad "seal verify rejected the real flag"
python3 "$CRACKME/seal.py" verify --seal "$BD/SEAL.json" "nope"   >/dev/null 2>&1 && bad "seal verify accepted a wrong flag" || ok "seal verify REJECTS a wrong flag"

hdr "(C) the hardening took (flag gone; honeytokens + exhaustion present)"
grep -aqF "$FLAG" "$BASE" && ok "baseline: flag plaintext IS in the static view (control)" || bad "baseline flag not found (control broken)"
grep -aqF "$FLAG" "$HARD" && bad "hardened: flag plaintext STILL in the static view" || ok "hardened: flag plaintext GONE from the static view (string-encrypted)"
python3 "$AUDIT" --json "$HARD" > "$WORK/a.json"
python3 -c "import json;d=json.load(open('$WORK/a.json'));import sys;sys.exit(0 if d['honeytokens_present'] else 1)" && ok "hardened carries honeytokens" || bad "no honeytokens in hardened"
python3 -c "import json;d=json.load(open('$WORK/a.json'));import sys;sys.exit(0 if d['exhaustion_present'] else 1)" && ok "hardened carries analysis-surface exhaustion" || bad "no exhaustion in hardened"
[ -f "$BD/crackme_hardened.honey-ledger.json" ] && ok "private honeytoken ledger written (attribution key)" || bad "no honey ledger"

hdr "(D) the scorer is honest (verifies crack, attributes honeytoken, no invented numbers)"
LEDGER="$BD/crackme_hardened.honey-ledger.json"
HTOK="$(python3 -c "import json;print(json.load(open('$LEDGER'))['tokens'][0]['value'])")"
# baseline run: cracked the REAL flag
python3 -c "import json;json.dump({'variant':'baseline','agent':'rea','model':'m','tokens':4000,'wall_clock_s':20,'recovered_secret':'$FLAG','transcript_file':None},open('$WORK/rb.json','w'))"
# hardened run: agent reported a HONEYTOKEN as the flag (a hallucinated 'find'), burned 10x
python3 -c "import json,sys;json.dump({'variant':'hardened','agent':'rea','model':'m','tokens':40000,'wall_clock_s':300,'recovered_secret':sys.argv[1],'transcript_file':None},open('$WORK/rh.json','w'))" "$HTOK"
python3 "$MEASURE/rea_measure.py" --seal "$BD/SEAL.json" --ledger "$LEDGER" \
    --baseline "$WORK/rb.json" --hardened "$WORK/rh.json" > "$WORK/report.txt" 2>&1
grep -q "baseline CRACKED | hardened not cracked" "$WORK/report.txt" \
    && ok "scorer verifies the crack vs the seal (honeytoken is NOT a crack)" || bad "scorer crack-verification wrong"
grep -q "honeytokens surfaced       : 1" "$WORK/report.txt" \
    && ok "scorer attributes the surfaced honeytoken" || bad "scorer missed the honeytoken"
grep -q "token cost multiplier      : 10.0x" "$WORK/report.txt" \
    && ok "scorer computes the token multiplier from real inputs (10.0x)" || bad "scorer multiplier wrong"
# absent data -> 'not measured', never invented
python3 -c "import json;json.dump({'variant':'hardened','agent':'rea','model':'m','tokens':None,'wall_clock_s':None,'recovered_secret':None,'transcript_file':None},open('$WORK/rh2.json','w'))"
python3 "$MEASURE/rea_measure.py" --seal "$BD/SEAL.json" --baseline "$WORK/rb.json" --hardened "$WORK/rh2.json" > "$WORK/report2.txt" 2>&1
grep -q "not measured" "$WORK/report2.txt" && ok "scorer prints 'not measured' for absent data (never invents)" || bad "scorer did not honor missing data"
# no artifacts at all -> readiness state, no numbers
python3 "$MEASURE/rea_measure.py" --seal "$BD/SEAL.json" > "$WORK/report3.txt" 2>&1
grep -q "NO RUN ARTIFACTS YET" "$WORK/report3.txt" && ok "scorer reports a clean readiness state with no data" || bad "no readiness state"

rm -rf "$BD"   # keep the tree clean

hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
echo "  (plumbing only — the effectiveness claim needs the operator VM run: runbook)"
[ "$FAIL" -eq 0 ] && { echo "  SLICE K VERIFIED"; exit 0; } || { echo "  SLICE K HAS FAILURES"; exit 1; }

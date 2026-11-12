#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice J (honeytokens / canaries: Poison + attribution).
#
# Proves, on a real sample ELF, that honeytoken planting:
#   (A) the AUDIT flips absent<->present and counts the planted tokens;
#   (B) tokens are PLAUSIBLE + UNIQUE and STRINGS-VISIBLE (a naive agent mines them);
#   (C) is NON-BREAKING: runtime byte-identical, app still runs, exports untouched,
#       and the tokens are provably inert (non-alloc section, unreferenced decoys);
#   (D) the ATTRIBUTION tripwire works: `check` matches a leaked token back to its
#       build and never false-positives, and tokens are unique per build;
#   (E) is DETERMINISTIC (reproducible builds + ledger).
#
# Honeytokens DETECT/attribute + poison; they do not prevent (CLAUDE.md §3). This
# verifies the mechanism, not an effectiveness claim.
#
# Exit 0 = all hard assertions passed.
set -u
cd "$(dirname "$0")"
SAMPLE_DIR="$(cd ../sample && pwd)"
AUDIT="$(cd ../audit && pwd)/elf_exposure_audit.py"
HONEY="$(cd ../harden && pwd)/carapace_honeytokens.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()  { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "== $* =="; }
jget() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

N=10

hdr "BUILD + PLANT"
make -C "$SAMPLE_DIR" sample_dev >/dev/null 2>&1 && ok "sample_dev (clean baseline) built" || { bad "build failed"; exit 1; }
BASE="$SAMPLE_DIR/sample_dev"
HON="$WORK/sample_honey"
python3 "$HONEY" plant "$BASE" "$HON" --ledger "$WORK/ledger.json" --count "$N" \
    --build-tag "verify-A" --seed s1 >/dev/null 2>&1 \
    && ok "planted $N honeytokens + wrote private ledger" || { bad "plant failed"; exit 1; }

hdr "(A) AUDIT flips absent<->present and counts"
python3 "$AUDIT" --json "$BASE" > "$WORK/a_base.json"
python3 "$AUDIT" --json "$HON"  > "$WORK/a_hon.json"
[ "$(jget "$WORK/a_base.json" honeytokens_present)" = "False" ] && ok "baseline: honeytokens ABSENT" || bad "baseline should be absent"
[ "$(jget "$WORK/a_hon.json"  honeytokens_present)" = "True"  ] && ok "planted: honeytokens PRESENT" || bad "planted should be present"
[ "$(jget "$WORK/a_hon.json"  honeytoken_count)" = "$N" ] && ok "audit counts $N honeytokens" || bad "count wrong"

hdr "(B) tokens plausible, unique, strings-visible"
# every token value unique + the aws_key kind matches a real AWS-key shape
python3 - "$WORK/ledger.json" <<'PY' && ok "token values unique + aws_key shape plausible (AKIA[A-Z0-9]{16})" || bad "token plausibility/uniqueness failed"
import json,re,sys
t=json.load(open(sys.argv[1]))["tokens"]
vals=[x["value"] for x in t]
assert len(set(vals))==len(vals), "not unique"
aws=[x["value"] for x in t if x["kind"]=="aws_key"]
assert aws and all(re.fullmatch(r"AKIA[A-Z0-9]{16}", v) for v in aws), "aws shape"
PY
TOK="$(python3 -c "import json;print(json.load(open('$WORK/ledger.json'))['tokens'][0]['value'])")"
grep -aF "$TOK" "$HON" >/dev/null && ok "a planted token is visible to a strings/list_strings scan" || bad "token not visible in static view"

hdr "(C) NON-BREAKING + provably inert"
out_base="$("$BASE")"; out_hon="$("$HON")"
[ "$out_base" = "$out_hon" ] && ok "runtime output byte-identical (\"$out_hon\")" || bad "runtime differs: '$out_base' vs '$out_hon'"
case "$out_hon" in *"ran OK"*) ok "planted sample still runs cleanly";; *) bad "planted sample did not run: $out_hon";; esac
readelf -WsD "$BASE" 2>/dev/null > "$WORK/d0.txt"; readelf -WsD "$HON" 2>/dev/null > "$WORK/d1.txt"
cmp -s "$WORK/d0.txt" "$WORK/d1.txt" && ok "exports (.dynsym) byte-identical — dynamic linking intact" || bad "dynsym changed"
# the honey section must be NON-ALLOC (never mapped => unreferenced pure decoy)
python3 - "$HON" "$AUDIT" <<'PY' && ok "honeytoken section is non-alloc (never mapped; inert decoy)" || bad "honey section is allocated"
import sys,os
sys.path.insert(0, os.path.dirname(sys.argv[2]))
from elf_exposure_audit import ELF
elf=ELF(sys.argv[1]); SHF_ALLOC=0x2
sh=elf.sections.get(".carapace_honey")
sys.exit(0 if sh and not (sh["flags"] & SHF_ALLOC) else 1)
PY

hdr "(D) ATTRIBUTION tripwire"
# a leaked paste containing a token -> check names the token id + build tag (rc 7)
printf 'dumped creds from the crack: %s\n' "$TOK" > "$WORK/leak.txt"
python3 "$HONEY" check --ledger "$WORK/ledger.json" --input "$WORK/leak.txt" > "$WORK/hit.txt" 2>&1
rc=$?
[ "$rc" -eq 7 ] && grep -q "LEAK DETECTED" "$WORK/hit.txt" && ok "leak of a token is detected + attributed to its build" || bad "attribution failed (rc=$rc)"
# clean input -> no hit (rc 0), no false positive
echo "nothing sensitive here" > "$WORK/clean.txt"
python3 "$HONEY" check --ledger "$WORK/ledger.json" --input "$WORK/clean.txt" >/dev/null 2>&1
[ "$?" -eq 0 ] && ok "no false positive on clean input" || bad "false positive on clean input"
# a DIFFERENT build's tokens differ -> a leak is attributable to ONE build
python3 "$HONEY" plant "$BASE" "$WORK/sample_honey_B" --ledger "$WORK/ledgerB.json" \
    --count "$N" --build-tag "verify-B" --seed s1 >/dev/null 2>&1
python3 "$HONEY" check --ledger "$WORK/ledgerB.json" --input "$WORK/leak.txt" >/dev/null 2>&1
[ "$?" -eq 0 ] && ok "build-B ledger does NOT match build-A's token (unique per build)" || bad "token collided across builds"

hdr "(E) DETERMINISTIC"
python3 "$HONEY" plant "$BASE" "$WORK/sample_honey_2" --ledger "$WORK/ledger2.json" \
    --count "$N" --build-tag "verify-A" --seed s1 >/dev/null 2>&1
cmp -s "$HON" "$WORK/sample_honey_2" && ok "two plants (same seed+tag) are byte-identical" || bad "plant not deterministic"

hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "  SLICE J VERIFIED"; exit 0; } || { echo "  SLICE J HAS FAILURES"; exit 1; }

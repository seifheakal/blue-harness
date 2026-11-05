#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice I (analysis-surface EXHAUSTION).
#
# Proves, on a real sample ELF, that the exhaustion pass:
#   (A) the AUDIT flips absent<->present and MEASURES the inflated surface;
#   (B) is NON-BREAKING: runtime output byte-identical, app still runs, and the
#       dynamic surface (exports / .dynsym) is untouched;
#   (C) the decoy sections are NON-ALLOCATED (never mapped at runtime) and the
#       synthetic symbols are LOCAL + .symtab-only (not exported);
#   (D) is DETERMINISTIC (reproducible builds).
#
# This is the honest version of a peer's size-diff "verify": we prove the cost is
# added to the analyst's surface, not to the program (CLAUDE.md §4: done = tested).
#
# Exit 0 = all hard assertions passed.
set -u
cd "$(dirname "$0")"
SAMPLE_DIR="$(cd ../sample && pwd)"
AUDIT="$(cd ../audit && pwd)/elf_exposure_audit.py"
EXHAUST="$(cd ../harden && pwd)/carapace_exhaust.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()  { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "== $* =="; }
jget() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

NSEC=4; SSZ=131072; NSYM=300

hdr "BUILD + EXHAUST"
make -C "$SAMPLE_DIR" sample_dev >/dev/null 2>&1 && ok "sample_dev (clean baseline) built" || { bad "build failed"; exit 1; }
BASE="$SAMPLE_DIR/sample_dev"
EXH="$WORK/sample_exhausted"
python3 "$EXHAUST" "$BASE" "$EXH" --sections "$NSEC" --section-size "$SSZ" --symbols "$NSYM" >/dev/null 2>&1 \
    && ok "exhaustion pass produced a binary" || { bad "exhaust tool failed"; exit 1; }

# -------------------------------------------------- (A) audit flips + measures
hdr "(A) AUDIT flips absent<->present and measures the surface"
python3 "$AUDIT" --json "$BASE" > "$WORK/a_base.json"
python3 "$AUDIT" --json "$EXH"  > "$WORK/a_exh.json"
[ "$(jget "$WORK/a_base.json" exhaustion_present)" = "False" ] && ok "baseline: exhaustion ABSENT" || bad "baseline should be absent"
[ "$(jget "$WORK/a_exh.json"  exhaustion_present)" = "True"  ] && ok "exhausted: exhaustion PRESENT" || bad "exhausted should be present"
[ "$(jget "$WORK/a_exh.json" exhaust_synth_symbols)" = "$NSYM" ] && ok "audit counts $NSYM synthetic symbols" || bad "synth symbol count wrong"
[ "$(jget "$WORK/a_exh.json" exhaust_decoy_bytes)" = "$((NSEC*SSZ))" ] && ok "audit measures $((NSEC*SSZ)) decoy bytes" || bad "decoy byte count wrong"
# non-alloc ratio must jump well past the baseline (.comment only)
python3 - "$WORK/a_base.json" "$WORK/a_exh.json" <<'PY' && ok "non-alloc byte ratio jumps (baseline -> exhausted)" || bad "non-alloc ratio did not jump"
import json,sys
b=json.load(open(sys.argv[1]))["nonalloc_byte_ratio"]; e=json.load(open(sys.argv[2]))["nonalloc_byte_ratio"]
sys.exit(0 if e > b + 0.5 else 1)
PY

# -------------------------------------------------- (B) non-breaking ----------
hdr "(B) NON-BREAKING (runtime identical, still runs, exports intact)"
out_base="$("$BASE")"; out_exh="$("$EXH")"
[ "$out_base" = "$out_exh" ] && ok "runtime output byte-identical (\"$out_exh\")" || bad "runtime output differs: '$out_base' vs '$out_exh'"
case "$out_exh" in *"ran OK"*) ok "exhausted sample still runs cleanly";; *) bad "exhausted sample did not run: $out_exh";; esac
# exports / dynamic symbol table must be untouched (dynamic linking intact)
readelf -WsD "$BASE" 2>/dev/null > "$WORK/dyn_base.txt"
readelf -WsD "$EXH"  2>/dev/null > "$WORK/dyn_exh.txt"
cmp -s "$WORK/dyn_base.txt" "$WORK/dyn_exh.txt" && ok "exports (.dynsym) byte-identical — dynamic linking intact" || bad "dynsym changed — would risk breakage"

# -------------------------------------------------- (C) proven non-loaded -----
hdr "(C) decoy NON-ALLOCATED; synthetic symbols LOCAL + .symtab-only"
# every .carapace_exh_* section must lack SHF_ALLOC (0x2) => never mapped at runtime
python3 - "$EXH" "$AUDIT" <<'PY' && ok "all decoy sections are non-alloc (SHF_ALLOC clear) — never mapped" || bad "a decoy section is allocated (would load at runtime)"
import sys,os
sys.path.insert(0, os.path.dirname(sys.argv[2]))
from elf_exposure_audit import ELF
elf=ELF(sys.argv[1]); SHF_ALLOC=0x2
sec=[(n,sh) for n,sh in elf.sections.items() if n.startswith(".carapace_exh_")]
sys.exit(0 if sec and all(not (sh["flags"] & SHF_ALLOC) for _,sh in sec) else 1)
PY
# synthetic symbols present in .symtab ...
nsym="$(nm "$EXH" 2>/dev/null | grep -c 'carapace_exh_fn_')"
[ "$nsym" = "$NSYM" ] && ok "$NSYM synthetic FUNC symbols present in .symtab" || bad "symtab synthetic count = $nsym (want $NSYM)"
# ... and ABSENT from .dynsym (no export pollution)
dsym="$(readelf -WsD "$EXH" 2>/dev/null | grep -c 'carapace_exh_fn_' || true)"
[ "${dsym:-0}" = "0" ] && ok "no synthetic symbol leaked into .dynsym (exports clean)" || bad "$dsym synthetic symbols leaked into .dynsym"

# -------------------------------------------------- (D) deterministic ---------
hdr "(D) DETERMINISTIC (reproducible build)"
EXH2="$WORK/sample_exhausted2"
python3 "$EXHAUST" "$BASE" "$EXH2" --sections "$NSEC" --section-size "$SSZ" --symbols "$NSYM" >/dev/null 2>&1
cmp -s "$EXH" "$EXH2" && ok "two exhaust passes are byte-identical" || bad "exhaust output is not deterministic"

hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "  SLICE I VERIFIED"; exit 0; } || { echo "  SLICE I HAS FAILURES"; exit 1; }

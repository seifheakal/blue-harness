#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice O (Mach-O LOCAL-symbol strip — first Mach-O harden).
#
# We cannot RUN a Mach-O on Linux, so this proves the transform is SURGICAL and
# correct STRUCTURALLY (runtime-identical is platform-gated to a macOS host — the
# tool and this header say so). Proves:
#   (A) locals removed: the static/internal symbol names are gone, symbol_count drops;
#   (B) externals PRESERVED: the exported names dyld needs survive;
#   (C) surgical: file size stable, every segment/section + dylib list byte-identical,
#       the result still parses;
#   (D) deterministic;
#   (E) honest: the tool prints the runtime-identical caveat; refuses safely when
#       there is no LC_DYSYMTAB / nothing to strip;
#   (F) the skill drives it (`carapace apply` on a Mach-O).
#
# Exit 0 = all hard assertions passed.
set -u
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
SAMPLE_DIR="$(cd ../sample && pwd)"
AUDIT="$REPO/harness/audit/macho_exposure_audit.py"
FIX="$SAMPLE_DIR/macho_fixture.py"
STRIP="$REPO/harness/harden/carapace_macho_strip.py"
CARA="python3 $REPO/skill/carapace.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()  { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "== $* =="; }
jget() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

LOCALS="_compute_checksum _g_secret_key _decrypt_blob _phone_home"
EXTS="_main _validate_license"

hdr "BUILD + STRIP"
python3 "$FIX" --profile soft --out "$WORK/mo" >/dev/null 2>&1 && ok "soft Mach-O (locals+externals+DYSYMTAB) built" || { bad "fixture failed"; exit 1; }
python3 "$STRIP" --in "$WORK/mo" --out "$WORK/mo.stripped" > "$WORK/strip.txt" 2>&1 \
    && ok "strip ran" || { bad "strip failed"; cat "$WORK/strip.txt"; exit 1; }

hdr "(A) locals removed"
python3 "$AUDIT" --json "$WORK/mo" > "$WORK/before.json"
python3 "$AUDIT" --json "$WORK/mo.stripped" > "$WORK/after.json"
[ "$(jget "$WORK/before.json" symbol_count)" = "6" ] && ok "before: 6 symbols" || bad "pre-strip count wrong"
[ "$(jget "$WORK/after.json" symbol_count)" = "2" ] && ok "after: 2 symbols (4 locals removed)" || bad "post-strip count wrong"
miss=0; for n in $LOCALS; do grep -aqc "$n" "$WORK/mo.stripped" >/dev/null 2>&1; [ "$(grep -ac "$n" "$WORK/mo.stripped")" -ne 0 ] && miss=1; done
[ "$miss" -eq 0 ] && ok "every LOCAL symbol name is gone from the bytes" || bad "a local symbol name survived"

hdr "(B) externals preserved (dyld needs them)"
keptall=1; for n in $EXTS; do [ "$(grep -ac "$n" "$WORK/mo.stripped")" -ge 1 ] || keptall=0; done
[ "$keptall" -eq 1 ] && ok "external/exported names preserved ($EXTS)" || bad "an external name was removed"

hdr "(C) surgical (size stable; segments/sections + dylibs byte-identical; still parses)"
bs=$(stat -c '%s' "$WORK/mo"); as=$(stat -c '%s' "$WORK/mo.stripped")
[ "$bs" = "$as" ] && ok "file size stable ($bs bytes; offsets kept)" || bad "file size changed ($bs -> $as)"
python3 - "$WORK/before.json" "$WORK/after.json" <<'PY' && ok "entropy_map + dylibs unchanged (segments/sections intact)" || bad "a segment/section/dylib changed"
import json,sys
a=json.load(open(sys.argv[1])); b=json.load(open(sys.argv[2]))
sys.exit(0 if a["entropy_map"]==b["entropy_map"] and a["dylibs"]==b["dylibs"] and a["format"]==b["format"] else 1)
PY
python3 "$AUDIT" "$WORK/mo.stripped" >/dev/null 2>&1 && ok "stripped Mach-O still parses cleanly" || bad "stripped file no longer parses"

hdr "(D) deterministic"
python3 "$STRIP" --in "$WORK/mo" --out "$WORK/mo.s2" >/dev/null 2>&1
cmp -s "$WORK/mo.stripped" "$WORK/mo.s2" && ok "two strips are byte-identical" || bad "strip not deterministic"

hdr "(E) honest caveat + safe refusals"
grep -qi "runtime-identical needs a macOS host" "$WORK/strip.txt" && ok "prints the runtime-identical (platform-gated) caveat" || bad "missing runtime caveat"
# a stripped-already / no-DYSYMTAB-or-empty input must refuse, not corrupt
python3 "$FIX" --profile hard --out "$WORK/mo_nosyms" >/dev/null 2>&1   # hard has no symbols
python3 "$STRIP" --in "$WORK/mo_nosyms" --out "$WORK/mo_nosyms.out" > "$WORK/refuse.txt" 2>&1; rc=$?
[ "$rc" -eq 2 ] && grep -qi "nothing to strip" "$WORK/refuse.txt" && ok "refuses safely when there are no symbols (rc 2)" || bad "did not refuse an empty symtab cleanly (rc=$rc)"
# a fat binary must be refused (strip each slice separately)
python3 "$FIX" --profile soft --fat --out "$WORK/mo_fat" >/dev/null 2>&1
python3 "$STRIP" --in "$WORK/mo_fat" --out "$WORK/mo_fat.out" > "$WORK/fat.txt" 2>&1; rc=$?
[ "$rc" -eq 2 ] && grep -qi "fat" "$WORK/fat.txt" && ok "refuses a fat/universal binary with guidance (rc 2)" || bad "fat not refused cleanly (rc=$rc)"

hdr "(F) skill drives it"
$CARA apply "$WORK/mo" --out "$WORK/mo.skill" > "$WORK/skill.txt" 2>&1 && ok "carapace apply ran on a Mach-O" || bad "carapace apply failed on Mach-O"
[ "$(python3 "$AUDIT" --json "$WORK/mo.skill" | python3 -c 'import json,sys;print(json.load(sys.stdin)["symbol_count"])')" = "2" ] \
    && ok "carapace apply produced a locally-stripped Mach-O (6→2)" || bad "carapace apply did not strip"

hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
echo "  (structural proof — runtime-identical is platform-gated to a macOS host)"
[ "$FAIL" -eq 0 ] && { echo "  SLICE O VERIFIED"; exit 0; } || { echo "  SLICE O HAS FAILURES"; exit 1; }

#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice N (Mach-O exposure audit — the third format).
#
# No Apple toolchain in the container, so we drive a toolchain-free Mach-O fixture
# generator (soft/hard/encrypted/fat) and prove the self-contained parser reads
# every signal, scores a soft->hard flip, and that the skill routes Mach-O by magic.
#
# Proves:
#   (A) parse: thin 64-bit header (format/machine/filetype), symtab, __cstring
#       strings, linked dylibs;
#   (B) soft->hard flip: hard is stripped + PIE + __RESTRICT + code-signed, and the
#       exposure score drops with a different tier;
#   (C) __TEXT encryption (LC_ENCRYPTION_INFO cryptid) craters the static-view score;
#   (D) fat/universal is parsed (slice count reported);
#   (E) code signature is READ-ONLY (presence reported, the honest note printed);
#   (F) the skill dispatches Mach-O to this scanner, and harden now runs the Mach-O
#       harden chain (Slice Q);
#   (G) a non-Mach-O is rejected gracefully.
#
# Exit 0 = all hard assertions passed.
set -u
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
SAMPLE_DIR="$(cd ../sample && pwd)"
AUDIT="$REPO/harness/audit/macho_exposure_audit.py"
FIX="$SAMPLE_DIR/macho_fixture.py"
CARA="python3 $REPO/skill/carapace.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()  { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "== $* =="; }
jget() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    v=v[k]
print(v)' "$1" "$2"; }

hdr "(A) BUILD fixtures + parse the soft one"
for p in soft hard encrypted; do
    python3 "$FIX" --profile "$p" --out "$WORK/mo_$p" >/dev/null 2>&1 || { bad "fixture $p failed"; exit 1; }
done
python3 "$FIX" --profile soft --fat --out "$WORK/mo_fat" >/dev/null 2>&1 || { bad "fat fixture failed"; exit 1; }
ok "soft/hard/encrypted/fat fixtures generated"
python3 "$AUDIT" --json "$WORK/mo_soft" > "$WORK/soft.json" 2>&1 || { bad "soft parse failed"; cat "$WORK/soft.json"; exit 1; }
[ "$(jget "$WORK/soft.json" format)" = "Mach-O64" ] && ok "format = Mach-O64" || bad "format wrong"
[ "$(jget "$WORK/soft.json" machine)" = "x86-64" ] && ok "machine = x86-64" || bad "machine wrong"
[ "$(jget "$WORK/soft.json" filetype)" = "EXECUTE" ] && ok "filetype = EXECUTE" || bad "filetype wrong"
[ "$(jget "$WORK/soft.json" symbol_count)" = "6" ] && ok "symbol table parsed (6 symbols)" || bad "symbol count wrong"
python3 -c "import json,sys; sys.exit(0 if json.load(open('$WORK/soft.json'))['string_density']>=0.5 else 1)" \
    && ok "high __cstring string density read" || bad "string density not read"
python3 -c "import json,sys; d=json.load(open('$WORK/soft.json')); sys.exit(0 if any('libSystem' in x for x in d['dylibs']) else 1)" \
    && ok "linked dylib parsed (libSystem)" || bad "dylib not parsed"

hdr "(B) soft -> hard flip"
python3 "$AUDIT" --json "$WORK/mo_hard" > "$WORK/hard.json" 2>&1
[ "$(jget "$WORK/hard.json" symbols_present)" = "False" ] && ok "hard: symbol table stripped" || bad "hard not stripped"
[ "$(jget "$WORK/hard.json" hardening.pie)" = "True" ] && ok "hard: PIE set" || bad "hard PIE not set"
[ "$(jget "$WORK/hard.json" hardening.restrict_segment)" = "True" ] && ok "hard: __RESTRICT segment present" || bad "hard __RESTRICT missing"
ss=$(jget "$WORK/soft.json" score); hs=$(jget "$WORK/hard.json" score)
[ "$ss" -gt "$hs" ] && ok "exposure score drops soft($ss) -> hard($hs)" || bad "score did not drop ($ss -> $hs)"
[ "$(jget "$WORK/soft.json" tier)" != "$(jget "$WORK/hard.json" tier)" ] && ok "posture tier changed soft vs hard" || bad "tier unchanged"

hdr "(C) __TEXT encryption craters the static-view score"
python3 "$AUDIT" --json "$WORK/mo_encrypted" > "$WORK/enc.json" 2>&1
[ "$(jget "$WORK/enc.json" hardening.encrypted)" = "True" ] && ok "LC_ENCRYPTION_INFO cryptid read (encrypted)" || bad "encryption not detected"
es=$(jget "$WORK/enc.json" score)
[ "$es" -lt "$ss" ] && ok "encrypted score ($es) < soft ($ss) — static view is ciphertext" || bad "encrypted score not lowered"

hdr "(D) fat/universal parsed"
python3 "$AUDIT" --json "$WORK/mo_fat" > "$WORK/fat.json" 2>&1
case "$(jget "$WORK/fat.json" format)" in *FAT*) ok "fat format reported";; *) bad "fat not reported";; esac
[ "$(jget "$WORK/fat.json" fat_slices)" -ge 1 ] && ok "fat slice count reported" || bad "fat slices wrong"

hdr "(E) code signature READ-ONLY + honest note"
[ "$(jget "$WORK/hard.json" code_signature_present)" = "True" ] && ok "code signature presence detected" || bad "code signature missed"
python3 "$AUDIT" "$WORK/mo_hard" | grep -q "READ-ONLY, not verified" && ok "render marks the signature READ-ONLY (not verified)" || bad "read-only note missing"

hdr "(F) skill dispatch + honest refusal"
$CARA audit "$WORK/mo_soft" 2>&1 | grep -q "Mach-O Exposure Audit" && ok "carapace audit routes Mach-O to this scanner" || bad "skill did not route Mach-O"
$CARA harden "$WORK/mo_soft" --out "$WORK/mo_soft.hard" >/dev/null 2>&1; [ "$?" -eq 0 ] && ok "harden now dispatches the Mach-O harden chain (Slice Q)" || bad "harden did not run on Mach-O"

hdr "(G) non-Mach-O rejected gracefully"
make -C "$SAMPLE_DIR" sample_dev >/dev/null 2>&1
python3 "$AUDIT" "$SAMPLE_DIR/sample_dev" > "$WORK/nonmo.txt" 2>&1; rc=$?
[ "$rc" -eq 2 ] && ! grep -qi Traceback "$WORK/nonmo.txt" && ok "an ELF is rejected cleanly (rc 2, no traceback)" || bad "non-Mach-O not handled cleanly (rc=$rc)"

hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "  SLICE N VERIFIED"; exit 0; } || { echo "  SLICE N HAS FAILURES"; exit 1; }

#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice P (Windows PE harden path).
#
# PE was audit-only (Slice G). Slice P gives it a post-build HARDEN path with three
# provable, non-breaking levers, proven STRUCTURALLY / byte-level on Linux with NO
# Windows host (exactly how the Slice O Mach-O strip is proven):
#   (A) COFF-symbol + debug/PDB STRIP  — audit flips present→absent; dev names +
#       PDB path gone; imports preserved; file size stable; SURGICAL (every changed
#       byte lies inside the symbol/debug metadata regions — nothing else moves).
#   (B) decoy NON-MAPPED overlay (exhaust) — audit flips absent→present; append-only
#       (original file is a byte-identical prefix); decoys provably in the overlay,
#       past the end of every section's raw data (never mapped).
#   (C) honeytokens — audit flips absent→present; tokens unique + plausible (AKIA)
#       + whole-file-strings visible; attributable via a PRIVATE ledger; inert.
#   (D) the skill drives it (`carapace apply` = strip; `carapace harden` = all three).
#   (E) honest: tier+bypass on every lever, never "unbreakable", the Windows-host
#       caveat is printed, and non-PE / nothing-to-strip inputs are refused cleanly.
#
# Runtime-identical is platform-gated to a WINDOWS host (like Slice O's macOS host).
# Exit 0 = all hard assertions passed.
set -u
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
AUDIT="$REPO/harness/audit/pe_exposure_audit.py"
AUDIT_DIR="$REPO/harness/audit"
FIX="$REPO/harness/sample/pe_fixture.py"
STRIP="$REPO/harness/harden/carapace_pe_strip.py"
EXH="$REPO/harness/harden/carapace_pe_exhaust.py"
HONEY="$REPO/harness/harden/carapace_pe_honeytokens.py"
CARA="python3 $REPO/skill/carapace.py"
ELF_DEV="$REPO/harness/sample/sample_dev"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()  { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "== $* =="; }
# jget <file> <key>  — print one top-level JSON field
jget() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

DEV_NAMES="compute_license_check g_secret_key decrypt_blob_xor verify_entitlement"

hdr "BUILD fixtures (minimal PE32+, no toolchain)"
python3 "$FIX" --out "$WORK/exposed.exe" --profile exposed >/dev/null 2>&1 \
    && ok "exposed PE fixture (COFF symbols + PDB) built" || { bad "fixture failed"; exit 1; }
python3 "$FIX" --out "$WORK/signed.exe"  --profile exposed --signed >/dev/null 2>&1 && ok "signed exposed fixture built" || bad "signed fixture failed"
python3 "$FIX" --out "$WORK/hard.exe"    --profile hard >/dev/null 2>&1 && ok "hard fixture (no symbols/PDB) built" || bad "hard fixture failed"

# =====================================================================(A) STRIP
hdr "(A) STRIP — audit flips present→absent, dev identity gone, imports kept"
python3 "$STRIP" --in "$WORK/exposed.exe" --out "$WORK/stripped.exe" > "$WORK/strip.txt" 2>&1 \
    && ok "strip ran" || { bad "strip failed"; cat "$WORK/strip.txt"; }
python3 "$AUDIT" --json "$WORK/exposed.exe"  > "$WORK/before.json"
python3 "$AUDIT" --json "$WORK/stripped.exe" > "$WORK/after.json"
[ "$(jget "$WORK/before.json" symbols_present)" = "True"  ] && ok "before: COFF symbols present" || bad "pre-strip symbols wrong"
[ "$(jget "$WORK/after.json"  symbols_present)" = "False" ] && ok "after:  COFF symbols absent"  || bad "post-strip symbols survived"
[ "$(jget "$WORK/before.json" debug_info_present)" = "True"  ] && ok "before: debug/PDB present" || bad "pre-strip debug wrong"
[ "$(jget "$WORK/after.json"  debug_info_present)" = "False" ] && ok "after:  debug/PDB absent"  || bad "post-strip debug survived"
[ "$(jget "$WORK/after.json"  pdb_path)" = "None" ] && ok "after:  PDB path is gone" || bad "PDB path survived"
bs=$(jget "$WORK/before.json" score); as=$(jget "$WORK/after.json" score)
[ "$as" -lt "$bs" ] && ok "exposure score drops ($bs → $as)" || bad "score should drop ($bs → $as)"
miss=0; for n in $DEV_NAMES; do [ "$(grep -ac "$n" "$WORK/stripped.exe")" -ne 0 ] && miss=1; done
[ "$miss" -eq 0 ] && ok "every dev-identity symbol name is gone from the bytes" || bad "a dev symbol name survived"
[ "$(grep -ac '\.pdb' "$WORK/stripped.exe")" -eq 0 ] && ok "the .pdb path is gone from the bytes" || bad ".pdb path survived"
keptall=1; for n in KERNEL32.dll CreateFileW VirtualProtect; do [ "$(grep -ac "$n" "$WORK/stripped.exe")" -ge 1 ] || keptall=0; done
[ "$keptall" -eq 1 ] && ok "import table preserved (KERNEL32: CreateFileW, VirtualProtect)" || bad "an import name was removed"

hdr "(A2) STRUCTURAL surgery — size stable; only metadata regions changed"
sb=$(stat -c '%s' "$WORK/exposed.exe"); sa=$(stat -c '%s' "$WORK/stripped.exe")
[ "$sb" = "$sa" ] && ok "file size stable ($sb bytes; offsets kept)" || bad "file size changed ($sb → $sa)"
python3 - "$WORK/exposed.exe" "$WORK/stripped.exe" "$AUDIT_DIR" <<'PY' && ok "every changed byte lies inside a symbol/debug metadata region (surgical)" || bad "a byte changed OUTSIDE the metadata regions"
import sys, struct
sys.path.insert(0, sys.argv[3])
from pe_exposure_audit import PE
a = open(sys.argv[1], "rb").read()
b = open(sys.argv[2], "rb").read()
assert len(a) == len(b), "size changed"
pe = PE(sys.argv[1])
allowed = []  # list of (lo, hi) byte ranges the strip is permitted to change
coff = pe.e_lfanew + 4
allowed.append((coff + 8, coff + 16))                       # PointerToSymbolTable + NumberOfSymbols
if pe.ptr_symtab and pe.num_symbols:
    so = pe.ptr_symtab; sb_ = pe.num_symbols * 18; to = so + sb_
    ss = struct.unpack_from("<I", a, to)[0] if to + 4 <= len(a) else 0
    allowed.append((so, min(len(a), to + max(ss, 4))))      # symtab + string table
dir_off = pe.opt + (0x70 if pe.pe32plus else 0x60) + 6 * 8
allowed.append((dir_off, dir_off + 8))                      # Debug data directory entry
drva, dsz = pe.dir(6)
if drva and dsz:
    doff = pe.rva_to_off(drva)
    allowed.append((doff, doff + dsz))                      # IMAGE_DEBUG_DIRECTORY
    for e in range(0, dsz, 28):
        base = doff + e
        size_of_data = struct.unpack_from("<I", a, base + 16)[0]
        ptr_raw = struct.unpack_from("<I", a, base + 24)[0]
        if ptr_raw and size_of_data:
            allowed.append((ptr_raw, ptr_raw + size_of_data))  # CodeView / PDB record
def ok_off(i):
    return any(lo <= i < hi for lo, hi in allowed)
bad_offsets = [i for i in range(len(a)) if a[i] != b[i] and not ok_off(i)]
sys.exit(0 if not bad_offsets else 1)
PY

# ==================================================================(B) EXHAUST
hdr "(B) EXHAUST — decoy regions provably NON-MAPPED (overlay), append-only"
python3 "$EXH" "$WORK/exposed.exe" "$WORK/exh.exe" --sections 4 --section-size 8192 > "$WORK/exh.txt" 2>&1 \
    && ok "exhaust ran" || { bad "exhaust failed"; cat "$WORK/exh.txt"; }
python3 "$AUDIT" --json "$WORK/exh.exe" > "$WORK/exh.json"
[ "$(jget "$WORK/before.json" decoy_overlay_present)" = "False" ] && ok "before: no decoy overlay" || bad "pre-exhaust decoy flag wrong"
[ "$(jget "$WORK/exh.json"    decoy_overlay_present)" = "True"  ] && ok "after:  decoy overlay present" || bad "post-exhaust decoy flag wrong"
python3 - "$WORK/exposed.exe" "$WORK/exh.exe" "$AUDIT_DIR" <<'PY' && ok "append-only (original is a byte-identical prefix) AND decoys past every section's raw end (non-mapped)" || bad "exhaust was not append-only / decoy not provably non-mapped"
import sys
sys.path.insert(0, sys.argv[3])
from pe_exposure_audit import PE
a = open(sys.argv[1], "rb").read()
b = open(sys.argv[2], "rb").read()
if b[:len(a)] != a:            # append-only
    sys.exit(1)
pe = PE(sys.argv[1])
mapped_end = max([0] + [s["PointerToRawData"] + s["SizeOfRawData"] for s in pe.sections if s["SizeOfRawData"]])
marker = b.find(b"__CARAPACE_PE_EXH_")
sys.exit(0 if marker >= mapped_end and marker >= len(a) else 1)
PY
grew=$(python3 -c 'import sys;print(len(open(sys.argv[1],"rb").read())-len(open(sys.argv[2],"rb").read()))' "$WORK/exh.exe" "$WORK/exposed.exe")
[ "$grew" -gt 30000 ] && ok "analysis surface grew by $grew bytes (4×8 KiB decoys)" || bad "surface did not grow as expected ($grew)"

# ===============================================================(C) HONEYTOKENS
hdr "(C) HONEYTOKENS — poison + attribution, provably inert"
python3 "$HONEY" plant "$WORK/exposed.exe" "$WORK/honey.exe" --ledger "$WORK/ledger.json" \
    --count 10 --build-tag build-AAA > "$WORK/honey.txt" 2>&1 && ok "plant ran" || { bad "plant failed"; cat "$WORK/honey.txt"; }
python3 "$AUDIT" --json "$WORK/honey.exe" > "$WORK/honey.json"
[ "$(jget "$WORK/before.json" honeytokens_present)" = "False" ] && ok "before: no honeytokens" || bad "pre-plant honey flag wrong"
[ "$(jget "$WORK/honey.json"  honeytokens_present)" = "True"  ] && ok "after:  honeytokens present" || bad "post-plant honey flag wrong"
python3 - "$WORK/exposed.exe" "$WORK/honey.exe" <<'PY' && ok "plant is append-only (original is a byte-identical prefix)" || bad "plant was not append-only"
import sys
a=open(sys.argv[1],"rb").read(); b=open(sys.argv[2],"rb").read()
sys.exit(0 if b[:len(a)]==a else 1)
PY
python3 -c 'import json,sys
t=[x["value"] for x in json.load(open(sys.argv[1]))["tokens"]]
sys.exit(0 if len(set(t))==len(t) and any(v.startswith("AKIA") for v in t) else 1)' "$WORK/ledger.json" \
    && ok "tokens unique + at least one plausible AWS (AKIA) key" || bad "tokens not unique / no plausible AKIA key"
TOK=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["tokens"][0]["value"])' "$WORK/ledger.json")
[ "$(grep -acF "$TOK" "$WORK/honey.exe")" -ge 1 ] && ok "a honeytoken is visible to a whole-file strings scan" || bad "honeytoken not strings-visible"
python3 "$HONEY" check --ledger "$WORK/ledger.json" --input "$WORK/honey.exe" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 7 ] && ok "attribution: a leaked token is matched back to its build (rc 7)" || bad "attribution did not fire (rc=$rc)"
python3 "$HONEY" check --ledger "$WORK/ledger.json" --input "$WORK/hard.exe" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok "no false positive against an unrelated binary (rc 0)" || bad "false positive (rc=$rc)"
python3 "$HONEY" plant "$WORK/exposed.exe" "$WORK/honey2.exe" --ledger "$WORK/ledger2.json" --count 10 --build-tag build-BBB >/dev/null 2>&1
python3 -c 'import json,sys
a=[x["value"] for x in json.load(open(sys.argv[1]))["tokens"]]
b=[x["value"] for x in json.load(open(sys.argv[2]))["tokens"]]
sys.exit(0 if set(a).isdisjoint(b) else 1)' "$WORK/ledger.json" "$WORK/ledger2.json" \
    && ok "tokens are unique PER BUILD (two build-tags share none)" || bad "tokens collide across builds"

# =================================================================(D) SKILL
hdr "(D) SKILL drives it (apply = strip; harden = all three)"
$CARA apply "$WORK/exposed.exe" --out "$WORK/skill.stripped.exe" > "$WORK/skill_apply.txt" 2>&1 \
    && ok "carapace apply ran on a PE" || { bad "carapace apply failed"; cat "$WORK/skill_apply.txt"; }
[ "$(python3 "$AUDIT" --json "$WORK/skill.stripped.exe" | python3 -c 'import json,sys;print(json.load(sys.stdin)["symbols_present"])')" = "False" ] \
    && ok "carapace apply produced a symbol-stripped PE" || bad "carapace apply did not strip"
$CARA harden "$WORK/exposed.exe" --out "$WORK/skill.hardened.exe" --build-tag CI-run > "$WORK/skill_harden.txt" 2>&1 \
    && ok "carapace harden ran on a PE" || { bad "carapace harden failed"; cat "$WORK/skill_harden.txt"; }
python3 "$AUDIT" --json "$WORK/skill.hardened.exe" > "$WORK/skh.json"
[ "$(jget "$WORK/skh.json" symbols_present)" = "False" ] && [ "$(jget "$WORK/skh.json" decoy_overlay_present)" = "True" ] && [ "$(jget "$WORK/skh.json" honeytokens_present)" = "True" ] \
    && ok "harden applied all three (symbols stripped + decoy + honeytokens)" || bad "harden did not apply all three passes"
[ -f "$WORK/skill.hardened.exe.honey-ledger.json" ] && ok "harden wrote the PRIVATE honeytoken ledger" || bad "no private ledger written"

# =================================================================(E) HONESTY
hdr "(E) HONEST — tier+bypass, Windows-host caveat, clean refusals, no overclaim"
grep -qi "runtime-identical needs a Windows host" "$WORK/strip.txt" && ok "strip prints the Windows-host (platform-gated) caveat" || bad "strip missing the runtime caveat"
grep -qi "bypass" "$WORK/strip.txt" && grep -qi "tier" "$WORK/strip.txt" && ok "strip states a tier + a named bypass" || bad "strip missing tier/bypass"
grep -qi "nothing here is unbreakable" "$WORK/skill_harden.txt" && ok "harden states the honest negation (nothing is unbreakable)" || bad "harden missing the honest 'nothing is unbreakable' framing"
grep -qi "server-side" "$WORK/skill_harden.txt" && ok "harden surfaces the server-side Strong-tier truth" || bad "harden missing the server-side truth"
# nothing-to-strip refusal
python3 "$STRIP" --in "$WORK/hard.exe" --out "$WORK/hard.out" > "$WORK/refuse.txt" 2>&1; rc=$?
[ "$rc" -eq 2 ] && grep -qi "nothing to strip" "$WORK/refuse.txt" && ok "strip refuses cleanly when there is nothing to strip (rc 2)" || bad "did not refuse an already-clean PE (rc=$rc)"
# non-PE refusal
if [ -f "$ELF_DEV" ] || make -C "$REPO/harness/sample" sample_dev >/dev/null 2>&1; then
    python3 "$STRIP" --in "$ELF_DEV" --out "$WORK/elf.out" >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 2 ] && ok "strip rejects a non-PE (ELF) cleanly (rc 2)" || bad "non-PE not refused (rc=$rc)"
else
    printf 'not a PE at all, just text' > "$WORK/blob.bin"
    python3 "$STRIP" --in "$WORK/blob.bin" --out "$WORK/blob.out" >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 2 ] && ok "strip rejects a non-PE blob cleanly (rc 2)" || bad "non-PE blob not refused (rc=$rc)"
fi
# signed → Authenticode warning on every lever
python3 "$STRIP" --in "$WORK/signed.exe" --out "$WORK/signed.stripped.exe" 2>&1 | grep -qi "invalidates it" && ok "strip warns that stripping invalidates an Authenticode signature" || bad "strip missing the signed warning"
python3 "$EXH" "$WORK/signed.exe" "$WORK/signed.exh.exe" --sections 1 --section-size 256 2>&1 | grep -qi "invalidates the signature" && ok "exhaust warns on a signed PE" || bad "exhaust missing the signed warning"

hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
echo "  (structural proof — runtime-identical is platform-gated to a Windows host)"
[ "$FAIL" -eq 0 ] && { echo "  SLICE P VERIFIED"; exit 0; } || { echo "  SLICE P HAS FAILURES"; exit 1; }

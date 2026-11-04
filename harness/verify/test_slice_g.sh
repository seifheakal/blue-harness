#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice G (PE / Windows exposure audit).
# Audit-first, no new countermeasure: prove the PE scanner reads the signals an
# AI-RE agent reads and scores them honestly. Fixtures are generated in-process
# (no mingw/pefile needed) by harness/sample/pe_fixture.py.
#
# Exit 0 = all hard assertions passed.
set -u

cd "$(dirname "$0")"
AUDIT="$(cd ../audit && pwd)/pe_exposure_audit.py"
FIXTURE="$(cd ../sample && pwd)/pe_fixture.py"
ELF_DEV="$(cd ../sample && pwd)/sample_dev"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()  { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "== $* =="; }

# JSON field helper: jget <file> <python-expr over d>
jget() { python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(eval(sys.argv[2]))' "$1" "$2"; }

# ---------------------------------------------------------------- build ----
hdr "BUILD fixtures (minimal PE32+, no toolchain)"
python3 "$FIXTURE" --out "$WORK/soft.exe"   --profile soft   >/dev/null && ok "soft PE fixture generated"   || bad "soft fixture failed"
python3 "$FIXTURE" --out "$WORK/hard.exe"   --profile hard   >/dev/null && ok "hard PE fixture generated"   || bad "hard fixture failed"
python3 "$FIXTURE" --out "$WORK/packed.exe" --profile packed >/dev/null && ok "packed PE fixture generated" || bad "packed fixture failed"

python3 "$AUDIT" --json "$WORK/soft.exe"   > "$WORK/soft.json"
python3 "$AUDIT" --json "$WORK/hard.exe"   > "$WORK/hard.json"
python3 "$AUDIT" --json "$WORK/packed.exe" > "$WORK/packed.json"

# ------------------------------------------- (A) format + imports ----------
hdr "(A) parses format, machine, imports (what rea reads)"
[ "$(jget "$WORK/soft.json" 'd["format"]')" = "PE32+" ] && ok "format = PE32+" || bad "format wrong"
[ "$(jget "$WORK/soft.json" 'd["machine"]')" = "x86-64" ] && ok "machine = x86-64" || bad "machine wrong"
imps=$(jget "$WORK/soft.json" 'd["imports"].get("KERNEL32.dll",[])')
case "$imps" in *CreateFileW*VirtualProtect*) ok "import table parsed (KERNEL32: CreateFileW, VirtualProtect, …)";; *) bad "imports not parsed: $imps";; esac
[ "$(jget "$WORK/hard.json" 'd["imports"]==json.load(open("'"$WORK"'/soft.json"))["imports"]')" = "True" ] \
    && ok "imports identical across soft/hard (parser is deterministic)" || bad "imports differ unexpectedly"

# ----------------------------------- (B) hardening flags flip --------------
hdr "(B) DllCharacteristics flip soft -> hard"
for f in aslr dep_nx cfg; do
    [ "$(jget "$WORK/soft.json" "d['hardening']['$f']")" = "False" ] && ok "soft: $f OFF" || bad "soft $f should be off"
done
for f in aslr dep_nx cfg high_entropy_va; do
    [ "$(jget "$WORK/hard.json" "d['hardening']['$f']")" = "True" ] && ok "hard: $f ON" || bad "hard $f should be on"
done

# ------------------------------- (C) debug/PDB, authenticode, score --------
hdr "(C) PDB, Authenticode (read-only), score"
[ "$(jget "$WORK/soft.json" 'd["debug_info_present"]')" = "True" ] && ok "soft: debug/PDB detected" || bad "soft PDB missing"
case "$(jget "$WORK/soft.json" 'd["pdb_path"]')" in *.pdb) ok "soft: PDB path recovered ($(jget "$WORK/soft.json" 'd["pdb_path"]'))";; *) bad "soft PDB path not recovered";; esac
[ "$(jget "$WORK/hard.json" 'd["debug_info_present"]')" = "False" ] && ok "hard: no debug/PDB" || bad "hard should have no PDB"
[ "$(jget "$WORK/soft.json" 'd["authenticode_present"]')" = "False" ] && ok "soft: unsigned" || bad "soft should be unsigned"
[ "$(jget "$WORK/hard.json" 'd["authenticode_present"]')" = "True" ] && ok "hard: Authenticode present (read-only, not verified)" || bad "hard should be signed"
ss=$(jget "$WORK/soft.json" 'd["score"]'); hs=$(jget "$WORK/hard.json" 'd["score"]')
[ "$hs" -lt "$ss" ] && ok "exposure score drops soft($ss) -> hard($hs)" || bad "score should drop ($ss -> $hs)"

# honesty: the report must state the signature is read-only / not verified
python3 "$AUDIT" "$WORK/hard.exe" | grep -qi "not verified" && ok "report states a signature on disk is NOT verified (honesty)" || bad "missing the read-only-signature honesty note"

# ----------------------------------------------- (D) packer + non-PE -------
hdr "(D) packer tell + graceful non-PE handling"
case "$(jget "$WORK/packed.json" 'd["packer"]')" in *UPX0*) ok "packed: packer tell detected (UPX0)";; *) bad "packer tell missing";; esac
[ "$(jget "$WORK/packed.json" 'd["high_entropy"]')" = "True" ] && ok "packed: high-entropy section flagged" || bad "high entropy not flagged"
if [ -f "$ELF_DEV" ] || make -C "$(dirname "$ELF_DEV")" sample_dev >/dev/null 2>&1; then
    python3 "$AUDIT" "$ELF_DEV" >/dev/null 2>&1
    [ $? -eq 2 ] && ok "an ELF is rejected gracefully by the PE scanner (exit 2)" || bad "PE scanner should reject an ELF"
else
    SKIP=$((SKIP+1)); echo "  SKIP  no ELF handy to test non-PE rejection"
fi

# ------------------------------------------------------------- summary -----
hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "  SLICE G VERIFIED"; exit 0; } || { echo "  SLICE G HAS FAILURES"; exit 1; }

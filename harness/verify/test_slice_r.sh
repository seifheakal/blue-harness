#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice R (mobile-container reach).
#
# Proves the harness can reach INTO a mobile container (APK/AAB/IPA — all ZIP),
# enumerate the NATIVE payloads inside, DELEGATE each to the existing per-format
# auditor, and HARDEN + REPACK by dispatching through the stable Slice-M entry
# point — honestly (never fakes re-signing). Synthetic fixtures only (a tiny ELF
# `.so` + a tiny Mach-O), so the audit + the Mach-O harden path are pure-Python /
# CROSS-PLATFORM (not host-gated). The ELF-payload HARDEN sub-checks need an
# ELF-capable binutils (objcopy) + gcc — present on the Ubuntu CI, SKIP'd
# elsewhere, exactly like the bare-ELF slices.
#
# Proves:
#   (A) container detection + native-payload enumeration (APK ELF .so / IPA Mach-O),
#       DEX + resources skipped (out of scope / non-native);
#   (B) the audit DELEGATES to the real ELF/Mach-O auditors (score parity);
#   (C) the skill routes a container (audit/report/recommend/apply), refuses a
#       non-mobile ZIP cleanly;
#   (D) harden DISPATCHES + REPACKS an IPA (Mach-O, cross-platform): payloads
#       transformed, resources byte-identical, sidecars kept OUT, honest signing
#       limitation + tier + bypass stated;
#   (E) harden DISPATCHES + REPACKS an APK (ELF) on a host with ELF binutils;
#   (F) honesty: never claims to sign; the private keys stay out of the container.
#
# Exit 0 = all hard assertions passed.
set -u
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
SAMPLE="$REPO/harness/sample"
MAUDIT="$REPO/harness/audit/mobile_container_audit.py"
ELFAUDIT="$REPO/harness/audit/elf_exposure_audit.py"
MACHOAUDIT="$REPO/harness/audit/macho_exposure_audit.py"
FIX_ELF="$SAMPLE/elf_so_fixture.py"
FIX_MACHO="$SAMPLE/macho_fixture.py"
CARA="python3 $REPO/skill/carapace.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()  { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
skip(){ echo "  SKIP  $*"; SKIP=$((SKIP+1)); }
hdr() { echo; echo "== $* =="; }

mkzip() { # $1=srcdir  $2=out
  python3 - "$1" "$2" <<'PY'
import sys, os, zipfile
src, out = sys.argv[1], sys.argv[2]
z = zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED)
for root, _, fs in os.walk(src):
    for f in sorted(fs):
        p = os.path.join(root, f)
        a = os.path.relpath(p, src).replace(os.sep, "/")
        z.write(p, a)
z.close()
PY
}

# ---------------------------------------------------------------- fixtures
hdr "BUILD FIXTURES (synthetic APK + IPA)"
AD="$WORK/apk"; ID="$WORK/ipa"
mkdir -p "$AD/lib/arm64-v8a" "$AD/lib/armeabi-v7a" "$AD/res" \
         "$ID/Payload/Demo.app/Frameworks/Core.framework"
python3 "$FIX_ELF" --out "$AD/lib/arm64-v8a/libnative.so"   >/dev/null 2>&1 || { bad "elf fixture"; exit 1; }
python3 "$FIX_ELF" --out "$AD/lib/armeabi-v7a/libnative.so" >/dev/null 2>&1 || { bad "elf fixture"; exit 1; }
printf 'binary-xml-manifest' > "$AD/AndroidManifest.xml"
printf 'dex\n035\000fake-dalvik-bytecode' > "$AD/classes.dex"
printf 'arsc-resources'       > "$AD/resources.arsc"
printf 'PNGDATA'              > "$AD/res/icon.png"
python3 "$FIX_MACHO" --profile soft --out "$ID/Payload/Demo.app/Demo" >/dev/null 2>&1 || { bad "macho fixture"; exit 1; }
python3 "$FIX_MACHO" --profile soft --out "$ID/Payload/Demo.app/Frameworks/Core.framework/Core" >/dev/null 2>&1 || { bad "macho fixture"; exit 1; }
printf '<plist/>' > "$ID/Payload/Demo.app/Info.plist"
printf 'PNGDATA'  > "$ID/Payload/Demo.app/icon.png"
mkzip "$AD" "$WORK/app.apk"
mkzip "$ID" "$WORK/app.ipa"
[ -f "$WORK/app.apk" ] && [ -f "$WORK/app.ipa" ] && ok "APK + IPA fixtures built" || { bad "zip build"; exit 1; }

python3 "$MAUDIT" --json "$WORK/app.apk" > "$WORK/apk.json" 2>"$WORK/apk.err" || { bad "apk audit crashed"; cat "$WORK/apk.err"; exit 1; }
python3 "$MAUDIT" --json "$WORK/app.ipa" > "$WORK/ipa.json" 2>"$WORK/ipa.err" || { bad "ipa audit crashed"; cat "$WORK/ipa.err"; exit 1; }

# ------------------------------------------------- (A) detection + enumerate
hdr "(A) container detection + native-payload enumeration"
python3 - "$WORK/apk.json" <<'PY' && ok "APK: kind=apk os=android, 2 ELF payloads, 1 DEX skipped" || bad "APK enumeration wrong"
import json,sys
d=json.load(open(sys.argv[1]))
arcs=sorted(p["arcname"] for p in d["payloads"])
assert d["kind"]=="apk" and d["os"]=="android", d
assert d["payload_count"]==2 and d["dex_skipped"]==1, d
assert arcs==["lib/arm64-v8a/libnative.so","lib/armeabi-v7a/libnative.so"], arcs
assert all(p["format"]=="elf" for p in d["payloads"]), d
abis=sorted(p["abi"] for p in d["payloads"])
assert abis==["arm64-v8a","armeabi-v7a"], abis
PY
python3 - "$WORK/ipa.json" <<'PY' && ok "IPA: kind=ipa os=ios, 2 Mach-O payloads (binary + framework)" || bad "IPA enumeration wrong"
import json,sys
d=json.load(open(sys.argv[1]))
arcs=sorted(p["arcname"] for p in d["payloads"])
assert d["kind"]=="ipa" and d["os"]=="ios", d
assert d["payload_count"]==2, d
assert arcs==["Payload/Demo.app/Demo","Payload/Demo.app/Frameworks/Core.framework/Core"], arcs
assert all(p["format"]=="macho" for p in d["payloads"]), d
PY
# non-native members never enumerated as payloads
python3 - "$WORK/apk.json" "$WORK/ipa.json" <<'PY' && ok "non-native members (manifest/dex/arsc/plist/png) are NOT payloads" || bad "a non-native member leaked into payloads"
import json,sys
for f in sys.argv[1:]:
    d=json.load(open(f))
    for p in d["payloads"]:
        n=p["arcname"].lower()
        assert not n.endswith((".dex",".xml",".arsc",".plist",".png")), p
PY

# -------------------------------------------- (B) delegation to real auditors
hdr "(B) audit DELEGATES to the real per-format auditors (score parity)"
ELF_SCORE=$(python3 "$ELFAUDIT" --json "$AD/lib/arm64-v8a/libnative.so" | python3 -c 'import json,sys;print(json.load(sys.stdin)["score"])')
APK_SCORE=$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print([p["score"] for p in d["payloads"] if "arm64" in p["arcname"]][0])' "$WORK/apk.json")
[ -n "$ELF_SCORE" ] && [ "$ELF_SCORE" = "$APK_SCORE" ] && ok "APK ELF payload score == standalone ELF audit ($ELF_SCORE)" || bad "ELF delegation mismatch ($ELF_SCORE vs $APK_SCORE)"
MACHO_SYMS=$(python3 "$MACHOAUDIT" --json "$ID/Payload/Demo.app/Demo" | python3 -c 'import json,sys;print(json.load(sys.stdin)["symbol_count"])')
IPA_SYMS=$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["payloads"][0]["symbol_count"])' "$WORK/ipa.json")
[ "$MACHO_SYMS" = "6" ] && [ "$IPA_SYMS" = "6" ] && ok "IPA Mach-O payload symbol_count == standalone Mach-O audit (6)" || bad "Mach-O delegation mismatch ($MACHO_SYMS vs $IPA_SYMS)"

# ---------------------------------------------------- (C) skill routes it
hdr "(C) skill routes the container (Slice-M dispatch extended)"
$CARA audit "$WORK/app.apk" > "$WORK/c_apk.txt" 2>&1
grep -q "MOBILE-CONTAINER AUDIT" "$WORK/c_apk.txt" && grep -q "APK" "$WORK/c_apk.txt" && ok "carapace audit routes APK -> mobile audit" || bad "skill did not route APK"
$CARA audit "$WORK/app.ipa" > "$WORK/c_ipa.txt" 2>&1
grep -q "IPA" "$WORK/c_ipa.txt" && grep -qi "ios" "$WORK/c_ipa.txt" && ok "carapace audit routes IPA -> mobile audit" || bad "skill did not route IPA"
$CARA recommend "$WORK/app.apk" > "$WORK/c_rec.txt" 2>&1
grep -qi "native payload" "$WORK/c_rec.txt" && grep -qi "server-side" "$WORK/c_rec.txt" && ok "carapace recommend: native payloads + server-side truth" || bad "recommend missing payload/server truth"
$CARA apply "$WORK/app.apk" > "$WORK/c_apply.txt" 2>&1; rc=$?
[ "$rc" -eq 3 ] && grep -qi "use .carapace harden." "$WORK/c_apply.txt" && ok "carapace apply on a container -> points at harden (rc 3)" || bad "apply did not defer to harden (rc=$rc)"
# a non-mobile ZIP is refused cleanly (no traceback)
printf 'just text' > "$WORK/plain.txt"; ( cd "$WORK" && python3 -c "import zipfile;z=zipfile.ZipFile('notmobile.zip','w');z.write('plain.txt');z.close()" )
$CARA audit "$WORK/notmobile.zip" > "$WORK/c_bad.txt" 2>&1; rc=$?
[ "$rc" -eq 2 ] && grep -qi "unrecognized mobile container" "$WORK/c_bad.txt" && ! grep -qi "Traceback" "$WORK/c_bad.txt" && ok "non-mobile ZIP refused cleanly (rc 2, no traceback)" || bad "non-mobile ZIP not refused cleanly (rc=$rc)"

# ---------------------------------- (D) harden dispatch + repack — IPA (Mach-O)
hdr "(D) harden DISPATCHES + REPACKS an IPA (Mach-O; cross-platform)"
$CARA harden "$WORK/app.ipa" --out "$WORK/out.ipa" --build-tag slice-r > "$WORK/h_ipa.txt" 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok "carapace harden ran on an IPA (rc 0)" || { bad "IPA harden failed (rc=$rc)"; cat "$WORK/h_ipa.txt"; }
python3 - "$WORK/out.ipa" <<'PY' && ok "repacked IPA is a valid ZIP" || bad "repacked IPA not a valid zip"
import zipfile,sys; sys.exit(0 if zipfile.is_zipfile(sys.argv[1]) else 1)
PY
python3 - "$WORK/app.ipa" "$WORK/out.ipa" <<'PY' && ok "payloads transformed; resources byte-identical; member set preserved" || bad "repack did not substitute payloads / corrupted resources"
import zipfile,sys
za,zb=zipfile.ZipFile(sys.argv[1]),zipfile.ZipFile(sys.argv[2])
assert za.namelist()==zb.namelist(), "member set/order changed"
pay=["Payload/Demo.app/Demo","Payload/Demo.app/Frameworks/Core.framework/Core"]
res=["Payload/Demo.app/Info.plist","Payload/Demo.app/icon.png"]
assert all(za.read(n)!=zb.read(n) for n in pay), "a payload was not transformed"
assert all(za.read(n)==zb.read(n) for n in res), "a resource changed"
PY
python3 - "$WORK/out.ipa" "$MAUDIT" <<'PY' && ok "re-audit: every Mach-O payload stripped (symbol_count 6->2)" || bad "payloads not stripped in the repack"
import json,sys,subprocess
out=subprocess.check_output(["python3",sys.argv[2],"--json",sys.argv[1]])
d=json.loads(out)
assert all(p["symbol_count"]==2 for p in d["payloads"]), d
PY
# sidecars (private keys) must NOT be inside the repacked container
python3 - "$WORK/out.ipa" <<'PY' && ok "no private sidecars (map/ledger) leaked into the container" || bad "a sidecar leaked into the container"
import zipfile,sys
z=zipfile.ZipFile(sys.argv[1])
assert not any(("carapace" in n or "ledger" in n or n.endswith("map.json")) for n in z.namelist()), z.namelist()
PY

hdr "(D') honest signing limitation + tier + bypass stated"
grep -qi "re-sign\|codesign\|does NOT sign\|NOT DONE" "$WORK/h_ipa.txt" && ok "states the operator must re-sign (does not fake it)" || bad "missing signing limitation"
grep -qi "codesign" "$WORK/h_ipa.txt" && ok "iOS: names codesign + provisioning as the re-sign step" || bad "iOS re-sign step not named"
grep -q "TIER" "$WORK/h_ipa.txt" && grep -qi "BYPASS" "$WORK/h_ipa.txt" && ok "names a strength tier AND a bypass (honesty)" || bad "tier/bypass not stated"
grep -qi "unbreakable" "$WORK/h_ipa.txt" && grep -qi "server-side" "$WORK/h_ipa.txt" && ok "honest footer: nothing unbreakable; server-side is the only Strong tier" || bad "honest footer missing"
# never a FALSE claim of having signed
! grep -Eqi "re-signed (the|your|it)|signature (is )?(now )?valid|successfully signed" "$WORK/h_ipa.txt" && ok "never claims to have signed the container" || bad "made a false signing claim"

# ---------------------------------- (E) harden dispatch + repack — APK (ELF)
hdr "(E) harden DISPATCHES + REPACKS an APK (ELF payload) [needs ELF binutils]"
# Gate on the ACTUAL artifact: build with gcc, then require the output to really
# be ELF (a MinGW/Windows gcc emits PE — then skip, like the bare-ELF slices).
_ELF_READY=0
if command -v gcc >/dev/null 2>&1 && command -v objcopy >/dev/null 2>&1; then
  RD="$WORK/apk_real"; mkdir -p "$RD/lib/arm64-v8a"
  cat > "$WORK/native.c" <<'CEOF'
int carapace_demo_table[4] = {11,22,33,44};
int carapace_demo_check(int x){ return carapace_demo_table[x & 3] + x; }
const char *carapace_demo_msg(void){ return "LICENSE_OK https://api.example.test/activate"; }
CEOF
  if gcc -shared -fPIC -o "$RD/lib/arm64-v8a/libnative.so" "$WORK/native.c" 2>"$WORK/gcc.err" \
     && python3 -c "import sys;sys.exit(0 if open(sys.argv[1],'rb').read(4)==b'\x7fELF' else 1)" "$RD/lib/arm64-v8a/libnative.so"; then
    _ELF_READY=1
  fi
fi
if [ "$_ELF_READY" -eq 1 ]; then
    printf 'binary-xml-manifest' > "$RD/AndroidManifest.xml"
    printf 'dex\n035\000fake' > "$RD/classes.dex"
    mkzip "$RD" "$WORK/real.apk"
    $CARA harden "$WORK/real.apk" --out "$WORK/out.apk" --build-tag slice-r > "$WORK/h_apk.txt" 2>&1; rc=$?
    [ "$rc" -eq 0 ] && ok "carapace harden ran on an APK (rc 0)" || { bad "APK harden failed (rc=$rc)"; cat "$WORK/h_apk.txt"; }
    python3 - "$WORK/real.apk" "$WORK/out.apk" <<'PY' && ok "APK repack: .so transformed; manifest/dex byte-identical; members preserved" || bad "APK repack wrong"
import zipfile,sys
za,zb=zipfile.ZipFile(sys.argv[1]),zipfile.ZipFile(sys.argv[2])
assert za.namelist()==zb.namelist(), "members changed"
so="lib/arm64-v8a/libnative.so"
assert za.read(so)!=zb.read(so), ".so not transformed"
for n in ("AndroidManifest.xml","classes.dex"):
    assert za.read(n)==zb.read(n), f"{n} changed"
PY
    # ELF harden emits PRIVATE sidecars (de-obf map + honeytoken ledger) OUTSIDE the apk
    find "$WORK/out.apk.carapace-private" -type f 2>/dev/null | grep -qi "carapace-map" && \
    find "$WORK/out.apk.carapace-private" -type f 2>/dev/null | grep -qi "honey-ledger" && \
      ok "private map + honeytoken ledger collected OUTSIDE the container" || bad "sidecars not collected outside"
    python3 - "$WORK/out.apk" <<'PY' && ok "no private sidecars leaked into the APK" || bad "sidecar leaked into APK"
import zipfile,sys
z=zipfile.ZipFile(sys.argv[1])
assert not any(("carapace" in n or "ledger" in n) for n in z.namelist()), z.namelist()
PY
    grep -qi "apksigner" "$WORK/h_apk.txt" && ok "Android: names apksigner as the re-sign step" || bad "apksigner re-sign step not named"
else
  skip "no ELF-producing gcc/binutils on this host (e.g. MinGW emits PE) — APK ELF-harden is CI-only, like the bare-ELF slices"
fi

hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
echo "  (audit + Mach-O harden are cross-platform; ELF-payload harden gates on binutils, like the bare-ELF slices)"
[ "$FAIL" -eq 0 ] && { echo "  SLICE R VERIFIED"; exit 0; } || { echo "  SLICE R HAS FAILURES"; exit 1; }

#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice Q (Mach-O harden DEPTH — parity with ELF/PE).
#
# Slice O gave Mach-O a local-symbol strip. Slice Q adds the two remaining post-build
# levers as Mach-O-native constructs, proven STRUCTURALLY / byte-level on Linux with NO
# macOS host (exactly how Slice O/P are proven):
#   (A) DECOY NON-MAPPED SEGMENT + trailer (exhaust) — audit flips absent→present; a real
#       LC_SEGMENT_64 __CARAPACE_EXH with vmsize=0 is spliced into the header pad IN PLACE
#       (surgical: only the mach-header counts + the consumed zero pad change); the decoy
#       trailer sits past mapped_end (non-mapped); the added segment maps nothing (vmsize=0).
#   (B) HONEYTOKENS — audit flips absent→present; tokens unique + plausible (AKIA) +
#       whole-file-strings visible; append-only; attributable via a PRIVATE ledger; inert.
#   (C) the skill drives it (`carapace apply` = strip; `carapace harden` = all three).
#   (D) honest: tier+bypass on every lever, macOS-host caveat printed, fat/32-bit/non-Mach-O
#       refused cleanly, code-signature warnings, no "unbreakable"; and the no-header-pad
#       case falls back to a trailer-only decoy with the -headerpad remedy (not a silent skip).
#
# Runtime-identical + real-dyld acceptance of the decoy segment are platform-gated to a
# macOS host (like Slice O's macOS host and the Slice K VM). Exit 0 = all assertions passed.
set -u
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
HARDEN_DIR="$REPO/harness/harden"
AUDIT="$REPO/harness/audit/macho_exposure_audit.py"
FIX="$REPO/harness/sample/macho_fixture.py"
EXH="$HARDEN_DIR/carapace_macho_exhaust.py"
HONEY="$HARDEN_DIR/carapace_macho_honeytokens.py"
STRIP="$HARDEN_DIR/carapace_macho_strip.py"
CARA="python3 $REPO/skill/carapace.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()  { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "== $* =="; }
jget() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

hdr "BUILD fixtures (toolchain-free; headerpad = room for an added load command)"
python3 "$FIX" --profile soft --headerpad 256 --out "$WORK/mo" >/dev/null 2>&1 \
    && ok "soft Mach-O with header pad built (syms + __cstring + dylib)" || { bad "fixture failed"; exit 1; }
python3 "$FIX" --profile soft --signed --headerpad 256 --out "$WORK/mo_signed" >/dev/null 2>&1 \
    && ok "signed+symbols fixture built (for the strip→sign warning)" || bad "signed fixture failed"
python3 "$FIX" --profile soft --out "$WORK/mo_nopad" >/dev/null 2>&1 \
    && ok "no-header-pad fixture built (for the fallback path)" || bad "nopad fixture failed"
python3 "$FIX" --profile soft --fat --out "$WORK/mo_fat" >/dev/null 2>&1 && ok "fat fixture built" || bad "fat fixture failed"
python3 "$AUDIT" --json "$WORK/mo" > "$WORK/before.json"

# =============================================================(A) DECOY SEGMENT
hdr "(A) DECOY NON-MAPPED SEGMENT + trailer (exhaust)"
python3 "$EXH" "$WORK/mo" "$WORK/mo.exh" --regions 4 --region-size 8192 > "$WORK/exh.txt" 2>&1 \
    && ok "exhaust ran" || { bad "exhaust failed"; cat "$WORK/exh.txt"; }
python3 "$AUDIT" --json "$WORK/mo.exh" > "$WORK/exh.json"
[ "$(jget "$WORK/before.json" decoy_segment_present)" = "False" ] && ok "before: no decoy segment" || bad "pre-exhaust flag wrong"
[ "$(jget "$WORK/exh.json"    decoy_segment_present)" = "True"  ] && ok "after:  decoy segment present" || bad "post-exhaust flag wrong"
[ "$(jget "$WORK/exh.json"    carapace_segment_count)" = "1" ] && ok "exactly one added __CARAPACE segment (load command spliced)" || bad "decoy segment LC not added"

# the added LC_SEGMENT_64 maps NOTHING (vmsize==0, initprot==maxprot==0)
python3 - "$WORK/mo.exh" "$HARDEN_DIR" <<'PY' && ok "added segment has vmsize==0 + prot NONE (dyld ignores it → maps nothing)" || bad "decoy segment is not inert (vmsize/prot not zero)"
import sys, struct
sys.path.insert(0, sys.argv[2])
import carapace_macho_segment as seg
d = open(sys.argv[1], "rb").read()
v = seg.MachOView(d); e = v.e
off = v.hdr; found = None
for _ in range(v.ncmds):
    cmd = struct.unpack_from(e+"I", d, off)[0] & ~seg.LC_REQ_DYLD
    sz  = struct.unpack_from(e+"I", d, off+4)[0]
    if cmd == seg.LC_SEGMENT_64:
        name = d[off+8:off+24].split(b"\x00")[0].decode("latin-1")
        if name.startswith("__CARAPACE"):
            vmsize   = struct.unpack_from(e+"Q", d, off+32)[0]
            maxprot  = struct.unpack_from(e+"i", d, off+56)[0]
            initprot = struct.unpack_from(e+"i", d, off+60)[0]
            nsects   = struct.unpack_from(e+"I", d, off+64)[0]
            found = (vmsize, maxprot, initprot, nsects)
    off += sz
sys.exit(0 if found == (0, 0, 0, 0) else 1)
PY

# surgical splice: the ONLY changed bytes in [0, original_len) are the mach-header
# counts and the consumed header pad — and that pad was zero in the input.
python3 - "$WORK/mo" "$WORK/mo.exh" "$HARDEN_DIR" <<'PY' && ok "surgical splice: every changed in-file byte is a header count or the consumed zero pad" || bad "a byte changed outside the allowed splice region"
import sys
sys.path.insert(0, sys.argv[3])
import carapace_macho_segment as seg
a = open(sys.argv[1], "rb").read()
b = open(sys.argv[2], "rb").read()
v = seg.MachOView(a)
lc_end = v.hdr + v.sizeofcmds
splice = range(lc_end, lc_end + seg.SEG64_CMDSIZE)
counts = range(16, 24)                       # mach_header ncmds + sizeofcmds
if any(a[i] != 0 for i in splice):           # the pad we overwrote must have been zero
    sys.exit(1)
changed = [i for i in range(len(a)) if a[i] != b[i]]
bad = [i for i in changed if i not in counts and i not in splice]
sys.exit(0 if not bad else 1)
PY

# the decoy trailer is appended past mapped_end (non-mapped), at the original EOF
python3 - "$WORK/mo" "$WORK/mo.exh" "$HARDEN_DIR" <<'PY' && ok "decoy trailer sits at original EOF, past mapped_end (non-mapped)" || bad "decoy trailer not provably non-mapped"
import sys
sys.path.insert(0, sys.argv[3])
import carapace_macho_segment as seg
a = open(sys.argv[1], "rb").read()
b = open(sys.argv[2], "rb").read()
me = seg.MachOView(a).mapped_end()
marker = b.find(b"__CARAPACE_MACHO_EXH_")
sys.exit(0 if marker >= len(a) and marker >= me else 1)
PY
grew=$(python3 -c 'import sys;print(len(open(sys.argv[1],"rb").read())-len(open(sys.argv[2],"rb").read()))' "$WORK/mo.exh" "$WORK/mo")
[ "$grew" -gt 30000 ] && ok "analysis surface grew by $grew bytes (4×8 KiB decoys)" || bad "surface did not grow as expected ($grew)"

# ================================================================(B) HONEYTOKENS
hdr "(B) HONEYTOKENS — poison + attribution, provably inert"
python3 "$HONEY" plant "$WORK/mo" "$WORK/mo.honey" --ledger "$WORK/ledger.json" \
    --count 10 --build-tag build-AAA > "$WORK/honey.txt" 2>&1 && ok "plant ran" || { bad "plant failed"; cat "$WORK/honey.txt"; }
python3 "$AUDIT" --json "$WORK/mo.honey" > "$WORK/honey.json"
[ "$(jget "$WORK/before.json" honeytokens_present)" = "False" ] && ok "before: no honeytokens" || bad "pre-plant flag wrong"
[ "$(jget "$WORK/honey.json"  honeytokens_present)" = "True"  ] && ok "after:  honeytokens present" || bad "post-plant flag wrong"
python3 - "$WORK/mo" "$WORK/mo.honey" <<'PY' && ok "plant is append-only (original is a byte-identical prefix; no LC/segment touched)" || bad "plant was not append-only"
import sys
a=open(sys.argv[1],"rb").read(); b=open(sys.argv[2],"rb").read()
sys.exit(0 if b[:len(a)]==a else 1)
PY
python3 -c 'import json,sys
t=[x["value"] for x in json.load(open(sys.argv[1]))["tokens"]]
sys.exit(0 if len(set(t))==len(t) and any(v.startswith("AKIA") for v in t) else 1)' "$WORK/ledger.json" \
    && ok "tokens unique + at least one plausible AWS (AKIA) key" || bad "tokens not unique / no AKIA key"
TOK=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["tokens"][0]["value"])' "$WORK/ledger.json")
[ "$(grep -acF "$TOK" "$WORK/mo.honey")" -ge 1 ] && ok "a honeytoken is visible to a whole-file strings scan" || bad "honeytoken not strings-visible"
python3 "$HONEY" check --ledger "$WORK/ledger.json" --input "$WORK/mo.honey" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 7 ] && ok "attribution: a leaked token is matched back to its build (rc 7)" || bad "attribution did not fire (rc=$rc)"
python3 "$HONEY" check --ledger "$WORK/ledger.json" --input "$WORK/mo" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 0 ] && ok "no false positive against the un-planted binary (rc 0)" || bad "false positive (rc=$rc)"
python3 "$HONEY" plant "$WORK/mo" "$WORK/mo.honey2" --ledger "$WORK/ledger2.json" --count 10 --build-tag build-BBB >/dev/null 2>&1
python3 -c 'import json,sys
a=[x["value"] for x in json.load(open(sys.argv[1]))["tokens"]]
b=[x["value"] for x in json.load(open(sys.argv[2]))["tokens"]]
sys.exit(0 if set(a).isdisjoint(b) else 1)' "$WORK/ledger.json" "$WORK/ledger2.json" \
    && ok "tokens are unique PER BUILD (two build-tags share none)" || bad "tokens collide across builds"

# =====================================================================(C) SKILL
hdr "(C) SKILL drives it (apply = strip; harden = all three)"
$CARA apply "$WORK/mo" --out "$WORK/mo.applied" > "$WORK/apply.txt" 2>&1 \
    && ok "carapace apply ran on a Mach-O" || { bad "carapace apply failed"; cat "$WORK/apply.txt"; }
[ "$(python3 "$AUDIT" --json "$WORK/mo.applied" | python3 -c 'import json,sys;print(json.load(sys.stdin)["symbol_count"])')" = "2" ] \
    && ok "carapace apply stripped LOCAL symbols (6→2)" || bad "carapace apply did not strip"
$CARA harden "$WORK/mo" --out "$WORK/mo.hard" --build-tag CI-run > "$WORK/harden.txt" 2>&1 \
    && ok "carapace harden ran on a Mach-O" || { bad "carapace harden failed"; cat "$WORK/harden.txt"; }
python3 "$AUDIT" --json "$WORK/mo.hard" > "$WORK/hard.json"
[ "$(jget "$WORK/hard.json" symbol_count)" = "2" ] && [ "$(jget "$WORK/hard.json" decoy_segment_present)" = "True" ] && [ "$(jget "$WORK/hard.json" honeytokens_present)" = "True" ] \
    && ok "harden applied all three (locals stripped + decoy segment + honeytokens)" || bad "harden did not apply all three passes"
[ -f "$WORK/mo.hard.honey-ledger.json" ] && ok "harden wrote the PRIVATE honeytoken ledger" || bad "no private ledger written"

# ===================================================================(D) HONEST
hdr "(D) HONEST — tier+bypass, macOS-host caveat, clean refusals, fallback, no overclaim"
grep -qi "runtime-identical + real-dyld acceptance need a macOS host" "$WORK/exh.txt" && ok "exhaust prints the macOS-host (platform-gated) caveat" || bad "exhaust missing the runtime caveat"
grep -qi "bypass" "$WORK/exh.txt" && grep -qi "tier" "$WORK/exh.txt" && ok "exhaust states a tier + a named bypass" || bad "exhaust missing tier/bypass"
grep -qi "nothing here is unbreakable" "$WORK/harden.txt" && ok "harden states the honest negation (nothing is unbreakable)" || bad "harden missing the honest framing"
grep -qi "server-side" "$WORK/harden.txt" && ok "harden surfaces the server-side Strong-tier truth" || bad "harden missing the server-side truth"
# fat is refused cleanly
python3 "$EXH" "$WORK/mo_fat" "$WORK/mo_fat.exh" > "$WORK/fat.txt" 2>&1; rc=$?
[ "$rc" -eq 2 ] && grep -qi "fat" "$WORK/fat.txt" && ! grep -qi Traceback "$WORK/fat.txt" && ok "exhaust refuses a fat/universal binary (rc 2)" || bad "fat not refused cleanly (rc=$rc)"
# a 32-bit thin Mach-O is refused (segment splice is 64-bit only)
printf '\xce\xfa\xed\xfe\x07\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$WORK/mo32"
python3 "$EXH" "$WORK/mo32" "$WORK/mo32.exh" > "$WORK/mo32.txt" 2>&1; rc=$?
[ "$rc" -eq 2 ] && grep -qi "32-bit" "$WORK/mo32.txt" && ok "exhaust refuses a 32-bit Mach-O with guidance (rc 2)" || bad "32-bit not refused cleanly (rc=$rc)"
# a non-Mach-O blob is refused
printf 'this is not a Mach-O file at all, just text' > "$WORK/blob.bin"
python3 "$HONEY" plant "$WORK/blob.bin" "$WORK/blob.out" --ledger "$WORK/bl.json" > "$WORK/blob.txt" 2>&1; rc=$?
[ "$rc" -eq 2 ] && ! grep -qi Traceback "$WORK/blob.txt" && ok "honeytokens refuses a non-Mach-O blob cleanly (rc 2)" || bad "non-Mach-O not refused cleanly (rc=$rc)"
# signed → warning on both levers
python3 "$EXH" "$WORK/mo_signed" "$WORK/mo_signed.exh" --regions 1 --region-size 256 2>&1 | grep -qi "invalidates it" && ok "exhaust warns that appending/splicing invalidates a signature" || bad "exhaust missing the signed warning"
python3 "$HONEY" plant "$WORK/mo_signed" "$WORK/mo_signed.honey" --ledger "$WORK/sled.json" 2>&1 | grep -qi "invalidates it" && ok "honeytokens warns on a signed Mach-O" || bad "honeytokens missing the signed warning"

hdr "(E) FALLBACK — no header pad: trailer decoy still applied, LC honestly deferred"
python3 "$EXH" "$WORK/mo_nopad" "$WORK/mo_nopad.exh" --regions 1 --region-size 256 > "$WORK/nopad.txt" 2>&1 \
    && ok "exhaust ran on a no-pad Mach-O (did not corrupt / did not hard-fail)" || bad "exhaust failed on no-pad input"
grep -qi "NOT added" "$WORK/nopad.txt" && grep -qi "headerpad" "$WORK/nopad.txt" && ok "no-pad: load command honestly deferred with the -headerpad remedy" || bad "no-pad fallback not reported honestly"
[ "$(python3 "$AUDIT" --json "$WORK/mo_nopad.exh" | python3 -c 'import json,sys;print(json.load(sys.stdin)["decoy_segment_present"])')" = "True" ] \
    && ok "no-pad: the decoy trailer is still present (marker detected)" || bad "no-pad: decoy trailer missing"
[ "$(python3 "$AUDIT" --json "$WORK/mo_nopad.exh" | python3 -c 'import json,sys;print(json.load(sys.stdin)["carapace_segment_count"])')" = "0" ] \
    && ok "no-pad: no load command was spliced (count 0) — matches the honest report" || bad "no-pad: a segment was unexpectedly added"

hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
echo "  (structural proof — runtime-identical + real-dyld acceptance are platform-gated to a macOS host)"
[ "$FAIL" -eq 0 ] && { echo "  SLICE Q VERIFIED"; exit 0; } || { echo "  SLICE Q HAS FAILURES"; exit 1; }

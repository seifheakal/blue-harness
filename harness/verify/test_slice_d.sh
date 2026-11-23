#!/usr/bin/env bash
# blue-harness — VERIFY harness for Implementation Slice D (runtime code-integrity +
# server-nonce attestation, and the anti-Frida detector; rea Cluster G).
#
# Proves, on a real sample ELF, WITHOUT installing any offensive tooling (we
# reproduce the exact OS footprint Frida leaves and patch the on-disk code):
#   (A) the AUDIT detects both new guards present<->absent;
#   (B) integrity/attestation FIRES: the C client MAC matches the stdlib server
#       (SHA-256/HMAC correct) so a pristine build is ACCEPTED; a patched hot
#       function is REJECTED; a replayed response is REJECTED;
#   (C) the anti-Frida detector FIRES: a clean process is clean, and a process
#       carrying a frida-agent mapping + a gum-js-loop thread + a :27042 listener
#       is detected on all three signals.
#
# Exit 0 = all hard assertions passed. Nonzero = at least one failed.
set -u

cd "$(dirname "$0")"
SAMPLE_DIR="$(cd ../sample && pwd)"
HARDEN_DIR="$(cd ../harden && pwd)"
AUDIT="$(cd ../audit && pwd)/elf_exposure_audit.py"
SRV="python3 $HARDEN_DIR/attest_server.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()  { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "== $* =="; }

jbool() { python3 -c 'import json,sys;print(str(json.load(open(sys.argv[1]))[sys.argv[2]]).lower())' "$1" "$2"; }

# ---------------------------------------------------------------- build ----
hdr "BUILD"
make -C "$SAMPLE_DIR" clean >/dev/null 2>&1
if make -C "$SAMPLE_DIR" sample_attest sample_baseline >/tmp/bh_d_build.log 2>&1; then
    ok "sample_attest + sample_baseline built"
else
    bad "build failed"; cat /tmp/bh_d_build.log; exit 1
fi
ATT="$SAMPLE_DIR/sample_attest"
# a stand-in for an injected frida agent (path carries the real signature)
echo 'int _bh_fake_agent;' > "$WORK/fa.c"
cc -shared -fPIC -o "$WORK/frida-agent-x86_64.so" "$WORK/fa.c" && ok "built frida-agent signature .so (no real Frida installed)" || bad "fake agent build failed"

# ------------------------------------------------ (A) audit flip ----------
hdr "(A) AUDIT detects the new guards"
python3 "$AUDIT" --json "$SAMPLE_DIR/sample_baseline" > "$WORK/a_base.json"
python3 "$AUDIT" --json "$ATT" > "$WORK/a_att.json"
[ "$(jbool "$WORK/a_base.json" integrity_guard_present)" = "false" ] && ok "baseline: integrity guard ABSENT" || bad "baseline integrity should be absent"
[ "$(jbool "$WORK/a_base.json" antifrida_guard_present)" = "false" ] && ok "baseline: anti-Frida guard ABSENT" || bad "baseline anti-frida should be absent"
[ "$(jbool "$WORK/a_att.json" integrity_guard_present)" = "true" ] && ok "sample_attest: integrity guard PRESENT" || bad "attest integrity should be present"
[ "$(jbool "$WORK/a_att.json" antifrida_guard_present)" = "true" ] && ok "sample_attest: anti-Frida guard PRESENT" || bad "attest anti-frida should be present"

# ---------------------------------------- (B) integrity/attestation -------
hdr "(B) integrity + server-nonce attestation FIRES"
GOOD="$("$ATT" checksum)"
echo "    known-good hot-fn checksum: $GOOD"

# pristine: server nonce -> client responds -> ACCEPT (also proves C HMAC == stdlib)
N1="$($SRV nonce)"
M1="$("$ATT" attest "$N1")"
if $SRV verify --good "$GOOD" --nonce "$N1" --mac "$M1" >/dev/null; then
    ok "pristine attestation ACCEPTED (C SHA-256/HMAC matches the stdlib server)"
else
    bad "pristine attestation should be accepted"
fi

# tamper: patch the hot-fn license compare constant (0x5AFE6A11) on disk
cp "$ATT" "$WORK/tampered"
python3 - "$WORK/tampered" <<'PY'
import sys, struct
p=sys.argv[1]; d=bytearray(open(p,'rb').read())
# Patch the compare constant 0x5AFE6A11 -> 0x5AFE6A12 (a real crack's patch; the
# binary still runs, so only the server can stop it). Its encoding is per-arch.
how=None
i=d.find(bytes([0x11,0x6A,0xFE,0x5A]))      # x86-64: contiguous LE imm32
if i>=0:
    d[i]=0x12; how="x86-64 imm32"
else:
    # AArch64: the constant is built as `movz wN,#0x6a11` + `movk wN,#0x5afe,lsl 16`.
    # Rewrite only the imm16 field of the 32-bit MOVZ — still a valid instruction.
    # Mask 0xFFE00000 pins sf=0 (32-bit W reg), opc=MOVZ and hw=0 (no shift), so a
    # 64-bit `movz xN` or a shifted `movz ...,lsl 16` with the same imm16 never matches.
    for i in range(0, len(d)-3, 4):
        insn=struct.unpack_from('<I', d, i)[0]
        if insn & 0xFFE00000 == 0x52800000 and (insn>>5) & 0xFFFF == 0x6A11:
            insn=(insn & ~(0xFFFF<<5)) | (0x6A12<<5)
            struct.pack_into('<I', d, i, insn); how="aarch64 movz imm16"; break
assert how, "hot-fn marker not found (x86-64 or aarch64) — cannot run tamper test"
open(p,'wb').write(d)
print(f"    patched hot function ({how}) at file offset {i}")
PY
TAMP_CS="$("$WORK/tampered" checksum)"
[ "$TAMP_CS" != "$GOOD" ] && ok "patched hot function changes the checksum ($GOOD != $TAMP_CS)" || bad "checksum did not change on patch"
MT="$("$WORK/tampered" attest "$N1")"
if $SRV verify --good "$GOOD" --nonce "$N1" --mac "$MT" >/dev/null; then
    bad "tampered binary was accepted — integrity check did NOT fire"
else
    ok "tampered binary REJECTED by the server (checksum mismatch)"
fi
# and the attacker's patched app still runs locally — the server is what stops it
"$WORK/tampered" run | grep -q "ran OK" && ok "tampered binary still runs locally (server-side is the gate)" || bad "tampered binary failed to run"

# replay: a valid old response, but the server issues a fresh nonce
N2="$($SRV nonce)"
if $SRV verify --good "$GOOD" --nonce "$N2" --mac "$M1" >/dev/null; then
    bad "replayed response accepted — nonce binding did NOT fire"
else
    ok "replayed response REJECTED (fresh nonce defeats replay)"
fi

# ------------------------------------------------ (C) anti-Frida ----------
hdr "(C) anti-Frida detector FIRES"
clean="$("$ATT" antifrida)"; crc=$?
[ "$clean" = "clean" ] && [ $crc -eq 0 ] && ok "clean process reports no Frida (no false positive)" || bad "clean scan wrong: '$clean' rc=$crc"

planted="$("$ATT" antifrida-plant "$WORK/frida-agent-x86_64.so")"; prc=$?
echo "    planted scan: $planted"
[ $prc -ne 0 ] && ok "planted process detected (nonzero exit)" || bad "planted process not detected"
for sig in maps threads port27042; do
    case "$planted" in *"$sig"*) ok "signal fired: $sig";; *) bad "signal missed: $sig";; esac
done

# ------------------------------------------------------------- summary -----
hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "  SLICE D VERIFIED"; exit 0; } || { echo "  SLICE D HAS FAILURES"; exit 1; }

#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice M (format dispatch: route audit/report by magic).
#
# The Slice-G PE scanner existed but was only reachable via `make audit-pe`. This
# slice teaches the skill to detect the format by magic byte and route the one
# `audit`/`report`/`recommend` front door to the right scanner. Since Slice P, a
# PE also has a post-build harden path, so apply/harden DISPATCH a PE to the PE
# hardener (writing a separate output, leaving the input untouched) rather than
# refusing — the ELF-only transforms are never faked onto a PE.
#
# Proves:
#   (A) `carapace audit` routes ELF→ELF scanner, PE→PE scanner;
#   (B) `report`/`recommend` on a PE render the PE audit + the format-independent
#       server-side truth, and never claim an ELF-only hardening;
#   (C) `apply`/`harden` DISPATCH a PE to the PE hardener (rc 0) and leave the
#       INPUT byte-identical (output is a separate file — nothing mangled in place);
#   (D) the ELF path is unregressed (full ordered plan still renders);
#   (E) an unsupported blob errors cleanly (no traceback).
#
# Exit 0 = all hard assertions passed.
set -u
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
SAMPLE_DIR="$(cd ../sample && pwd)"
CARA="python3 $REPO/skill/carapace.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()  { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "== $* =="; }

hdr "BUILD + FIXTURE"
make -C "$SAMPLE_DIR" sample_dev >/dev/null 2>&1 && ok "sample_dev (ELF) built" || { bad "ELF build failed"; exit 1; }
ELF="$SAMPLE_DIR/sample_dev"
PE="$WORK/fixture.exe"
python3 "$SAMPLE_DIR/pe_fixture.py" --profile soft --out "$PE" >/dev/null 2>&1 \
    && ok "PE fixture generated" || { bad "PE fixture failed"; exit 1; }

hdr "(A) carapace audit routes by magic"
$CARA audit "$ELF" > "$WORK/a_elf.txt" 2>&1
grep -q "ELF Exposure Audit" "$WORK/a_elf.txt" && ok "ELF → ELF scanner" || bad "ELF not routed to ELF scanner"
$CARA audit "$PE" > "$WORK/a_pe.txt" 2>&1
grep -q "PE Exposure Audit" "$WORK/a_pe.txt" && ok "PE → PE scanner" || bad "PE not routed to PE scanner"

hdr "(B) report/recommend on PE: PE audit + server-side truth, no ELF overclaim"
$CARA report "$PE" > "$WORK/r_pe.txt" 2>&1
grep -q "PE Exposure Audit" "$WORK/r_pe.txt" && ok "report renders the PE audit" || bad "PE report missing the audit"
grep -qi "server-side" "$WORK/r_pe.txt" && ok "report surfaces the server-side Strong truth" || bad "server-side truth missing on PE"
# must NOT claim an ELF-only build-time guard was applicable here
grep -qi "carapace_guards.c\|PTRACE_TRACEME\|core-dump suppression guard" "$WORK/r_pe.txt" \
    && bad "PE report leaked an ELF-only hardening recommendation" || ok "no ELF-only hardening claimed on PE"
$CARA recommend "$PE" > "$WORK/rec_pe.txt" 2>&1
grep -q "\[PE\]" "$WORK/rec_pe.txt" && ok "recommend labels the PE format" || bad "recommend didn't mark PE"

hdr "(C) apply/harden DISPATCH a PE to the PE hardener (rc 0), input untouched"
$CARA harden "$PE" --out "$WORK/h.hardened.exe" > "$WORK/h.txt" 2>&1; rc=$?
[ "$rc" -eq 0 ] && grep -qi "harden (PE)" "$WORK/h.txt" && ok "harden dispatches a PE to the PE hardener (rc 0)" || bad "harden did not dispatch the PE (rc=$rc)"
$CARA apply "$PE" --out "$WORK/ap.stripped.exe" > "$WORK/ap.txt" 2>&1; rc=$?
[ "$rc" -eq 0 ] && grep -qi "PE COFF-symbol" "$WORK/ap.txt" && ok "apply dispatches a PE to the PE strip (rc 0)" || bad "apply did not dispatch the PE (rc=$rc)"
# the INPUT PE must be untouched (byte-identical) — outputs are separate files
python3 "$SAMPLE_DIR/pe_fixture.py" --profile soft --out "$WORK/fixture_ref.exe" >/dev/null 2>&1
cmp -s "$PE" "$WORK/fixture_ref.exe" && ok "input PE left byte-identical (output is a separate file)" || bad "input PE was modified in place"

hdr "(D) ELF path unregressed (full ordered plan)"
$CARA report "$ELF" > "$WORK/r_elf.txt" 2>&1
grep -q "Ordered hardening plan" "$WORK/r_elf.txt" && ok "ELF report still renders the ordered plan" || bad "ELF report regressed"

hdr "(E) unsupported blob errors cleanly"
printf 'just some text, not a binary\n' > "$WORK/blob.txt"
$CARA audit "$WORK/blob.txt" > "$WORK/blob.out" 2>&1; rc=$?
[ "$rc" -ne 0 ] && ! grep -qi "Traceback" "$WORK/blob.out" && ok "non-binary rejected cleanly (no traceback)" || bad "unsupported blob not handled cleanly (rc=$rc)"

hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "  SLICE M VERIFIED"; exit 0; } || { echo "  SLICE M HAS FAILURES"; exit 1; }

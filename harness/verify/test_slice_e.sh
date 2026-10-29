#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice E (the front-door one-shot `report`).
# Slice E ships no new countermeasure; this covers the new skill code so the
# "done = tested" rule still holds. (run_all.sh runs this alongside A–D.)
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

hdr "BUILD"
make -C "$SAMPLE_DIR" sample_dev >/dev/null 2>&1 && ok "sample_dev built" || { bad "build failed"; exit 1; }

hdr "carapace report (audit + ordered plan in one call)"
$CARA report "$SAMPLE_DIR/sample_dev" > "$WORK/report.txt" 2>&1 && ok "report exits 0" || bad "report exited nonzero"

grep -q "EXPOSURE SCORE" "$WORK/report.txt" && ok "report includes the full audit" || bad "audit section missing"
grep -q "Ordered hardening plan" "$WORK/report.txt" && ok "report includes the ordered plan" || bad "plan section missing"

# the plan must carry a tier AND a bypass on every listed item
ntier=$(grep -c "strength tier" "$WORK/report.txt")
nbypass=$(grep -c "named bypass" "$WORK/report.txt")
[ "$ntier" -ge 1 ] && [ "$ntier" -eq "$nbypass" ] && ok "every plan item carries a tier + a named bypass ($ntier each)" \
    || bad "tier/bypass mismatch (tiers=$ntier bypasses=$nbypass)"

# honesty: every mention of "unbreakable" must be a NEGATION (never/nothing/not),
# never a positive claim.
if grep -iq unbreakable "$WORK/report.txt"; then
    if grep -i unbreakable "$WORK/report.txt" | grep -viqE "never|nothing|not|isn't"; then
        bad "report contains an overclaiming 'unbreakable' statement"
    else
        ok "no overclaim: 'unbreakable' appears only in honest negations"
    fi
else
    ok "no 'unbreakable' claim in report"
fi

# the server-side-truth (only Strong tier) must be surfaced
grep -qi "server-side\|server-relocation\|off the client" "$WORK/report.txt" \
    && ok "server-side relocation (the only Strong tier) is surfaced" || bad "server-side truth missing"

hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "  SLICE E VERIFIED"; exit 0; } || { echo "  SLICE E HAS FAILURES"; exit 1; }

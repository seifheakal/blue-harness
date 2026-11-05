#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice L (one-command `harden` + skill `install`).
#
# Proves:
#   (A) `carapace harden` applies EVERY applicable post-build pass in one command
#       (identity decoy -> exhaust -> honeytokens), emitting the hardened binary +
#       the PRIVATE key artifacts;
#   (B) it is NON-BREAKING: the hardened binary runs with byte-identical output;
#   (C) it is HONEST: it lists the build-time guards as "needs a rebuild" (never
#       fakes them), surfaces the server-side Strong tier, puts a tier + bypass on
#       every applied item, and never overclaims;
#   (D) `carapace install` symlinks the skill into .claude/skills/carapace and
#       refuses to clobber a real directory.
#
# Exit 0 = all hard assertions passed.
set -u
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
SAMPLE_DIR="$(cd ../sample && pwd)"
AUDIT="$(cd ../audit && pwd)/elf_exposure_audit.py"
CARA="python3 $REPO/skill/carapace.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()  { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "== $* =="; }
jget() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

hdr "BUILD + harden (one command)"
make -C "$SAMPLE_DIR" sample_dev >/dev/null 2>&1 && ok "sample_dev built" || { bad "build failed"; exit 1; }
APP="$WORK/app"; cp "$SAMPLE_DIR/sample_dev" "$APP"
$CARA harden "$APP" --build-tag "slice-L" > "$WORK/harden.txt" 2>&1 \
    && ok "carapace harden exits 0" || { bad "harden failed"; cat "$WORK/harden.txt"; exit 1; }
HARD="$APP.hardened"
[ -f "$HARD" ] && ok "hardened binary produced (<bin>.hardened)" || bad "no hardened binary"

hdr "(A) every applicable POST-BUILD pass applied"
grep -q "identity transform" "$WORK/harden.txt" && ok "identity transform applied" || bad "identity transform missing"
[ -f "$APP.hardened.carapace-map.json" ] && ok "private symbol map written" || bad "no private map"
python3 "$AUDIT" --json "$HARD" > "$WORK/a.json"
[ "$(jget "$WORK/a.json" exhaustion_present)" = "True" ] && ok "exhaustion present in hardened binary" || bad "exhaustion missing"
[ "$(jget "$WORK/a.json" honeytokens_present)" = "True" ] && ok "honeytokens present in hardened binary" || bad "honeytokens missing"
[ -f "$APP.hardened.honey-ledger.json" ] && ok "private honeytoken ledger written" || bad "no ledger"

hdr "(B) NON-BREAKING"
out_base="$("$APP")"; out_hard="$("$HARD")"
[ "$out_base" = "$out_hard" ] && ok "hardened runs with byte-identical output (\"$out_hard\")" || bad "runtime differs: '$out_base' vs '$out_hard'"

hdr "(C) HONEST (build-time deferred, Strong surfaced, tier+bypass, no overclaim)"
grep -q "NOT APPLIED — build-time" "$WORK/harden.txt" && ok "build-time guards listed as needing a rebuild (not faked)" || bad "build-time items not deferred honestly"
grep -q "Add anti-ptrace" "$WORK/harden.txt" && grep -q "Add core-dump" "$WORK/harden.txt" && ok "names specific deferred build-time guards" || bad "deferred guards not named"
grep -q "THE ONLY STRONG TIER" "$WORK/harden.txt" && ok "surfaces the server-side Strong tier" || bad "Strong tier not surfaced"
# every applied item carries a tier AND a bypass
na=$(grep -c "✓ " "$WORK/harden.txt"); nt=$(grep -c "tier   :" "$WORK/harden.txt"); nb=$(grep -c "bypass :" "$WORK/harden.txt")
[ "$na" -ge 1 ] && [ "$na" -eq "$nt" ] && [ "$na" -eq "$nb" ] && ok "every applied item carries a tier + bypass ($na each)" || bad "tier/bypass mismatch (applied=$na tier=$nt bypass=$nb)"
# honesty: 'unbreakable' only ever in a negation
if grep -iq unbreakable "$WORK/harden.txt"; then
    grep -i unbreakable "$WORK/harden.txt" | grep -viqE "never|nothing|not|isn't" \
        && bad "overclaiming 'unbreakable' statement" || ok "no overclaim: 'unbreakable' only in honest negation"
else
    ok "no 'unbreakable' claim"
fi

hdr "(D) skill install"
$CARA install --dir "$WORK/skills" >/dev/null 2>&1 && [ -f "$WORK/skills/carapace/SKILL.md" ] \
    && ok "install symlinks the skill (SKILL.md reachable)" || bad "install did not create a working skill link"
$CARA install --dir "$WORK/skills" >/dev/null 2>&1 && ok "install is idempotent (re-run OK)" || bad "re-install failed"
rm -f "$WORK/skills/carapace"; mkdir -p "$WORK/skills/carapace"; : > "$WORK/skills/carapace/real"
$CARA install --dir "$WORK/skills" >/dev/null 2>&1; [ "$?" -eq 2 ] && ok "install refuses to clobber a real directory (rc=2)" || bad "install clobbered or wrong rc"

hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "  SLICE L VERIFIED"; exit 0; } || { echo "  SLICE L HAS FAILURES"; exit 1; }

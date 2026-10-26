#!/usr/bin/env bash
# Carapace — VERIFY harness for Implementation Slice C (the drive-the-harness
# skill: audit -> recommend -> apply). A prose-only skill can't be verified, so
# the skill's behavior lives in skill/carapace.py and is proven here.
#
# Proves:
#   (A) audit runs and reports an exposure posture;
#   (B) recommend yields the next highest-value hardening, with a strength tier
#       AND a named bypass on every item, and never claims unbreakability;
#   (C) apply applies the post-build hardening (identity transform) and the app
#       still runs; the recommendation then ADVANCES and the score drops; and a
#       build-time hardening is honestly REFUSED (not faked onto a built binary).
#
# Exit 0 = all hard assertions passed. Nonzero = at least one failed.
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

# -------------------------------------------------------------- build ------
hdr "BUILD dev target"
make -C "$SAMPLE_DIR" clean >/dev/null 2>&1
make -C "$SAMPLE_DIR" sample_dev >/dev/null 2>&1 && ok "sample_dev built" || { bad "build failed"; exit 1; }
cp "$SAMPLE_DIR/sample_dev" "$WORK/target"
DEV_OUT="$("$WORK/target" run)"

# ----------------------------------------------------- (A) audit -----------
hdr "(A) carapace audit"
if $CARA audit "$WORK/target" > "$WORK/audit.txt" 2>&1; then
    grep -q "EXPOSURE SCORE" "$WORK/audit.txt" && ok "audit prints an exposure posture" || bad "audit missing score"
else
    bad "audit exited nonzero"; cat "$WORK/audit.txt"
fi

# ------------------------------------------------ (B) recommend ------------
hdr "(B) carapace recommend (honest tier + named bypass)"
$CARA recommend --json "$WORK/target" > "$WORK/rec.json" 2>&1
$CARA recommend --all --json "$WORK/target" > "$WORK/recall.json" 2>&1

python3 - "$WORK/rec.json" "$WORK/recall.json" <<'PY' && ok "recommend JSON well-formed; honesty fields present" || bad "recommend JSON/honesty checks failed"
import json,sys
rec=json.load(open(sys.argv[1])); allrec=json.load(open(sys.argv[2]))
top=rec["recommendations"][0]
assert top["id"]=="identity-transform", f"top should be identity-transform, got {top['id']}"
assert top["kind"]=="post-build", top["kind"]
plan=[r["id"] for r in allrec["recommendations"]]
# ordered plan: identity first, guards next, server-relocation present (Strong truth)
assert plan[0]=="identity-transform", plan
assert "coredump-guard" in plan and "antiptrace-guard" in plan, plan
assert plan[-1]=="server-relocation", plan
srv=[r for r in allrec["recommendations"] if r["id"]=="server-relocation"][0]
assert "Strong" in srv["tier"], srv["tier"]
# every recommendation carries a tier AND a named bypass, and none overclaims
for r in allrec["recommendations"]:
    assert r["tier"].strip(), r
    assert r["bypass"].strip(), r
    blob=(r["tier"]+r["title"]+r["bypass"]).lower()
    assert "unbreakable" not in blob, f"overclaim in {r['id']}"
print("recommend structured checks OK")
PY

# the human readout must carry the honest footer (never claims unbreakable)
$CARA recommend "$WORK/target" > "$WORK/rec.txt" 2>&1
grep -q "never makes software" "$WORK/rec.txt" && ok "human readout carries the honest no-overclaim footer" || bad "missing honest footer"
tier_top=$(python3 -c 'import json;print(json.load(open("'"$WORK"'/rec.json"))["recommendations"][0]["tier"])')
echo "    top rec: identity-transform — tier: $tier_top"

# ------------------------------------------------ (C) apply ---------------
hdr "(C) carapace apply (post-build fires; build-time honestly refused)"
$CARA apply "$WORK/target" --mode S --out "$WORK/target.release" --map "$WORK/target.map.json" > "$WORK/apply.txt" 2>&1
rc=$?
[ $rc -eq 0 ] && [ -f "$WORK/target.release" ] && ok "apply produced the hardened artifact + private map" || { bad "apply failed (rc=$rc)"; cat "$WORK/apply.txt"; }

REL_OUT="$("$WORK/target.release" run)"
[ "$REL_OUT" = "$DEV_OUT" ] && ok "hardened artifact still runs (identical output)" || bad "output changed: '$REL_OUT' != '$DEV_OUT'"

# recommendation advances + score drops after the strip
s_before=$(python3 -c 'import json;print(json.load(open("'"$WORK"'/rec.json"))["score"])')
$CARA recommend --json "$WORK/target.release" > "$WORK/rec2.json" 2>&1
top2=$(python3 -c 'import json;print(json.load(open("'"$WORK"'/rec2.json"))["recommendations"][0]["id"])')
s_after=$(python3 -c 'import json;print(json.load(open("'"$WORK"'/rec2.json"))["score"])')
[ "$top2" = "coredump-guard" ] && ok "recommendation advanced after strip (identity-transform -> coredump-guard)" \
    || bad "recommendation did not advance (top is $top2)"
[ "$s_after" -lt "$s_before" ] && ok "exposure score dropped after apply ($s_before -> $s_after)" \
    || bad "score did not drop ($s_before -> $s_after)"

# build-time hardening must be honestly refused (not patched onto a built binary)
$CARA apply "$WORK/target.release" > "$WORK/apply2.txt" 2>&1
rc2=$?
if [ $rc2 -eq 3 ] && grep -qiE "cannot be patched|build-time|rebuild" "$WORK/apply2.txt"; then
    ok "build-time guard apply honestly refused (points to rebuild, rc=3)"
else
    bad "build-time apply should refuse with guidance (rc=$rc2)"; cat "$WORK/apply2.txt"
fi

# ------------------------------------------------------------- summary -----
hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "  SLICE C VERIFIED"; exit 0; } || { echo "  SLICE C HAS FAILURES"; exit 1; }

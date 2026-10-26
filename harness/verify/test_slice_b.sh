#!/usr/bin/env bash
# Carapace — VERIFY harness for Implementation Slice B (dev<->release identity
# transform: the AI-layer decoy play).
#
# Proves, on a real sample ELF, the three claims from docs/STATE.md step 3:
#   (A) the AUDIT measures the transform — informativeness changes dev->release;
#   (B) the private MAPPING round-trips  — every release name resolves to its dev
#       original, and NO dev name leaks into the shipped artifact;
#   (C) the app STILL RUNS unchanged      — byte-identical output in every mode;
#   plus the honest distinguishing property: Mode D stays *plausible* (reads as
#   English) where Mode M/S read as opaque — so D avoids the "obfuscated" tell.
#
# Exit 0 = all hard assertions passed. Nonzero = at least one failed.
set -u

cd "$(dirname "$0")"
SAMPLE_DIR="$(cd ../sample && pwd)"
AUDIT="$(cd ../audit && pwd)/elf_exposure_audit.py"
TX="$(cd ../harden && pwd)/carapace_identity_transform.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP  $*"; SKIP=$((SKIP+1)); }
hdr()  { echo; echo "== $* =="; }

# informativeness field extractor: field name -> value
inf() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["informativeness"][sys.argv[2]])' "$1" "$2"; }

# ---------------------------------------------------------------- build ----
hdr "BUILD dev artifact"
make -C "$SAMPLE_DIR" clean >/dev/null 2>&1
if make -C "$SAMPLE_DIR" sample_dev >/tmp/carapace_b_build.log 2>&1; then
    ok "sample_dev built (clean, unstripped, with symbols)"
else
    bad "build failed"; cat /tmp/carapace_b_build.log; exit 1
fi
DEV="$SAMPLE_DIR/sample_dev"
DEV_OUT="$("$DEV" run)"

# internal, never-printed string + its same-length decoy (29 chars each)
OLD="build:prod-eu-signing-slot-03"
NEW="trace:warm-eu-metrics-slot-7a"
[ "${#OLD}" -eq "${#NEW}" ] && ok "string-decoy pair is same length (${#OLD})" \
    || bad "decoy pair length mismatch ${#OLD} vs ${#NEW}"
python3 -c "import json;json.dump([['$OLD','$NEW']],open('$WORK/sdec.json','w'))"

# transform in all three modes (D carries the string decoy too)
python3 "$TX" transform --mode S --in "$DEV" --out "$WORK/rel_S" --map "$WORK/map_S.json" >/dev/null
python3 "$TX" transform --mode M --in "$DEV" --out "$WORK/rel_M" --map "$WORK/map_M.json" >/dev/null
python3 "$TX" transform --mode D --in "$DEV" --out "$WORK/rel_D" --map "$WORK/map_D.json" --string-decoys "$WORK/sdec.json" >/dev/null
ok "produced release binaries + private maps for modes S / M / D"

# audit each
python3 "$AUDIT" --json "$DEV"        > "$WORK/a_dev.json"
python3 "$AUDIT" --json "$WORK/rel_S" > "$WORK/a_S.json"
python3 "$AUDIT" --json "$WORK/rel_M" > "$WORK/a_M.json"
python3 "$AUDIT" --json "$WORK/rel_D" > "$WORK/a_D.json"

# -------------------------------------------- (A) audit measures it --------
hdr "(A) AUDIT measures the identity transform"
dev_total=$(inf "$WORK/a_dev.json" symbol_total)
dev_ratio=$(inf "$WORK/a_dev.json" symbol_informative_ratio)
echo "    dev: $dev_total own symbols, informative ratio=$dev_ratio"
[ "$dev_total" -gt 0 ] && ok "dev exposes named symbols (control: $dev_total)" || bad "dev should expose symbols"
python3 -c "import sys;sys.exit(0 if float('$dev_ratio')>=0.9 else 1)" \
    && ok "dev symbols read as English (ratio=$dev_ratio)" || bad "dev ratio should be high"

s_total=$(inf "$WORK/a_S.json" symbol_total)
[ "$s_total" -eq 0 ] && ok "Mode S: symbols stripped (symbol_total=0)" || bad "Mode S should strip symbols (got $s_total)"

m_ratio=$(inf "$WORK/a_M.json" symbol_informative_ratio)
m_total=$(inf "$WORK/a_M.json" symbol_total)
python3 -c "import sys;sys.exit(0 if float('$m_ratio')<=0.1 else 1)" \
    && ok "Mode M: $m_total symbols present but OPAQUE (ratio=$m_ratio)" || bad "Mode M should be opaque (ratio=$m_ratio)"

d_ratio=$(inf "$WORK/a_D.json" symbol_informative_ratio)
d_total=$(inf "$WORK/a_D.json" symbol_total)
python3 -c "import sys;sys.exit(0 if float('$d_ratio')>=0.9 else 1)" \
    && ok "Mode D: $d_total symbols present and still PLAUSIBLE (ratio=$d_ratio)" || bad "Mode D should stay plausible (ratio=$d_ratio)"

# The distinguishing property: D avoids the "opaque => obfuscated" tell that M/S give.
python3 -c "import sys;sys.exit(0 if float('$d_ratio')>float('$m_ratio') else 1)" \
    && ok "Mode D reads more natural than Mode M (avoids the obfuscation tell)" || bad "D should out-plausible M"

# ------------------------------------------- (B) mapping round-trips -------
hdr "(B) private MAPPING round-trips; no dev name leaks"
# dev identity set (<=12, we have 5)
DEVSYMS=$(python3 -c 'import json;print("\n".join(json.load(open("'"$WORK"'/a_dev.json"))["informativeness"]["sample_symbols"]))')
echo "    dev identity: $(echo "$DEVSYMS" | tr "\n" " ")"

check_roundtrip() { # $1 map, $2 label
    python3 - "$1" "$2" <<'PY'
import json,sys,subprocess,os
mapp, label = sys.argv[1], sys.argv[2]
m=json.load(open(mapp))
devset=set(json.load(open(os.path.join(os.path.dirname(mapp),"a_dev.json")))["informativeness"]["sample_symbols"])
syms=m["symbols"]            # release_name -> dev_name
# every release name resolves (via the CLI) back to its recorded dev original
tx=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(mapp))),"")  # unused
bad=0
for rel,dev in syms.items():
    out=subprocess.run(["python3", os.environ["TXPATH"], "resolve","--map",mapp,rel],
                       capture_output=True,text=True).stdout.strip()
    if out!=dev: print(f"    round-trip MISMATCH {rel} -> {out} (want {dev})"); bad=1
recovered=set(syms.values())
# recovered originals must equal the dev identity set (nothing lost/extra)
if recovered!=devset:
    print(f"    recovered set != dev set: missing={devset-recovered} extra={recovered-devset}"); bad=1
print("RTOK" if not bad else "RTFAIL")
PY
}
export TXPATH="$TX"
for mode in M D; do
    res=$(check_roundtrip "$WORK/map_${mode}.json" "$mode" | tail -1)
    [ "$res" = "RTOK" ] && ok "Mode $mode: every release symbol resolves to its dev original (full set)" \
        || bad "Mode $mode: mapping round-trip failed"
done
# string decoy round-trips too
sres=$(python3 "$TX" resolve --map "$WORK/map_D.json" "$NEW")
[ "$sres" = "$OLD" ] && ok "Mode D: internal string decoy resolves ('$NEW' -> '$OLD')" || bad "string decoy did not resolve ($sres)"

# no dev identity leaks into ANY shipped artifact
leak=0
for f in rel_S rel_M rel_D; do
    while IFS= read -r dn; do
        [ -z "$dn" ] && continue
        if nm "$WORK/$f" 2>/dev/null | grep -qw "$dn"; then
            echo "    LEAK: dev name '$dn' present in $f"; leak=1
        fi
        if strings "$WORK/$f" | grep -qw "$dn"; then
            echo "    LEAK(str): dev name '$dn' present in $f"; leak=1
        fi
    done <<< "$DEVSYMS"
done
[ "$leak" -eq 0 ] && ok "no dev symbol name leaks into rel_S / rel_M / rel_D" || bad "a dev name leaked into a release artifact"
# and the real internal string is gone from the decoy build
strings "$WORK/rel_D" | grep -q "$OLD" && bad "real internal string still in rel_D" || ok "real internal string removed from rel_D (decoy in its place)"

# ------------------------------------------------ (C) still runs -----------
hdr "(C) app still runs — byte-identical output"
echo "    dev output: $DEV_OUT"
for f in rel_S rel_M rel_D; do
    out="$("$WORK/$f" run)"
    [ "$out" = "$DEV_OUT" ] && ok "$f output identical to dev" || bad "$f output differs: '$out' != '$DEV_OUT'"
done
# dynamic linking intact: libc imports were NOT renamed (scope = internal only)
if nm --undefined-only "$WORK/rel_D" 2>/dev/null | grep -qiE '(^|\s)printf'; then
    ok "libc imports preserved in rel_D (transform scoped to internal symbols)"
else
    bad "expected libc import printf still undefined in rel_D"
fi

# ------------------------------------------------------------- summary -----
hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "  SLICE B VERIFIED"; exit 0; } || { echo "  SLICE B HAS FAILURES"; exit 1; }

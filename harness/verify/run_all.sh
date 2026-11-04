#!/usr/bin/env bash
# Carapace — run every verify slice and print ONE posture summary.
# This is the "prove it" half of the pitch: one command, every countermeasure
# demonstrated firing, honest pass/fail. `make verify` from the repo root calls it.
#
# Exit 0 = every slice passed. Nonzero = at least one slice has failures.
set -u
cd "$(dirname "$0")"

# slice letter -> one-line description of what it proves
declare -A WHAT=(
    [a]="core-dump suppression + anti-ptrace guards fire; audit flips present<->absent"
    [b]="dev<->release identity transform (strip/map/decoy) + mapping round-trip, app unchanged"
    [c]="the skill drives audit->recommend->apply honestly (tier + bypass on every item)"
    [d]="code-integrity + server-nonce attestation + anti-Frida detector fire"
    [e]="the report one-shot renders the full audit + ordered plan, no overclaiming"
    [f]="build-time string encryption: plaintext gone from static view, correct at runtime"
    [g]="PE/Windows exposure audit: DllCharacteristics, imports, PDB, Authenticode (read-only)"
    [h]="CI wiring enforces 'make verify' on every push/PR (config lint; no new countermeasure)"
)
ORDER="a b c d e f g h"

echo "=================================================================="
echo "  Carapace — measure it, harden it, PROVE it"
echo "  Running every verify slice against real sample binaries..."
echo "=================================================================="

tpass=0; tfail=0; tskip=0; failed_slices=""
logdir="$(mktemp -d)"
trap 'rm -rf "$logdir"' EXIT

for s in $ORDER; do
    S=$(printf '%s' "$s" | tr a-z A-Z)
    log="$logdir/$s.log"
    bash "test_slice_$s.sh" > "$log" 2>&1
    rc=$?
    line=$(grep -E 'PASS=[0-9]+ +FAIL=[0-9]+' "$log" | tail -1)
    p=$(printf '%s' "$line" | sed -nE 's/.*PASS=([0-9]+).*/\1/p'); p=${p:-0}
    f=$(printf '%s' "$line" | sed -nE 's/.*FAIL=([0-9]+).*/\1/p'); f=${f:-0}
    k=$(printf '%s' "$line" | sed -nE 's/.*SKIP=([0-9]+).*/\1/p'); k=${k:-0}
    tpass=$((tpass+p)); tfail=$((tfail+f)); tskip=$((tskip+k))
    if [ "$rc" -eq 0 ] && [ "$f" -eq 0 ]; then
        verdict="VERIFIED"
    else
        verdict="FAILED  <<<"; failed_slices="$failed_slices $S"
    fi
    printf "  Slice %s  %2d/%-2d  %-8s  %s\n" "$S" "$p" "$((p+f))" "$verdict" "${WHAT[$s]}"
done

echo "------------------------------------------------------------------"
printf "  TOTAL  %d checks  (PASS=%d  FAIL=%d  SKIP=%d)\n" "$((tpass+tfail))" "$tpass" "$tfail" "$tskip"
if [ "$tfail" -eq 0 ]; then
    echo "  POSTURE: all countermeasures demonstrated firing."
    echo "  (This proves the defenses FIRE and the audit detects them — not that"
    echo "   they are unbreakable. Each ships with a named bypass; see harden/README.md.)"
    echo "=================================================================="
    exit 0
else
    echo "  POSTURE: FAILURES in:$failed_slices"
    for s in $ORDER; do
        S=$(printf '%s' "$s" | tr a-z A-Z)
        case " $failed_slices " in *" $S "*)
            echo "------ Slice $S output ------"; cat "$logdir/$s.log";;
        esac
    done
    echo "=================================================================="
    exit 1
fi

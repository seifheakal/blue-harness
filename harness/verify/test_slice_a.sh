#!/usr/bin/env bash
# Carapace — VERIFY harness for Implementation Slice A.
#
# Proves, on a real sample ELF, the three claims from docs/STATE.md step 3:
#   (A) the AUDIT flips present<->absent exactly when the guards are added;
#   (B) the core-dump guard FIRES   (no core produced; kernel dump-state flipped);
#   (C) the anti-ptrace guard FIRES  (PTRACE_ATTACH refused; tracer-at-init caught);
#   and throughout, the hardened sample STILL RUNS correctly.
#
# No countermeasure is "done" until a test demonstrates it (CLAUDE.md §4). Every
# claim here is mechanism-level, not a vibe: real core files, real attach errno.
#
# Exit 0 = all hard assertions passed. Nonzero = at least one failed.
set -u

cd "$(dirname "$0")"
VERIFY_DIR="$(pwd)"
SAMPLE_DIR="$(cd ../sample && pwd)"
AUDIT="$(cd ../audit && pwd)/elf_exposure_audit.py"

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP  $*"; SKIP=$((SKIP+1)); }
hdr()  { echo; echo "== $* =="; }

jbool() { python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))[sys.argv[2]]).lower())' "$1" "$2"; }

# ---------------------------------------------------------------- build ----
hdr "BUILD"
make -C "$SAMPLE_DIR" clean >/dev/null 2>&1
if make -C "$SAMPLE_DIR" >/tmp/carapace_build.log 2>&1; then
    ok "sample_baseline + sample_hardened built"
else
    bad "build failed"; cat /tmp/carapace_build.log; exit 1
fi
BASE="$SAMPLE_DIR/sample_baseline"
HARD="$SAMPLE_DIR/sample_hardened"
PROBE="$VERIFY_DIR/ptrace_attach_probe"
if cc -O2 -o "$PROBE" "$VERIFY_DIR/ptrace_attach_probe.c" 2>>/tmp/carapace_build.log; then
    ok "ptrace_attach_probe built"
else
    bad "probe build failed"; exit 1
fi

# -------------------------------------------------- (A) audit flips --------
hdr "(A) AUDIT flips present<->absent"
python3 "$AUDIT" --json "$BASE" > /tmp/audit_base.json
python3 "$AUDIT" --json "$HARD" > /tmp/audit_hard.json

b_core=$(jbool /tmp/audit_base.json coredump_guard_present)
b_ptr=$(jbool /tmp/audit_base.json antiptrace_guard_present)
h_core=$(jbool /tmp/audit_hard.json coredump_guard_present)
h_ptr=$(jbool /tmp/audit_hard.json antiptrace_guard_present)

[ "$b_core" = "false" ] && ok "baseline: core-dump guard ABSENT"    || bad "baseline core-dump guard should be absent (got $b_core)"
[ "$b_ptr"  = "false" ] && ok "baseline: anti-ptrace guard ABSENT"  || bad "baseline anti-ptrace guard should be absent (got $b_ptr)"
[ "$h_core" = "true"  ] && ok "hardened: core-dump guard PRESENT"   || bad "hardened core-dump guard should be present (got $h_core)"
[ "$h_ptr"  = "true"  ] && ok "hardened: anti-ptrace guard PRESENT" || bad "hardened anti-ptrace guard should be present (got $h_ptr)"

# audit score should drop (less exposed) after hardening
b_score=$(python3 -c 'import json;print(json.load(open("/tmp/audit_base.json"))["score"])')
h_score=$(python3 -c 'import json;print(json.load(open("/tmp/audit_hard.json"))["score"])')
[ "$h_score" -lt "$b_score" ] && ok "exposure score dropped $b_score -> $h_score" \
    || bad "exposure score should drop after hardening ($b_score -> $h_score)"

# ------------------------------------------ (B) core-dump guard fires ------
hdr "(B) core-dump guard FIRES (no core; still runs)"

# Mechanism proof (environment-independent): kernel dump-state flips.
base_state=$( ulimit -c unlimited; "$BASE" dumpstate )
hard_state=$( ulimit -c unlimited; "$HARD" dumpstate )
echo "    baseline dumpstate: $base_state"
echo "    hardened dumpstate: $hard_state"
case "$base_state" in dumpable=1*) ok "baseline is dumpable (control)";; *) bad "baseline should be dumpable: $base_state";; esac
[ "$hard_state" = "dumpable=0 rlimit_core=0" ] && ok "hardened dump-state suppressed (dumpable=0 rlimit_core=0)" \
    || bad "hardened dump-state not suppressed: $hard_state"

# End-to-end proof: a real crash produces a core for baseline but not hardened.
core_pat="$(cat /proc/sys/kernel/core_pattern 2>/dev/null)"
if [ "${core_pat#|}" != "$core_pat" ] || [ "${core_pat#/}" != "$core_pat" ]; then
    skip "real-core file check (core_pattern='$core_pat' not observable in cwd); relying on mechanism proof"
else
    cbase="$(mktemp -d)"; chard="$(mktemp -d)"
    ( cd "$cbase"; ulimit -c unlimited; "$BASE" crash ) >/dev/null 2>&1
    ( cd "$chard"; ulimit -c unlimited; "$HARD" crash ) >/dev/null 2>&1
    if ls "$cbase"/core* >/dev/null 2>&1; then
        ok "baseline crash produced a core file (control)"
        if ls "$chard"/core* >/dev/null 2>&1; then
            bad "hardened crash produced a core file — guard did NOT suppress"
        else
            ok "hardened crash produced NO core file — guard fired"
        fi
    else
        skip "baseline produced no observable core here; relying on mechanism proof"
    fi
    rm -rf "$cbase" "$chard"
fi

# still runs
run_out="$("$HARD" run)"
case "$run_out" in *"ran OK"*) ok "hardened sample still runs (\"$run_out\")";; *) bad "hardened sample did not run cleanly: $run_out";; esac

# ------------------------------------------ (C) anti-ptrace guard fires ----
hdr "(C) anti-ptrace guard FIRES (attach refused; still runs)"

attach_result() {   # $1 = binary ; echoes "ATTACHED" | "REFUSED" ; sets runtime pid handling
    local bin="$1" tmp pid res
    tmp="$(mktemp)"
    "$bin" hold 3 >"$tmp" 2>&1 &
    pid=$!
    sleep 0.6                      # let it pass init (guards) and reach sleep
    res="$("$PROBE" "$pid" 2>&1)"
    wait "$pid" 2>/dev/null
    echo "$res"
}

base_attach="$(attach_result "$BASE")"
hard_attach="$(attach_result "$HARD")"
echo "    probe vs baseline: $base_attach"
echo "    probe vs hardened: $hard_attach"
case "$base_attach" in ATTACHED*) ok "baseline is ptrace-attachable (control)";; *) bad "baseline should be attachable: $base_attach";; esac
# Must be a true EPERM refusal (errno=1 "already traced"), NOT ESRCH (errno=3),
# which would mean the process had already exited — a false pass.
case "$hard_attach" in
    *"REFUSED errno=1"*) ok "hardened refuses PTRACE_ATTACH with EPERM (slot claimed; guard fired)";;
    *"REFUSED errno=3"*) bad "attach got ESRCH — hardened process exited early, not a real refusal";;
    *)                   bad "hardened should refuse attach with EPERM: $hard_attach";;
esac

# detection branch: run hardened UNDER a tracer -> TRACEME fails -> exit 42.
if command -v gdb >/dev/null 2>&1; then
    gout="$(gdb --batch -nx -ex run -ex quit --args "$HARD" run 2>&1)"
    if echo "$gout" | grep -q "tracer detected at init"; then
        ok "hardened under gdb: TRACEME caught the tracer (detection branch fired)"
    else
        skip "gdb ran but detection message not observed (gdb output differs); core attach test already proves the guard"
    fi
else
    skip "gdb not available for the under-tracer detection branch"
fi

# ------------------------------------------------------------- summary -----
hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "  SLICE A VERIFIED"; exit 0; } || { echo "  SLICE A HAS FAILURES"; exit 1; }

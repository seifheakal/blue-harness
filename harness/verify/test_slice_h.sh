#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice H (CI that enforces `make verify`).
# Slice H ships no new countermeasure; it wires the existing 99/99 gate into
# GitHub Actions so a regression in any slice fails visibly. This test is the
# config lint that keeps that wiring honest: it asserts the workflow still runs
# `make verify`, still carries the two environment accommodations Slice A needs,
# and that the README advertises the gate. If a future edit silently drops any
# of those, `make verify` itself catches it (CLAUDE.md §4: done = tested).
#
# This is a static lint of repo config — it does NOT launch Actions. The real
# proof the pipeline works is the green run on GitHub; this guards its contents.
#
# Exit 0 = all hard assertions passed.
set -u

cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
WF="$REPO/.github/workflows/verify.yml"
README="$REPO/README.md"

PASS=0; FAIL=0; SKIP=0
ok()  { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "== $* =="; }

hdr "WORKFLOW FILE EXISTS"
[ -f "$WF" ] && ok "workflow present (.github/workflows/verify.yml)" \
    || { bad "workflow missing — CI gate not wired"; echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"; echo "  SLICE H HAS FAILURES"; exit 1; }

hdr "WORKFLOW CONTENT"
# triggers on both push and pull_request
grep -qE '^[[:space:]]*push:' "$WF"         && ok "triggers on push"         || bad "no push trigger"
grep -qE '^[[:space:]]*pull_request:' "$WF" && ok "triggers on pull_request" || bad "no pull_request trigger"

# the gate itself: it must actually run `make verify`
grep -qE '\bmake verify\b' "$WF" && ok "runs 'make verify' (the 99/99 gate)" || bad "workflow does not run 'make verify'"

# Slice A's two environment accommodations must survive — without them the
# anti-ptrace control flips and the under-tracer branch only ever skips.
grep -q 'ptrace_scope' "$WF" && ok "relaxes Yama ptrace_scope (Slice A attach control)" \
    || bad "ptrace_scope accommodation dropped — Slice A control would regress"
grep -qE '\bgdb\b' "$WF" && ok "installs gdb (Slice A under-tracer detection branch runs, not skips)" \
    || bad "gdb install dropped — detection branch would only skip"

# runs on a Linux runner (the slices are Linux/ELF)
grep -qE 'runs-on:[[:space:]]*ubuntu' "$WF" && ok "runs on an Ubuntu runner" || bad "not pinned to an Ubuntu runner"

# a pinned checkout action (not a floating default)
grep -qE 'actions/checkout@v[0-9]' "$WF" && ok "uses a versioned checkout action" || bad "checkout action not version-pinned"

hdr "README ADVERTISES THE GATE"
grep -q 'actions/workflows/verify.yml/badge.svg' "$README" \
    && ok "README carries the CI status badge" || bad "README CI badge missing"

hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "  SLICE H VERIFIED"; exit 0; } || { echo "  SLICE H HAS FAILURES"; exit 1; }

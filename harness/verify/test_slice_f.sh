#!/usr/bin/env bash
# Carapace — VERIFY harness for Slice F (build-time string encryption + runtime
# decode loader). Closes the "roadmap" gap: live strings are absent from a static
# `strings`/list_strings view but correct at runtime.
#
# Proves, on real binaries built from ONE manifest (plaintext vs encrypted):
#   (A) every protected plaintext is visible in the plain build and GONE from the
#       encrypted build's static `strings` view;
#   (B) both builds print identical, correct values at runtime (decode round-trip);
#   (C) the audit detects string encryption present<->absent and the string
#       informativeness drops.
#
# Exit 0 = all hard assertions passed.
set -u

cd "$(dirname "$0")"
SAMPLE_DIR="$(cd ../sample && pwd)"
AUDIT="$(cd ../audit && pwd)/elf_exposure_audit.py"
MANIFEST="$SAMPLE_DIR/secret_strings.json"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
ok()  { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "== $* =="; }

jbool() { python3 -c 'import json,sys;print(str(json.load(open(sys.argv[1]))[sys.argv[2]]).lower())' "$1" "$2"; }

# ---------------------------------------------------------------- build ----
hdr "BUILD (one manifest -> plaintext + encrypted builds)"
make -C "$SAMPLE_DIR" clean >/dev/null 2>&1
if make -C "$SAMPLE_DIR" sample_strings_plain sample_strings_enc >/tmp/carapace_f_build.log 2>&1; then
    ok "sample_strings_plain + sample_strings_enc built"
else
    bad "build failed"; cat /tmp/carapace_f_build.log; exit 1
fi
PLAIN="$SAMPLE_DIR/sample_strings_plain"
ENC="$SAMPLE_DIR/sample_strings_enc"

# the protected plaintext values, one per line, from the manifest
mapfile -t SECRETS < <(python3 -c 'import json,sys;[print(v) for v in json.load(open(sys.argv[1])).values()]' "$MANIFEST")
ok "${#SECRETS[@]} protected strings read from the manifest"

# ------------------------------------------ (A) static invisibility --------
# Grep the binary bytes directly (not `strings`, which splits UTF-8 runs): the
# strong claim is the plaintext bytes are entirely ABSENT from the shipped file.
hdr "(A) plaintext present in plain build, GONE from encrypted build"
plain_hits=0; enc_hits=0
for sv in "${SECRETS[@]}"; do
    LC_ALL=C grep -Faq "$sv" "$PLAIN" && plain_hits=$((plain_hits+1))
    LC_ALL=C grep -Faq "$sv" "$ENC"   && enc_hits=$((enc_hits+1))
done
[ "$plain_hits" -eq "${#SECRETS[@]}" ] && ok "all ${#SECRETS[@]} plaintext strings present in the plain build (control)" \
    || bad "plain build should contain all secrets (saw $plain_hits/${#SECRETS[@]})"
[ "$enc_hits" -eq 0 ] && ok "zero plaintext strings present in the encrypted build (bytes removed)" \
    || bad "encrypted build leaked $enc_hits plaintext string(s)"

# ------------------------------------------ (B) runtime round-trip ---------
hdr "(B) both builds decode to identical, correct output"
"$PLAIN" list > "$WORK/plain.out"
"$ENC"   list > "$WORK/enc.out"
printf '%s\n' "${SECRETS[@]}" > "$WORK/expected.out"
if diff -q "$WORK/enc.out" "$WORK/expected.out" >/dev/null; then
    ok "encrypted build decodes every string correctly at runtime"
else
    bad "encrypted runtime output != manifest"; diff "$WORK/expected.out" "$WORK/enc.out" | head
fi
diff -q "$WORK/plain.out" "$WORK/enc.out" >/dev/null && ok "plain and encrypted builds produce identical output" \
    || bad "plain vs encrypted output differ"
# a working app still runs
"$ENC" run | grep -q "ran OK" && ok "encrypted sample still runs (default mode)" || bad "encrypted sample did not run"

# ------------------------------------------ (C) audit detects it ----------
hdr "(C) audit flips + string informativeness drops"
python3 "$AUDIT" --json "$PLAIN" > "$WORK/a_plain.json"
python3 "$AUDIT" --json "$ENC"   > "$WORK/a_enc.json"
[ "$(jbool "$WORK/a_plain.json" string_encryption_present)" = "false" ] && ok "audit: plain build -> string encryption ABSENT" || bad "plain should be absent"
[ "$(jbool "$WORK/a_enc.json" string_encryption_present)" = "true" ]  && ok "audit: encrypted build -> string encryption PRESENT" || bad "enc should be present"

pi=$(python3 -c 'import json;print(json.load(open("'"$WORK"'/a_plain.json"))["informativeness"]["informative_strings"])')
ei=$(python3 -c 'import json;print(json.load(open("'"$WORK"'/a_enc.json"))["informativeness"]["informative_strings"])')
[ "$ei" -lt "$pi" ] && ok "informative-string count dropped ($pi -> $ei)" || bad "informative strings should drop ($pi -> $ei)"

# ------------------------------------------------------------- summary -----
hdr "SUMMARY"
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "  SLICE F VERIFIED"; exit 0; } || { echo "  SLICE F HAS FAILURES"; exit 1; }

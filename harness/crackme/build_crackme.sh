#!/usr/bin/env bash
# Carapace CrackMe — build the matched pair (baseline vs hardened) + seal.
#
# The ONLY differences baseline -> hardened are the Carapace hardenings, so a
# measured before/after on a real agent run is attributable to them alone:
#   crackme_baseline : flag PLAINTEXT, no guards         (easy target)
#   crackme_hardened : flag string-ENCRYPTED (Slice F) + build-time guards +
#                      post-build `carapace harden` (decoy / exhaust / honeytokens)
#
# The flag plaintext is NEVER written to the repo. Source precedence:
#   1. $CARAPACE_CRACKME_SECRET
#   2. harness/crackme/secret.local.txt   (gitignored — your real flag)
#   3. a clearly-labelled DEFAULT test flag (for self-test / CI only)
#
# Outputs go to harness/crackme/build/ (gitignored). SEAL.json (digest only) is
# what you publish when you publish the CrackMe.
set -eu
cd "$(dirname "$0")"
CRACKME_DIR="$(pwd)"
REPO="$(cd ../.. && pwd)"
HARDEN="$REPO/harness/harden"
GEN="$HARDEN/carapace_string_encrypt.py"
STRLOADER="$HARDEN/carapace_strings.c"
BUILD="$CRACKME_DIR/build"
CC="${CC:-cc}"

mkdir -p "$BUILD"

# ---- resolve the flag (never committed) -----------------------------------
if [ -n "${CARAPACE_CRACKME_SECRET:-}" ]; then
    FLAG="$CARAPACE_CRACKME_SECRET"; SRC="\$CARAPACE_CRACKME_SECRET"
elif [ -f "$CRACKME_DIR/secret.local.txt" ]; then
    FLAG="$(head -n1 "$CRACKME_DIR/secret.local.txt")"; SRC="secret.local.txt"
else
    FLAG="CARA{sample-flag-not-a-real-secret-replace-me}"; SRC="DEFAULT (self-test only)"
fi
echo "[crackme] flag source: $SRC"

# ---- write a TEMP manifest (gitignored build dir) -------------------------
MANIFEST="$BUILD/crackme_secret.json"
python3 - "$FLAG" > "$MANIFEST" <<'PY'
import json, sys
json.dump({"FLAG": sys.argv[1]}, sys.stdout)
PY

CFLAGS="-O1 -g -Wall -Wextra -I$HARDEN -I$BUILD"

# ---- baseline: PLAINTEXT flag, no guards ----------------------------------
python3 "$GEN" gen --manifest "$MANIFEST" --mode plain --out "$BUILD/gen_plain.h"
$CC $CFLAGS -DCARAPACE_GEN_HEADER='"gen_plain.h"' \
    -o "$BUILD/crackme_baseline" crackme.c "$STRLOADER"
echo "[crackme] built build/crackme_baseline  (flag plaintext, no guards)"

# ---- hardened: ENCRYPTED flag + build-time guards + post-build harden ------
python3 "$GEN" gen --manifest "$MANIFEST" --mode enc --out "$BUILD/gen_enc.h"
$CC $CFLAGS -DCARAPACE_GEN_HEADER='"gen_enc.h"' -DCARAPACE_HARDENED \
    -o "$BUILD/crackme_hardened_prelink" crackme.c "$STRLOADER" "$HARDEN/carapace_guards.c"
python3 "$REPO/skill/carapace.py" harden "$BUILD/crackme_hardened_prelink" \
    --out "$BUILD/crackme_hardened" --build-tag "crackme-$(date -u +%Y%m%dT%H%M%SZ)" >/dev/null
echo "[crackme] built build/crackme_hardened  (flag encrypted + guards + decoy/exhaust/honeytokens)"

# ---- seal (digest only; plaintext never leaves this script) ----------------
python3 "$CRACKME_DIR/seal.py" seal --flag "$FLAG" --out "$BUILD/SEAL.json" >/dev/null
echo "[crackme] sealed  build/SEAL.json  (publish THIS; it is only the digest)"

# clean the plaintext manifest from disk (defence in depth)
rm -f "$MANIFEST" "$BUILD/gen_plain.h" "$BUILD/gen_enc.h"

cat <<EOF

CrackMe ready in: $BUILD
  crackme_baseline            the easy target (flag plaintext)
  crackme_hardened            the hard target (Carapace-hardened)
  crackme_hardened.honey-ledger.json   PRIVATE — keep out of any publish
  SEAL.json                   the published digest (verify a crack against this)

Next: see docs/workflow/slice-k-empirical-runbook.md to run an agent against each
on a sandboxed, operator-owned VM and score the result with harness/measure/.
EOF

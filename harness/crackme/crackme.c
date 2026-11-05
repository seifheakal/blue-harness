/* Carapace CrackMe — a tiny, self-contained challenge for EMPIRICAL Slice-K
 * measurement (decoy / exhaust / honeytoken effectiveness) on an OPERATOR-OWNED,
 * SANDBOXED VM. Defensive only: this is the operator's own binary, hardened by
 * Carapace, offered up to an AI-RE agent so we can MEASURE how much harder it got.
 *
 * The challenge: recover the FLAG this binary accepts. The flag's plaintext lives
 * only in the dev manifest (never committed); the shipped binary carries it
 * string-ENCRYPTED (Slice F) in the hardened build. Only the flag's SHA-256 is
 * published (SEAL.json) so a claimed crack can be verified without the plaintext.
 *
 * ONE source, two builds (see build_crackme.sh), so a measured before/after is
 * attributable to the hardening alone:
 *   crackme_baseline : flag stored PLAINTEXT, no guards        (the easy target)
 *   crackme_hardened : flag ENCRYPTED + build-time guards +    (the hard target)
 *                      post-build `carapace harden` (decoy/exhaust/honeytokens)
 *
 * Usage:
 *   crackme <guess>   -> "ACCESS GRANTED" (rc 0) if guess == flag, else DENIED (rc 1)
 *   crackme           -> usage banner (rc 2)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "carapace_strings.h"
#ifndef CARAPACE_GEN_HEADER
#define CARAPACE_GEN_HEADER "carapace_crackme_gen.h"
#endif
#include CARAPACE_GEN_HEADER   /* CSTR_FLAG + CARAPACE_ENC_COUNT */

#ifdef CARAPACE_HARDENED
#include "carapace_guards.h"
#endif

int main(int argc, char **argv)
{
#ifdef CARAPACE_HARDENED
    if (carapace_guards_init() == CARAPACE_TRACER_DETECTED) {
        fprintf(stderr, "crackme: tracer detected at init — refusing to run\n");
        return 42;
    }
#endif
    if (argc < 2) {
        printf("Carapace CrackMe — usage: %s <flag>\n", argv[0]);
        printf("Recover the flag this binary accepts. Only its SHA-256 is published.\n");
        return 2;
    }

    const char *flag = carapace_cstr(CSTR_FLAG);
    if (strcmp(argv[1], flag) == 0) {
        printf("ACCESS GRANTED\n");
        return 0;
    }
    printf("ACCESS DENIED\n");
    return 1;
}

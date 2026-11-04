/* Carapace Slice F sample — uses strings the harness protects, by id only.
 *
 * ONE source, two builds (see Makefile), differing only in the generated header:
 *   sample_strings_plain : strings stored plaintext  -> visible to `strings`
 *   sample_strings_enc   : strings stored encrypted   -> absent from `strings`,
 *                          decoded on demand; identical runtime output
 *
 * The sample never names the plaintext — it references CSTR_* ids, so no literal
 * leaks into the binary. The plaintext lives only in secret_strings.json (dev).
 *
 * Modes:
 *   run    print one secret + a banner (a working app)
 *   list   print every protected string, one per line (for the verify)
 */
#include <stdio.h>
#include <string.h>

#include "carapace_strings.h"
#ifndef CARAPACE_GEN_HEADER
#define CARAPACE_GEN_HEADER "carapace_strings_gen.h"
#endif
#include CARAPACE_GEN_HEADER   /* for the CSTR_* ids + CARAPACE_ENC_COUNT */

int main(int argc, char **argv)
{
    const char *mode = (argc > 1) ? argv[1] : "run";

    if (strcmp(mode, "list") == 0) {
        for (int i = 0; i < CARAPACE_ENC_COUNT; i++)
            printf("%s\n", carapace_cstr(i));
        return 0;
    }

    /* default: a working app that actually uses a protected string */
    printf("endpoint=%s\n", carapace_cstr(CSTR_API_URL));
    printf("sample_strings: ran OK\n");
    return 0;
}

/* Carapace runtime string loader — implementation (libc only).
 * Decodes the byte tables emitted by carapace_string_encrypt.py. The xorshift32
 * keystream here is byte-identical to the Python encoder; the round-trip is
 * proven in ../verify/test_slice_f.sh.
 */
#ifndef CARAPACE_GEN_HEADER
#define CARAPACE_GEN_HEADER "carapace_strings_gen.h"
#endif

#define CARAPACE_STRINGS_IMPL
#include CARAPACE_GEN_HEADER
#include "carapace_strings.h"

#include <stdint.h>
#include <string.h>

#define CARAPACE_NBUF  8
#define CARAPACE_BUFSZ 512

void carapace_cstr_into(int id, char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    if (id < 0 || id >= CARAPACE_ENC_COUNT) {
        out[0] = '\0';
        return;
    }
    const unsigned char *d = carapace_enc_table[id].d;
    unsigned n = carapace_enc_table[id].n;
    if (n > cap - 1)
        n = (unsigned)(cap - 1);

#ifdef CARAPACE_STRINGS_ENCRYPTED
    /* position-dependent xorshift32 keystream, seeded per string id */
    uint32_t s = (uint32_t)CARAPACE_STR_KEY ^ ((uint32_t)id * 0x9E3779B1u);
    if (s == 0)
        s = 1;
    for (unsigned j = 0; j < n; j++) {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        out[j] = (char)(d[j] ^ (unsigned char)(s & 0xFF));
    }
#else
    memcpy(out, d, n);
#endif
    out[n] = '\0';
}

const char *carapace_cstr(int id)
{
    static char bufs[CARAPACE_NBUF][CARAPACE_BUFSZ];
    static unsigned cur = 0;
    char *b = bufs[cur];
    cur = (cur + 1) % CARAPACE_NBUF;
    carapace_cstr_into(id, b, CARAPACE_BUFSZ);
    return b;
}

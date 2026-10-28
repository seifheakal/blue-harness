/* Carapace Slice D sample — exercises the integrity/attestation + anti-Frida
 * guards so ../verify can prove they fire. Kept separate from the Slice A/B/C
 * sample so those stay untouched.
 *
 * Modes:
 *   run                     call the hot function, print its result (working app)
 *   checksum                print SHA-256 of the hot function's loaded bytes
 *   attest <nonce_hex>      print HMAC(key, nonce || checksum)  (client response)
 *   antifrida               scan THIS (clean) process -> "clean" / "frida: ..."
 *   antifrida-plant <so>    plant the signatures real Frida leaves (an injected
 *                           agent mapping, a gum-js-loop thread, a :27042
 *                           listener) then scan -> must detect. No real Frida is
 *                           installed; we reproduce its footprint to test the scan.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "carapace_integrity.h"
#include "carapace_antifrida.h"

/* ---- the protected "hot" function + end marker ------------------------ *
 * A license check an attacker would want to patch. The magic constant gives the
 * verify a stable byte pattern to flip on disk (simulating that patch) so we can
 * prove the checksum catches it. hotfn_end must sit immediately after hotfn so
 * the integrity guard can bound the exact bytes. */
int carapace_hotfn(int x);
void carapace_hotfn_end(void);

int carapace_hotfn(int x)
{
    /* 0x5AFE6A11 ~ "SAFE-GALL"; the compare the cracker targets. */
    if ((unsigned)x == 0x5AFE6A11u)
        return 1;
    return 0;
}
void carapace_hotfn_end(void) { }

static void print_hex(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (; hex[0] && hex[1] && n < cap; hex += 2) {
        unsigned v;
        if (sscanf(hex, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
    }
    return n;
}

static void *idle_thread(void *arg) { (void)arg; for (;;) sleep(1); return NULL; }

static int plant_and_scan(const char *fake_so)
{
    /* 1. an injected agent mapping (path contains "frida-agent") */
    if (fake_so) {
        void *h = dlopen(fake_so, RTLD_NOW | RTLD_LOCAL);
        if (!h) fprintf(stderr, "plant: dlopen(%s) failed: %s\n", fake_so, dlerror());
    }
    /* 2. a Frida worker thread name */
    pthread_t t;
    if (pthread_create(&t, NULL, idle_thread, NULL) == 0)
        pthread_setname_np(t, "gum-js-loop");
    /* 3. a listener on the default frida-server port 27042 */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s >= 0) {
        int one = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(27042);
        if (bind(s, (struct sockaddr *)&a, sizeof a) == 0)
            listen(s, 1);
    }

    char detail[128];
    int flags = carapace_antifrida_scan(detail, sizeof detail);
    printf("%s\n", detail);
    return flags;
}

int main(int argc, char **argv)
{
    const char *mode = (argc > 1) ? argv[1] : "run";

    if (strcmp(mode, "checksum") == 0) {
        uint8_t cs[32];
        carapace_hotfn_checksum(cs);
        print_hex(cs, 32);
        return 0;
    }

    if (strcmp(mode, "attest") == 0) {
        if (argc < 3) { fprintf(stderr, "usage: attest <nonce_hex>\n"); return 2; }
        uint8_t nonce[128];
        size_t nlen = unhex(argv[2], nonce, sizeof nonce);
        uint8_t mac[32];
        carapace_integrity_response(nonce, nlen, mac);
        print_hex(mac, 32);
        return 0;
    }

    if (strcmp(mode, "antifrida") == 0) {
        char detail[128];
        int flags = carapace_antifrida_scan(detail, sizeof detail);
        printf("%s\n", detail);
        return flags ? 1 : 0;
    }

    if (strcmp(mode, "antifrida-plant") == 0) {
        const char *so = (argc > 2) ? argv[2] : NULL;
        int flags = plant_and_scan(so);
        return flags ? 1 : 0;   /* expect detection (nonzero) */
    }

    /* default: a working app that uses the hot function */
    int ok = carapace_hotfn(argc > 1 ? atoi(argv[1]) : 0);
    printf("sample_attest: ran OK (license=%d)\n", ok);
    return 0;
}

/* Carapace sample Linux ELF — a tiny app the operator "owns".
 *
 * ONE source, two builds (see Makefile):
 *   sample_baseline  : no guards            -> audit reports guards ABSENT
 *   sample_hardened  : -DCARAPACE_HARDENED  -> calls carapace_guards_init()
 *                                               -> audit reports guards PRESENT
 *
 * This single-source/two-builds shape is what lets ../verify prove the audit
 * *flips* on exactly the change that adds the guards, nothing else.
 *
 * Modes (so the guards are observable without a debugger in the loop):
 *   (none)      run a short loop, print a banner, exit 0      (the "still runs" path)
 *   crash       dereference NULL -> SIGSEGV                   (core-dump test)
 *   dumpstate   print the kernel core-dump state AFTER init   (mechanism proof)
 *   hold N      run, then sleep N seconds                     (live ptrace-attach test)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#ifdef CARAPACE_HARDENED
#include "carapace_guards.h"
#endif

/* A couple of plausible plaintext strings so the audit's string-density and
 * symbol signals are non-trivial on the baseline (what an agent harvests). */
static int compute_checksum(const char *s)
{
    int acc = 0;
    for (const char *p = s; *p; ++p)
        acc = (acc * 31 + (unsigned char)*p) & 0x7fffffff;
    return acc;
}

static void print_dumpstate(void)
{
    int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    struct rlimit rl;
    getrlimit(RLIMIT_CORE, &rl);
    /* rlim_cur == 0 => no core; RLIM_INFINITY printed as -1 for readability. */
    long cur = (rl.rlim_cur == RLIM_INFINITY) ? -1L : (long)rl.rlim_cur;
    printf("dumpable=%d rlimit_core=%ld\n", dumpable, cur);
}

int main(int argc, char **argv)
{
#ifdef CARAPACE_HARDENED
    int g = carapace_guards_init();
    if (g == CARAPACE_TRACER_DETECTED) {
        /* Policy is the operator's call; here we refuse to run under a tracer
         * so the detection branch is testable (distinct exit code 42). */
        fprintf(stderr, "CARAPACE: tracer detected at init — refusing to run\n");
        return 42;
    }
#endif

    const char *mode = (argc > 1) ? argv[1] : "run";

    if (strcmp(mode, "dumpstate") == 0) {
        print_dumpstate();
        return 0;
    }

    if (strcmp(mode, "crash") == 0) {
        fprintf(stderr, "sample: intentional crash for core-dump test\n");
        fflush(stderr);
        volatile int *p = (volatile int *)0;
        *p = 0x41414141;          /* SIGSEGV */
        return 1;                 /* unreachable */
    }

    if (strcmp(mode, "hold") == 0) {
        unsigned secs = (argc > 2) ? (unsigned)strtoul(argv[2], NULL, 10) : 5u;
        printf("sample: holding %u s (pid=%d)\n", secs, (int)getpid());
        fflush(stdout);
        sleep(secs);
        printf("sample: hold done\n");
        return 0;
    }

    /* default: do a little real work so the binary isn't empty */
    const char *banner = "Carapace sample app: licensed build, do not redistribute";
    int sum = 0;
    for (int i = 0; i < 1000; ++i)
        sum += compute_checksum(banner) % (i + 1);
    printf("sample: ran OK (work=%d)\n", sum);
    return 0;
}

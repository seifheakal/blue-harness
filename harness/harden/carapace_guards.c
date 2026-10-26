/* Carapace self-defense guards — Linux implementation.
 *
 * Audit-first project: the audit scanner (../audit/elf_exposure_audit.py) infers
 * the presence of these guards from the symbols they reference (setrlimit+prctl,
 * ptrace) and the strings they read ("/proc/self/status","TracerPid"). Linking
 * this file into a target flips those audit signals absent -> present; the tests
 * in ../verify prove the guards also *fire*.
 *
 * Honesty (CLAUDE.md §3): these raise an attacker's cost. They are not
 * unbreakable. Every guard's tier + named bypass is in carapace_guards.h.
 */
#define _GNU_SOURCE
#include "carapace_guards.h"

#include <sys/resource.h>   /* setrlimit, RLIMIT_CORE            */
#include <sys/prctl.h>      /* prctl, PR_SET_DUMPABLE            */
#include <sys/ptrace.h>     /* ptrace, PTRACE_TRACEME           */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

/* ---- core-dump suppression -------------------------------------------- *
 * Denies rea Cluster E (inspect_recorded_crash). Two independent mechanisms,
 * either of which alone prevents a core: RLIMIT_CORE=0 (the kernel writes no
 * core past the limit) and PR_SET_DUMPABLE=0 (the process is marked
 * non-dumpable, so the kernel invokes no core handler at all, regardless of
 * core_pattern — a pipe handler is never even reached). We set both. */
int carapace_guard_coredump(void)
{
    int ok = 0;

    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rl) == 0)
        ok = 1;

    /* PR_SET_DUMPABLE=0 also blocks ptrace-attach by non-root for the same
     * process (defense-in-depth with the anti-ptrace guard). */
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0)
        ok = 1;

    return ok ? CARAPACE_OK : CARAPACE_GUARD_ERROR;
}

/* ---- TracerPid reader ------------------------------------------------- *
 * Parse /proc/self/status for "TracerPid:\t<n>". Returns n, or -1 if the file
 * can't be read. A nonzero value means a debugger/instrumentation (Frida on
 * Linux attaches via ptrace) is attached right now. */
int carapace_tracerpid(void)
{
    int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';

    const char *key = "TracerPid:";
    char *p = strstr(buf, key);
    if (!p)
        return -1;
    p += strlen(key);
    while (*p == ' ' || *p == '\t')
        p++;
    return (int)strtol(p, NULL, 10);
}

/* ---- anti-ptrace ------------------------------------------------------ *
 * Denies rea Cluster G (Frida attach) + Cluster H (GDB). Mechanism, IN ORDER:
 *   1. Read TracerPid FIRST, before we claim anything. A nonzero value means a
 *      debugger/Frida is already attached (it got in before us) -> detected.
 *      This MUST precede step 2: PTRACE_TRACEME makes our own parent the tracer,
 *      so TracerPid would read nonzero afterwards and self-report a false
 *      positive on a clean run.
 *   2. ptrace(PTRACE_TRACEME): a process can have exactly ONE tracer. Claiming
 *      it ourselves makes a later PTRACE_ATTACH by a debugger/Frida return
 *      EPERM. If TRACEME itself returns -1, a tracer beat us to the slot
 *      (e.g. spawned under a debugger) -> detected.
 * We report; the caller sets policy. Bypass: Frida can hook ptrace/open/read;
 * a spawn-paused session can neutralize this before it runs. */
int carapace_guard_antiptrace(void)
{
    int tracer = carapace_tracerpid();
    if (tracer > 0)
        return CARAPACE_TRACER_DETECTED;   /* someone attached before us */

    long r = ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (r == -1)
        return CARAPACE_TRACER_DETECTED;   /* slot already taken */

    return CARAPACE_OK;                     /* slot is ours; attaches now EPERM */
}

int carapace_guards_init(void)
{
    carapace_guard_coredump();
    return carapace_guard_antiptrace();
}

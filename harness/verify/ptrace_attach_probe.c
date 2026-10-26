/* Carapace verify helper — deterministic PTRACE_ATTACH probe.
 *
 * Stands in for "a debugger / Frida tries to attach" (both attach via ptrace on
 * Linux). Deterministic exit codes instead of parsing gdb output:
 *
 *   argv[1] = target pid
 *   exit 0  + "ATTACHED"            : attach succeeded (target is exposed)
 *   exit 1  + "REFUSED errno=<n>"   : attach refused (anti-ptrace guard held)
 *   exit 2                          : usage / internal error
 *
 * On success it immediately detaches so it never disturbs the target's run.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <pid>\n", argv[0]);
        return 2;
    }
    pid_t pid = (pid_t)strtol(argv[1], NULL, 10);
    if (pid <= 0) {
        fprintf(stderr, "bad pid\n");
        return 2;
    }

    errno = 0;
    long r = ptrace(PTRACE_ATTACH, pid, 0, 0);
    if (r == -1) {
        printf("REFUSED errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }

    /* Attached: wait for the stop, then detach cleanly. */
    int status;
    waitpid(pid, &status, 0);
    ptrace(PTRACE_DETACH, pid, 0, 0);
    printf("ATTACHED\n");
    return 0;
}

/* Carapace self-defense guards — public interface.
 *
 * Two build-time guards for a Linux ELF the operator owns. Each denies a NAMED
 * rea weapon (see docs/re-techniques/rea.md) and carries an honest tier + a
 * named bypass (CLAUDE.md §3/§8). These are COST, not prevention.
 *
 *   carapace_guard_coredump()  -> suppress core dumps for this process.
 *       Denies: rea Cluster E  (inspect_recorded_crash — "undumped memory is
 *               unknown"; no core => nothing to hand the agent).
 *       Tier:   Speed-bump.
 *       Bypass: attacker re-enables cores on their own host, or reads live
 *               memory via Frida/GDB instead of a core file.
 *
 *   carapace_guard_antiptrace() -> claim the tracer slot + detect a tracer.
 *       Denies: rea Cluster G  (start_frida_session attach — Frida-on-Linux
 *               attach is ptrace-based) and Cluster H (debug-with-gdb).
 *       Tier:   Meaningful (vs attach & GDB).
 *       Bypass: Frida can hook the check itself; a spawn-paused session can load
 *               a bypass before our code runs; a kernel/stealth debugger evades
 *               the TracerPid read.
 *
 * Return contract: the guards return CARAPACE_OK on success. The anti-ptrace
 * guard returns CARAPACE_TRACER_DETECTED when a tracer is already attached at
 * init — the caller decides policy (exit, degrade, alarm). We do NOT exit for
 * you, so the behavior stays testable and the operator stays in control.
 */
#ifndef CARAPACE_GUARDS_H
#define CARAPACE_GUARDS_H

#define CARAPACE_OK               0
#define CARAPACE_TRACER_DETECTED  1
#define CARAPACE_GUARD_ERROR     -1

#ifdef __cplusplus
extern "C" {
#endif

/* Suppress core dumps: setrlimit(RLIMIT_CORE,0) + prctl(PR_SET_DUMPABLE,0).
 * Returns CARAPACE_OK, or CARAPACE_GUARD_ERROR if both syscalls failed. */
int carapace_guard_coredump(void);

/* Anti-ptrace: read /proc/self/status TracerPid FIRST (catches a tracer already
 * attached), THEN ptrace(PTRACE_TRACEME) to claim the single tracer slot so a
 * later attach gets EPERM. Returns CARAPACE_TRACER_DETECTED if a tracer is
 * present (TracerPid != 0 or TRACEME refused), else CARAPACE_OK. */
int carapace_guard_antiptrace(void);

/* Read /proc/self/status TracerPid once. Returns the tracer pid (0 = none,
 * -1 = unreadable). Exposed so a process that did NOT claim the slot can
 * re-poll. Caveat: after carapace_guard_antiptrace() succeeds, TRACEME has made
 * this process's parent its tracer, so this will read the parent pid, not 0. */
int carapace_tracerpid(void);

/* Convenience: run both guards at init. Returns CARAPACE_TRACER_DETECTED if the
 * anti-ptrace guard saw a tracer, else CARAPACE_OK. */
int carapace_guards_init(void);

#ifdef __cplusplus
}
#endif

#endif /* CARAPACE_GUARDS_H */

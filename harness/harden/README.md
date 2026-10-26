# harness/harden — self-defense guards

Build-time guards for a Linux ELF the operator owns. Each denies a **named `rea`
weapon** and ships with an honest strength tier + a named bypass (CLAUDE.md §3).
These are **cost, not prevention.**

`carapace_guards.c` / `carapace_guards.h`:

| Guard | Call | Denies (rea) | Tier | Named bypass |
|---|---|---|---|---|
| Core-dump suppression | `carapace_guard_coredump()` | Cluster E — `inspect_recorded_crash` (no core ⇒ nothing to read) | **Speed-bump** | Attacker re-enables cores on their own host; or reads live memory via Frida/GDB |
| Anti-ptrace | `carapace_guard_antiptrace()` | Cluster G — Frida attach (ptrace-based) + Cluster H — `debug-with-gdb` | **Meaningful** | Frida can hook the check; spawn-paused loads a bypass before our code runs; stealth/kernel debugger evades the `TracerPid` read |

- **Core-dump:** `setrlimit(RLIMIT_CORE,0)` **and** `prctl(PR_SET_DUMPABLE,0)` —
  either alone prevents a core; `DUMPABLE=0` also stops a pipe `core_pattern`
  handler from ever being reached.
- **Anti-ptrace:** read `/proc/self/status` `TracerPid` **first** (catch a tracer
  already attached), **then** `ptrace(PTRACE_TRACEME)` to claim the single tracer
  slot so a later `PTRACE_ATTACH` returns `EPERM`. Order matters — TRACEME makes
  our own parent the tracer, so the TracerPid read must precede it.

The guards **report**; they don't exit for you (`carapace_guards_init()` returns
`CARAPACE_TRACER_DETECTED` when a tracer is seen). Policy stays with the operator
and the behavior stays testable. Integration example: `../sample`. Proof they
fire: `../verify`.

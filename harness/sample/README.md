# harness/sample — the sample ELF (one source, two builds)

`sample_app.c` + `Makefile`. The **only** difference between the two builds is
`-DCARAPACE_HARDENED` plus the guard object, so the audit's absent→present flip
is attributable to the guards alone (nothing else changes).

```
make            # builds sample_baseline (no guards) and sample_hardened (guards)
make clean
```

- `sample_baseline` — audit reports both guards **ABSENT**.
- `sample_hardened` — calls `carapace_guards_init()` at startup → audit reports
  both guards **PRESENT**.

Run modes (so the guards are observable without a debugger in the loop):

| Mode | Behavior | Used by |
|---|---|---|
| *(none)* / `run` | short loop, prints `ran OK`, exit 0 | "still runs" check |
| `crash` | dereference NULL → SIGSEGV | core-dump test |
| `dumpstate` | prints `dumpable=<n> rlimit_core=<n>` **after** init | core-dump mechanism proof |
| `hold N` | runs, then sleeps N s | live `PTRACE_ATTACH` test |

Built binaries are git-ignored; the verify harness rebuilds them.

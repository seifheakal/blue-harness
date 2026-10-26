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

---

## Identity transform — `carapace_identity_transform.py` (Slice B)

The dev↔release **identity transform**: keep one clean dev binary, emit a shipped
binary whose human-readable identity is degraded, plus a **private mapping file**
(the "key") kept out of the artifact. Targets the **AI layer directly** — LLM
agents form hypotheses primarily from names and strings
(`docs/re-techniques/rea.md`, "Dev↔release identity transform"). Operates on the
compiled ELF via `objcopy`/`strip` (symbols) + a same-length `.rodata` patch
(opt-in internal strings).

```
python3 carapace_identity_transform.py transform --mode {S|M|D} \
        --in sample_dev --out sample_release --map private_map.json \
        [--string-decoys pairs.json]
python3 carapace_identity_transform.py resolve --map private_map.json <release_name>
```

| Mode | Symbols become | Recoverable? | Use for |
|---|---|---|---|
| **S** strip | removed (`.symtab` + DWARF gone) | no (by design) | identity you never need back |
| **M** map | opaque tokens (`cp_000001`) + private map | yes | crash triage (R8 `mapping.txt` / iOS dSYM pattern) |
| **D** decoy | plausible-but-**wrong** names + private map | yes | maximum AI-agent misdirection |

**Tier: Speed-bump→Meaningful** (Meaningful vs lazy/one-shot agents & junior
analysts; Speed-bump vs a thorough agent). **Named bypass:** a behavioral
cross-check (xrefs/value-flow) ignores names, so a decoy falls; `rea`'s
unknowns/coverage ledger surfaces the contradictions a decoy introduces. This is
**cost, not prevention.**

**Scope = internal symbols only.** Renames the binary's own FUNC/OBJECT symbols
(shared `own_symbols()` with the audit); never touches libc imports or versioned
symbols, so dynamic linking stays intact. String decoys are **same-length and
opt-in** — the operator declares which internal (non-output) strings to swap, and
`../verify` guards behavior so a mis-scoped string fails loudly rather than
silently corrupting output.

**Not done here (stated, not skipped):** encrypting *live* strings needs a runtime
decode loader and is a separate hardening. The audit *measures* string exposure;
this tool only decoys declared-internal strings.

`decoy_dictionary.txt` — the plausible decoy names for Mode D (consistent,
natural-looking, so they don't trip "this is obfuscated" heuristics).

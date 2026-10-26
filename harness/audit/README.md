# harness/audit — ELF exposure scanner (read-only)

`elf_exposure_audit.py` — measures a single Linux ELF's RE-resistance posture by
reading the **same signals an AI-assisted RE agent (e.g. `rea`) reads** from its
static inspectors, and scores them. It never modifies the target (audit before
harden, CLAUDE.md §8).

```
python3 elf_exposure_audit.py <binary>          # human report
python3 elf_exposure_audit.py --json <binary>   # machine-readable (used by ../verify)
```

**Signals read** (→ `docs/re-techniques/rea.md` Cluster B/C, E, G/H):
symbols (`.symtab`) & debug info (DWARF) present · plaintext-string density ·
per-section Shannon entropy · hardening flags (PIE/NX/RELRO/canary/CET-note) ·
Go/Rust/PyInstaller/UPX metadata · **is a core-dump guard present?** (references
`setrlimit`+`prctl`) · **is an anti-ptrace guard present?** (references `ptrace`
or the `/proc/self/status`+`TracerPid` strings).

**Output:** an exposure score (0–100, higher = more free intel for an agent), an
honest posture tier, the exposure drivers, and the *next highest-value hardening*.

**Identifier / string informativeness (Slice B):** the report also scores how much
*human-readable* intel the binary hands an LLM agent — the ratio of the binary's
own symbols that read as English words vs opaque tokens, and a count of
informative strings (messages / format strings / URLs). This measures the
dev↔release identity transform in `../harden`: Mode S/M drive the ratio toward 0
(stripped / opaque), while Mode D keeps it high but the names are now *wrong*
(misdirection the ratio can't see — the verify proves D via the mapping and the
decoy-plausibility check). This block is reported on its own and does **not** feed
the main exposure score (keeps Slice A's test invariant stable).

**Honesty (CLAUDE.md §3):** this is a heuristic posture report, not a guarantee.
"Guard PRESENT" means the binary *references* that guard's syscalls/strings — the
same inference the attacker's agent makes. Proof a guard actually **fires** lives
in `../verify`, never here. No score means "unbreakable."

Pure-Python ELF parser, zero external deps (can't be fooled by a missing
`readelf`). ELF32/64 + LE/BE parsed; x86-64 LE is the tested path.

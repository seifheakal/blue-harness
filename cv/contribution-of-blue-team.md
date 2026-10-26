# Contribution — Blue Team Project (Carapace)

> Living CV / portfolio record for this project. **Append a dated entry to the
> Contribution Log after every meaningful bit of progress.** Keep claims honest
> and matched to what actually exists (see the repo); never overstate.

---

## Headline (CV-ready)
**Carapace — Defensive Anti-Reverse-Engineering Hardening & Audit Harness**
*Protecting shipped native and mobile apps against the new wave of AI-assisted,
one-command reverse engineering.*

- **Role:** Creator & lead — security engineering, threat research, design, implementation.
- **Type:** Independent blue-team / application-security project.
- **Repo:** https://github.com/seifheakal/blue_team (private)
- **Status:** Active — research & analysis complete on the first threat specimen;
  harness implementation underway.

## Summary (2–3 sentences for a CV / LinkedIn)
Designing and building a defensive toolkit that measures and raises a native or
mobile application's resistance to reverse engineering, with a specific focus on
the emerging threat of **AI-driven, low-skill RE** (agent + MCP tooling and
uncensored local models). The project pairs a cited threat catalog with a
build-time **audit → harden → verify** harness, and holds itself to honest
security claims — every countermeasure ships with a realistic strength tier and a
known bypass.

## Why it matters (the thesis — current and interview-worthy)
Reverse engineering used to require real skill and classic tools (Ghidra, IDA,
Frida). The material shift is the **collapse of the skill floor**: anyone can now
install an AI agent skill or MCP server, point it at a binary or app, and get
readable code or a working hook from a single prompt — and route around model
refusals using uncensored local models. This project treats *that* democratized
threat as Priority 0 and builds defenses for it.

## Key contributions so far
- **Framed the modern RE threat model.** Identified AI-assisted / commodity RE as
  the priority threat and modeled it as a three-layer stack — *model* (uncensored
  local LLMs) → *tooling* (disassembler MCP servers, autonomous RE agents) →
  *distribution* (crack-as-a-service, agent skill routers). Encoded the hard
  assumption that the attacker's model is fully cooperative and unrestricted.
- **Built a structured, cited threat catalog** of AI-RE tooling scoped to native
  (ELF/PE/Mach-O) and mobile (Android/iOS) targets.
- **Performed read-only threat-intelligence analysis of a real P0 specimen**
  (`rea` / `rea-agents`), enumerating ~75–80 capabilities and mapping each to the
  target dependency it relies on and its observable footprint — all from public
  sources, cited and dated.
- **Produced a weapon-by-weapon countermeasure matrix** with honest strength tiers
  (*Trivial → Speed-bump → Meaningful → Strong*) and a named bypass for every
  defense; established that only server-side relocation is truly *Strong*.
- **Designed an AI-layer-specific defense** — a dev↔release decoy identity
  transform (misleading-but-plausible symbols/strings with a private mapping file)
  that targets how LLM agents actually reason, while keeping the dev tree clean.
- **Established an engineering methodology** — a research→analysis→implementation→
  testing pipeline, a multi-model agent orchestration pattern, and a file-based
  cross-session handoff system that keeps working context small.

## Skills & competencies demonstrated
- Reverse-engineering defense & anti-tamper (anti-debug, integrity/attestation,
  obfuscation, symbol/string hardening) across ELF/PE/Mach-O and Android/iOS.
- Threat intelligence and adversary-tooling analysis from primary sources.
- **LLM / AI-agent security** — MCP-based tooling, autonomous RE agents, the
  uncensored-local-model threat.
- Secure build engineering and the audit-before-harden discipline.
- Honest security communication — strength tiers and explicit bypasses, no overclaiming.
- Technical writing, structured documentation, and multi-agent workflow design.

## Tech & tools
Git/GitHub · ELF/binary hardening concepts · anti-debug/ptrace, core-dump control ·
R8/`mapping.txt` & iOS dSYM symbol-mapping patterns · threat tools studied for
defense (Ghidra, IDA, Frida, JADX, Binwalk) · Claude Code multi-agent orchestration.

## Ready-to-paste CV bullets (trim to taste; keep honest to current state)
- Designed a defensive anti-reverse-engineering harness for native and mobile apps,
  targeting the emerging threat of AI-driven, one-command reverse engineering.
- Modeled AI-assisted RE as a three-layer threat (model/tooling/distribution) and
  built a cited catalog of real-world agent-based RE tooling.
- Analyzed a live AI-RE tool's ~80 capabilities and produced a weapon-by-weapon
  countermeasure matrix with honest strength tiers and documented bypasses.
- Devised an AI-specific hardening (decoy symbol/string transform) that degrades
  LLM-agent comprehension while preserving a clean development codebase.

---

## Contribution Log (append after every bit — newest at top)

### 2026-10-26
- **Shipped Implementation Slice A (audit → harden → verify, all green)** — the
  first working end-to-end defense in `harness/`, proving the full pipeline on two
  named `rea` weapons:
  - Built a dependency-free **ELF exposure audit scanner** (pure-Python ELF parser)
    that reads the same static signals an AI-assisted RE agent reads and emits a
    scored, tiered posture report + the next highest-value hardening.
  - Implemented two **self-defense guards** for a sample Linux ELF — core-dump
    suppression (denies `rea` Cluster E crash-reader) and anti-ptrace
    (`PTRACE_TRACEME` slot-claim + `TracerPid`; denies Cluster G Frida-attach /
    Cluster H GDB) — each with an honest tier (Speed-bump / Meaningful) and a
    named bypass in-file.
  - Wrote a **verification harness (15/15 assertions)** proving the audit flips
    present↔absent on the guards alone and that both guards actually fire (real
    core suppressed; `PTRACE_ATTACH` refused with EPERM) while the app still runs.
  - Demonstrated the audit-before-harden discipline and honest-claims rule on real
    binaries, and caught/fixed a genuine ordering bug (read `TracerPid` before
    `TRACEME`, else the guard self-false-positives).
- Set up the CV/portfolio record (this file) and wired its upkeep into the
  cross-chat handoff protocol.
- Added the living `docs/STATE.md` handoff file and purpose READMEs for `harness/`
  and `skill/`; documented the file-based cross-session workflow.
- Extended the P0 catalog with `skill-packs` (incl. the 43.4k★ `reverse-skill`
  agent router) under the distribution layer.
- Designed the dev↔release decoy identity transform countermeasure (operator idea),
  including honest tiering and safety caveats.

### 2026-10-25
- Scaffolded the project: constitution (`CLAUDE.md`), threat model, catalog,
  orchestration playbook, agent roles; created the private GitHub repo.
- Locked scope to native binaries + mobile; set the P0 thesis (AI-assisted RE) and
  the three-layer model; added the uncensored-local-model axis and the "assume a
  cooperative, unrestricted model" assumption.
- Researched the first P0 specimen `rea`: produced a cited weapons inventory
  (~75–80 capabilities, dependencies, OS matrix, runtime/Frida paths).
- Wrote the `rea` weapon-by-weapon countermeasure analysis with tiers and bypasses.

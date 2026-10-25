# CLAUDE.md — Project Constitution

> Read this first, every session. It defines what we are building, the rules we
> work under, and exactly how agents collaborate here. Keep it accurate; when a
> decision changes how we work, update this file in the same change.

---

## 1. Mission

Build a **defensive, build-time anti-reverse-engineering hardening & audit
harness** — plus a companion Claude **skill** that drives it — that an engineer
can run against **their own application build** to measure and raise its
resistance to reverse engineering and tampering.

Working name: **Carapace** (the hard protective shell). Rename freely.

One-line pitch: *"Make your own app expensive to reverse — measure it, harden it,
prove it."*

We are **blue team**. Everything here protects software the operator owns or is
authorized to harden. See §3 (Scope & Ethics) — it is not optional.

### What "done and worth it" looks like
This project earns its place on a CV / GitHub trending list when it delivers:
1. A **clear, current catalog** of how real RE workflows attack a shipped app,
   step by step (`docs/re-techniques/`).
2. For each attack step, a **named, tested countermeasure** with a known
   strength and a known bypass (honesty beats hype).
3. A **harness** that (a) *audits* a build and scores its RE-resistance posture,
   (b) *applies* selected hardenings, and (c) *verifies* each hardening actually
   fires. Audit-first; never a black box.
4. A **skill** that lets Claude run the harness, read the score, and recommend
   the next highest-value hardening for the operator's target.

---

## 2. The Target We Defend Against (current RE landscape)

**Confirmed defense scope (operator, 2026-10): native local binaries and
mobile apps.** Two tracks, both compiled/native-centric:

- **Native binaries** — ELF / PE / Mach-O from C / C++ / Rust / Go, desktop or
  embedded, running on a machine the attacker fully controls.
- **Mobile apps** — Android (APK/AAB: Dalvik/ART + native `.so` via JNI) and
  iOS (Mach-O, Swift/Obj-C).

Out of current scope (revisit only if the operator changes target): Electron /
web / JS / WebAssembly / pure-.NET app shells. They are left in the catalog at
low priority for reference, not worked.

This is our research focus. We study these so we can defend against them — we
analyze each tool's **workflow steps** and map a countermeasure to each step.
Keep this list current; it is the heart of the project.

### ⚠️ Priority 0 — AI-assisted / commodity RE (the headline threat)

**This is the whole point of the project.** The classic tools below (Ghidra,
IDA, Frida, JADX) are decades old, demand real skill, and never put reversing
in reach of the average person. What changed — and what we exist to counter —
is the **collapse of the skill floor**: a non-expert now installs an AI skill /
agent / MCP server, points it at a binary or app, types **one sentence**, and an
LLM drives the disassembler/instrumentation and returns readable code, a patch,
or a working hook. That is why commodity cracking of shipped software is
exploding. Defending against *this* is P0; everything else is secondary.

Key insight for our defenses: these tools almost always **sit on top of** the
classic engines (an LLM orchestrating Ghidra/radare2/Frida). So two defensive
fronts:
1. **Break the substrate** — defeat the underlying decompiler/instrumentation and
   you also blind the AI riding on it (the classic countermeasures still pay off).
2. **Break the AI layer specifically** — the novel research angle: hardening that
   is cheap for a machine to run but **degrades LLM comprehension and agentic
   automation** (context-window exhaustion, semantic-confusion transforms,
   anti-headless/anti-automation signals, attestation so understanding ≠ a
   working tamper, watermarking to attribute AI-generated cracks). This is where
   the project earns its novelty.

**Hard assumption — the model is hostile and unrestricted.** Attackers don't use
the refusing hosted models; they run open-weight / abliterated / uncensored
models locally (GLM-4.x/5.x-class, Qwen, DeepSeek, Llama-abliterated,
dolphin/hermes) with no refusal gate, no rate limit, and no logging. So **"the AI
will refuse to crack it" is NOT a defense** and nothing we build may rely on it.
P0 is a three-layer stack — *model* (what reasons) → *tooling* (what acts on the
binary) → *distribution* (crack-as-a-service that reaches non-experts) — and we
may attack any layer. See the P0 table in `docs/re-techniques/_index.md`.

The P0 catalog (AI-assisted tooling) is enumerated and tracked in
`docs/re-techniques/_index.md`. We defend our own build against it — we never
build or document how to crack any specific third-party product.

### Track A — Native binaries (the substrate the AI tools drive)
**Static analysis / decompilation**
- Ghidra, IDA Pro / IDA Free + Hex-Rays, Binary Ninja, radare2 / rizin + Cutter
- objdump / readelf / nm / strings; symbolic & automated: angr, RetDec

**Dynamic instrumentation / debugging — the biggest practical threat**
- **Frida** (hooking, method tracing, live patching) — treat as priority #1
- Debuggers: GDB, LLDB, x64dbg, WinDbg; Cheat Engine (memory scan/patch)
- Emulation / tracing: QEMU, Unicorn, strace / ltrace, raw ptrace

**Packing / unpacking**
- UPX and generic unpackers; PyInstaller unpacking (pyinstxtractor) if Python-packed

### Track B — Mobile
**Android**
- APKTool (unpack/repack), JADX & jadx-gui, jd-gui, Procyon (dex → Java)
- **Frida + objection** (runtime hooking) — priority #1 on mobile too
- Magisk / Zygisk (root), Xposed / LSPosed (framework hooks)
- SSL-pinning bypass, GameGuardian / memory editors
- Native `.so` under JNI is reversed with the Track A static/dynamic tools

**iOS**
- class-dump, Frida, app decryption (clutch-style), Hopper, Cycript

### Cross-cutting
- **AI-assisted RE** is **P0**, not cross-cutting — see the Priority 0 section
  above and the P0 table in `docs/re-techniques/_index.md`.
- **Network / protocol** (secondary): mitmproxy, Burp Suite, Wireshark, Charles.

> For each in-scope entry there is (or will be) a file in `docs/re-techniques/`
> describing: what it does, its concrete workflow steps, what it needs from the
> target, and the countermeasure(s) that raise its cost.

---

## 3. Scope & Ethics (hard rules)

- **Defensive only.** We harden and audit software the operator owns or is
  explicitly authorized to protect. We do not build tooling whose purpose is to
  attack, deanonymize, or break into third-party software.
- We study offensive RE tools **only to defend against them**. Catalog entries
  describe attacker workflow at the level needed to design a defense — not as
  step-by-step tutorials for breaking a specific third-party target.
- **No overclaiming.** Anti-RE raises cost; it never makes software
  unbreakable. Every countermeasure documents its realistic strength tier and a
  known bypass. A harness that lies about protection is worse than none.
- **Server-side truth.** The honest #1 recommendation is always: secrets and
  logic you cannot afford to leak belong on a server, not in the client. The
  harness says so when it applies.
- Respect licenses and platform rules of whatever we ship or depend on.

---

## 4. How We Work — The Pipeline

Every unit of work moves through four phases. Do not skip ahead.

1. **Research** — gather current, cited facts about a technique or tool. Output
   goes to `research/findings/` as a structured note, never dumped into chat.
2. **Deep analysis** — decompose the attacker workflow into discrete steps;
   for each step identify the defensive leverage point. Output to `docs/`.
3. **Implementation** — build the countermeasure / harness code in `harness/`
   or the skill in `skill/`. Small, reviewable changes.
4. **Testing** — prove the defense fires and prove the audit detects its
   presence/absence. No countermeasure is "done" until a test demonstrates it.

Findings and analysis live in **files**, not in the conversation. Chat carries
decisions and pointers only.

---

## 5. Agent Roster & Roles

We assign work by model strength. Use the role, not the version number — exact
model IDs are configured at runtime and will change.

| Role | Model (as of 2026-10) | Use for |
|------|----------------------|---------|
| **Thinker / Orchestrator** | Fable (`claude-fable-5-1`) | Planning, decomposition, orchestration, "think it through" work |
| **Evaluator** | Opus (`claude-opus-5-5`) | Judging quality, reviewing designs, verifying claims, final sign-off |
| **Scout** | Haiku (`claude-haiku-5-5`) | Searching, light lookups, fetching, cheap high-volume tasks |
| **Builder** | Sonnet (`claude-sonnet-5-5`) | Writing and editing code |

**Escalation:** if a task exceeds its assigned role's strength, escalate one
tier and note why in the work log. Don't silently struggle at the wrong tier.

---

## 6. Orchestration Pattern — Protect the Main Context

The agent the operator talks to is the **Primary** agent. Its context is
precious; we keep it as small as possible so the operator can steer across a
long project without the conversation filling up.

**Rule: the Primary does not do the heavy lifting itself.**

```
Operator  ⇄  PRIMARY (Fable, thin context — decisions & pointers only)
                 │  spawns
                 ▼
            LEAD agent  (same tier as Primary — the working orchestrator)
                 │  spawns & manages
                 ├── Scout subagents  (Haiku)   → research/findings/*.md
                 ├── Builder subagents (Sonnet) → harness/*, skill/*
                 └── Evaluator subagent (Opus)  → sign-off notes
```

- The **Primary** delegates a goal to a **Lead** agent (same model tier). The
  Lead owns the task: it spawns, manages, and collects from all specialized
  subagents.
- Specialized subagents write their output to **structured `.md` files**, not
  back into the Lead's context where avoidable.
- When the Lead finishes **or its context gets too full**, it does **not** dump
  everything back to the Primary. It writes a structured handoff file
  (`research/findings/<topic>.md` or `docs/...`) and returns to the Primary only:
  (1) one-line status, (2) the path(s) to the output, (3) any decision the
  operator must make. Nothing else.
- The Primary relays that pointer to the operator and moves on. The operator
  reads the file if they want detail.

**Handoff files are structured, never bloated.** Use the template in
`docs/workflow/handoff-template.md`. Headings, short bullets, cited facts,
explicit "open questions" — no transcript dumps, no filler.

> Note for the agent reading this: do **not** spawn subagents for small tasks you
> can do inline — that wastes tokens too. Use this pattern when a task is large,
> parallel, or research-heavy enough that doing it in the Primary's context would
> crowd out the operator. Judgment over ceremony.

---

## 7. Repository Layout

```
CLAUDE.md                   ← you are here: the constitution
README.md                   ← public front door (the pitch)
docs/
  threat-model.md           ← who/what we defend against and our assumptions
  re-techniques/            ← one file per RE tool/technique + its countermeasures
    _index.md               ← catalog index & status
  workflow/
    orchestration.md        ← the agent pattern in detail
    handoff-template.md     ← structured output template for agents
research/
  _index.md                 ← index of research notes
  findings/                 ← dated, structured research outputs
skill/                      ← the Claude skill that drives the harness
harness/                    ← the hardening & audit harness itself
.claude/
  agents/                   ← subagent role definitions (Scout, Builder, Evaluator, Lead)
```

---

## 8. Conventions

- **Write to files, talk in pointers.** Research and analysis go to `docs/` or
  `research/`; chat gets a one-line summary + path.
- **Cite.** Research notes carry source + date. The RE landscape moves fast; an
  uncited claim is a guess.
- **Honesty tiers.** Rate every countermeasure: *Trivial / Speed-bump /
  Meaningful / Strong*, and always name a bypass. Never imply "unbreakable."
- **Audit before harden.** The harness measures first, changes second.
- **Small commits**, each phase-labeled (`research:`, `analysis:`, `harness:`,
  `skill:`, `docs:`).
- **Keep this file true.** It is the first thing every agent reads.

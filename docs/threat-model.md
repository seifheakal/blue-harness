# Threat Model

> What Carapace defends, against whom, under what assumptions, and where the
> hard limits are. Everything in this repo should trace back to something here.

## What we protect
Software **the operator owns or is explicitly authorized to harden** — the
operator's own application build and the assets inside it (embedded logic,
license checks, client-side secrets they accept the risk of shipping, anti-cheat
or anti-tamper logic, proprietary algorithms).

## Who the adversary is
An analyst with physical/local access to a shipped build and standard RE
tooling (see `re-techniques/_index.md`). We assume the adversary:
- Can run the app in a controlled environment they fully own.
- Can read every byte we ship. **Anything in the client is readable.**
- Can attach debuggers, instrument with Frida, dump memory, patch binaries.
- Has unlimited time and can retry. Our goal is to **raise cost**, not to win.

## The one law of client-side protection
> You cannot keep a secret in software you give to the attacker.

Client-side hardening buys **time and cost**, deters casual/low-effort attackers,
protects against automated/at-scale analysis, and creates detectable tamper
events. It never provides cryptographic-grade secrecy for a motivated attacker.
Carapace states this plainly in its reports and never contradicts it.

## Defensive goals (in priority order)
1. **Relocate** what must not leak to the server (eliminate the exposure).
2. **Raise cost** of static analysis (obfuscation, symbol stripping, string
   protection, packing).
3. **Raise cost / detect** dynamic analysis (anti-debug, anti-Frida,
   anti-emulation, integrity/self-check, RASP responses).
4. **Attribute** leaks (watermarking, canary tokens) so a break is traceable.
5. **Prove** each defense is actually present and firing (the audit layer).

## Explicit non-goals
- We do **not** build tools to reverse, deanonymize, or break third-party
  software.
- We do **not** claim unbreakability or ship "protection theater."
- We do **not** rely on a single layer. Defense is layered; any one layer is
  assumed bypassable.

## Strength tiers (used everywhere)
| Tier | Meaning |
|------|---------|
| **Trivial** | Stops nobody competent; documents intent only. |
| **Speed-bump** | Costs a casual attacker minutes; a pro brushes it aside. |
| **Meaningful** | Costs a skilled attacker real time; defeats most automation. |
| **Strong** | Expensive even for experts; usually needs server-side backing. |

Every countermeasure in `docs/re-techniques/` MUST carry a tier and a named
bypass. No exceptions.

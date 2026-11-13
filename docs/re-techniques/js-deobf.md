# Minified / obfuscated JavaScript (deobfuscation)

> **Reference only — NOT worked.** Client-side JS is out of current `CLAUDE.md` §2
> scope. This entry feeds the scope-expansion proposal
> (`docs/proposals/scope-expansion-web-bundle-track.md`). Full cited research:
> `research/findings/2026-11-14-js-deobf-re-landscape.md` (accessed 2026-11-14).

- Category: static (web/bundle track candidate)
- What it does: recovers readable source from minified/bundled/obfuscated
  client-side JavaScript. The shipped artifact is already the language an LLM reads
  best, and every transform is text-to-text, so the skill floor is near zero.
- What it needs from the target: the shipped JS (client code reaches the attacker by
  definition). Cheapest win first: a leaked source map (`.map` / `sourcesContent`).

## Attacker workflow (steps)
1. Acquire the JS; check for leaked source maps (full original source if present).
2. Un-bundle (`webcrack` rewrites `__webpack_require__` back to modules).
3. Undo mechanical obfuscation deterministically (`webcrack` / `synchrony` /
   `restringer` reverse `javascript-obfuscator`/obfuscator.io string arrays + CFF).
4. Restore names/meaning with an LLM (`humanify` — one LLM call per identifier,
   AST-level rewrite via oxc; local Ollama backend supported).
5. Verify by running/diffing; re-prompt per function.

AI automation: devastating. `humanify` (one command) plus public agent-skill routers
("deobfuscate javascript") put this in reach of a non-expert. Measured evidence is
mixed, not one-sided (JsDeObsBench ~61% exec-correctness on benign code, mid-2025
models — secondary-sourced).

## Defensive leverage (step → countermeasure)
| Attacker step | Countermeasure | Strength tier | Known bypass |
|---|---|---|---|
| Grab source map | Withhold `.map` + `sourcesContent` | Trivial as logic-protection (Meaningful vs the map leak only) | Logic still in shipped JS; `humanify`/`webcrack` work without maps |
| Read names | Minification | Trivial | `humanify` renames identifiers back from context |
| Read literals | `javascript-obfuscator` string-array + rotation | Speed-bump | `webcrack`/`synchrony`/`restringer` reverse obfuscator.io output |
| Follow logic | Control-flow flattening / dead-code injection | Speed-bump (15–80% runtime cost) | OBsmith rates flattening "moderate"; LLM reconstructs per function |
| Analyse at all | `selfDefending` / `debugProtection` | Trivial | Headless agent doesn't open DevTools; strip the check after deobf |
| Read any secret | **Server-side secret logic** | **Strong** (honest #1) | Attacker calls the server; the API must be the boundary |

## Harness hooks
- Audit check(s) this maps to: **none yet** (proposed: source-map-leakage +
  identifier-informativeness exposure scorer, if a track is approved).
- Hardening(s) this maps to: **none** (reference only). Note: `javascript-obfuscator`'s
  own README marks the free package "fully vulnerable (no LLM-specific defenses)."

## Sources
- `research/findings/2026-11-14-js-deobf-re-landscape.md` (webcrack/synchrony/restringer/
  humanify READMEs, webpack devtool docs, JsDeObsBench arXiv 2506.20170, OBsmith arXiv
  2510.10066, CASCADE arXiv 2507.17691 — all accessed 2026-11-14; several version/figure
  dates secondary-sourced and flagged).

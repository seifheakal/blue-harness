# WebAssembly decompilation (Wasm)

> **Reference only — NOT worked.** Wasm is out of current `CLAUDE.md` §2 scope. This
> entry feeds the scope-expansion proposal
> (`docs/proposals/scope-expansion-web-bundle-track.md`). Full cited research:
> `research/findings/2026-11-14-wasm-re-landscape.md` (accessed 2026-11-14).

- Category: static (web/bundle track candidate)
- What it does: lowers a `.wasm` module to WAT text and then to C-like code. Wasm is
  a typed, structured stack machine (no arbitrary `goto`, explicit types,
  imports/exports), so it is harder to read than JS/IL but easier than native
  x86/ARM. Decompilers + LLM pipelines already produce usable C.
- What it needs from the target: the `.wasm` module (trivially downloadable from a
  page's network log, or on disk for WASI). Readability rises sharply if the `name`
  custom section or DWARF survive.

## Attacker workflow (steps)
1. Obtain the module (network log / install dir).
2. Lower to text (`wasm2wat`, `wasm-tools print`); names come from the `name` section.
3. Decompile to C-like code (`wasm-decompile`; NotDec; Ghidra + `ghidra-wasm-plugin`).
4. Feed to an LLM for structured reconstruction (WaDec, StackSight; `wasm2c`→LLVM for
   obfuscated modules, per Black Hat Asia 2025).
5. Recover names/semantics (the hard part only once the `name` section is stripped).

AI automation: an unrestricted local model + a NotDec/WaDec-class decompiler yields
readable logic for a typical unobfuscated module. **Scoping trap:** Blazor WASM AOT
still ships the managed IL DLLs — the real surface there is `dotnet-decompile`.

## Defensive leverage (step → countermeasure)
| Attacker step | Countermeasure | Strength tier | Known bypass |
|---|---|---|---|
| Read names | Strip `name` + DWARF + producers (`wasm-opt --strip-debug`, `wasm-tools strip --all`) | Trivial (semantics) / Speed-bump (symbol naming) | LLM semantic renaming — **name-strip-vs-LLM effect unmeasured** |
| Anchor on API | Randomise export/import names (host-JS change) | Speed-bump | Import-signature heuristics (fetch, WebCrypto, WASI) |
| Follow control flow | Control-flow flattening (WASMixer/Tigress) | Speed-bump (LLM) | LLVM deobf via `wasm2c`→LLVM |
| Read memory/consts | Linear-memory encryption (decrypt-on-load) | Speed-bump static / Trivial dynamic | Runtime dump / breakpoint on the decrypt wrapper; key is in-process |
| Read any secret | **Server-side relocation / no in-Wasm keys** | **Strong** | Key extraction from linear memory if shipped |

## Harness hooks
- Audit check(s) this maps to: **none yet** (proposed: detect `name`/DWARF/producers
  presence + export/import exposure, if a track is approved).
- Hardening(s) this maps to: **none** (reference only — pending scope decision).

## Sources
- `research/findings/2026-11-14-wasm-re-landscape.md` (NotDec arXiv 2608.03286, WaDec
  arXiv 2406.11346, StackSight arXiv 2406.04568, WASMixer, wasm-opt/wasm-tools docs,
  Blazor AOT Microsoft Learn — all accessed 2026-11-14; no stripped-vs-unstripped LLM
  measurement exists — the key open question).

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

---

## Runtime integrity + anti-Frida (Slice D) — vs rea Cluster G

Frida is rea's **only in-process modification path**. Two guards raise its cost;
both are libc-only (self-contained SHA-256/HMAC, no OpenSSL).

### Code-integrity + server-nonce attestation — `carapace_integrity.{c,h}`

Defeats the *value* of a patch (e.g. a NOP'd license check). The client returns
`HMAC(key, nonce || SHA-256(hot-function bytes))`; the **server** issues a fresh
nonce per challenge and holds the known-good checksum (`attest_server.py` is the
reference verifier).

```
carapace_hotfn_checksum(out32);                         // SHA-256 of the hot fn
carapace_integrity_response(nonce, nonce_len, mac32);   // HMAC(key, nonce||checksum)
```

| Property | Result |
|---|---|
| patched hot function | checksum changes → MAC mismatch → server **REJECT** |
| replayed response | nonce changed → **REJECT** |
| pristine | **ACCEPT** (C MAC == stdlib `hmac`, cross-checked in verify) |

**Tier:** client self-checksum alone is *Meaningful* (Frida can hook the reader);
the **server-nonce binding pushes toward *Strong*** — a one-time hook at resume
isn't enough. **Named bypass:** a sustained live hook recomputing the pristine
checksum each challenge; the client key can be extracted, so trust rests on the
server nonce + the server holding the good checksum, **not** on client secrecy.
Not a substitute for keeping the secret server-side (the only truly Strong tier).

### Anti-Frida detector — `carapace_antifrida.{c,h}`

```
int flags = carapace_antifrida_scan(detail, sizeof detail);  // 0 = clean
```

Three cheap, independent signals (any one trips): a `frida-agent`/`gum` **mapping**
in `/proc/self/maps`, a Frida worker **thread name** (`gum-js-loop`, …) in
`/proc/self/task/*/comm`, and a **listener on port 27042** (connect probe —
portable where `/proc/net/tcp` is namespaced/stale). Generic GLib names
(`gmain`/`gdbus`) are deliberately not matched, to avoid false positives.

**Tier:** *Meaningful*. **Named bypass:** Frida stalker/stealth modes, a renamed
gadget, a non-default port, or an attacker who edits the signatures once found.

`attest_server.py` — the reference server-side verifier (stdlib `hmac`/`hashlib`):
`nonce` issues a challenge, `verify` accepts/rejects a client response.

---

## String encryption (Slice F) — vs rea Cluster B/C `list_strings`

Removes **live, used** strings from a static `strings` / `list_strings` view by
storing them encrypted and decoding on demand — complementing the identity
transform's decoy pass (which only covers *internal* strings).

- `carapace_string_encrypt.py gen --manifest M.json --mode {enc|plain} --out gen.h`
  — build-time codegen. Reads `{ID: "plaintext"}`, emits C byte tables. The dev
  tree keeps the manifest (clear); the shipped binary carries only ciphertext.
- `carapace_strings.{c,h}` — the runtime loader: `carapace_cstr(id)` /
  `carapace_cstr_into(id, out, cap)` decode on demand.

```
python3 carapace_string_encrypt.py gen --manifest secrets.json --mode enc --out carapace_strings_gen.h
cc -DCARAPACE_GEN_HEADER='"carapace_strings_gen.h"' app.c carapace_strings.c
# then in code:  printf("%s", carapace_cstr(CSTR_API_URL));
```

**Cipher:** a position-dependent **xorshift32 keystream** XOR (seeded per string
id) — not a single-byte XOR that `strings`/entropy triage sees through. The Python
encoder and the C loader run the identical keystream (round-trip proven in verify).

**Tier:** *Speed-bump→Meaningful*. **Named bypass:** the key is embedded in the
binary, so an attacker recovers plaintext **at rest** (re-run the keystream) or
lifts the decoded string from **memory at runtime** (Frida/GDB). This raises cost
against static/one-shot AI analysis; it is **not a secret store** — a secret that
truly can't leak belongs server-side (the only Strong tier).

---

## Analysis-surface exhaustion (Slice I) — vs the naive "ingest everything" agent

Absorbs the commodity AI-RE defender "Exhaust" axis into our native lane, and —
unlike a peer's size-diff "verify" — we **prove** the cost lands on the analyst's
surface, not on the program. Operates on the compiled ELF via `objcopy` (two
non-breaking levers), post-build.

```
python3 carapace_exhaust.py sample_dev sample_dev.exh \
        --sections 4 --section-size 131072 --symbols 300
```

| Lever | What it adds | Why it's non-breaking |
|---|---|---|
| Decoy **non-alloc** sections (`.carapace_exh_*`) | N×`SHT_PROGBITS` with **SHF_ALLOC clear** | the loader never maps a non-alloc section → zero runtime cost, zero behaviour change |
| Synthetic **LOCAL FUNC** symbols (`carapace_exh_fn_*`) | M entries in `.symtab` only | LOCAL + symtab-only → `.dynsym`/exports and dynamic linking untouched |

A naive agent that inventories and dumps every section / enumerates every symbol
pays the full token/context cost of the inflated surface; its inventory can
truncate. Output is **deterministic** (seeded), so builds are reproducible and the
verify can assert byte-identical *runtime* behaviour against a clean baseline.

**Tier: Trivial→Speed-bump** (Speed-bump vs a naive ingest-everything agent — the
commodity-cracking path; Trivial vs anyone who filters). **Named bypass:** restrict
analysis to allocated/executable (`SHF_ALLOC`) sections and to code-referenced
symbols — our decoys are never mapped and our synthetic symbols are never called,
so a one-line filter drops them. **Cost, not prevention.** Pairs with the identity
transform: exhaust **after** decoying so the surface stays plausible.

Proof it fires + is non-breaking (runtime byte-identical, exports intact, decoys
non-alloc, no `.dynsym` pollution): `../verify/test_slice_i.sh`.

---

## Honeytokens / canaries (Slice J) — Poison + Hallucinate + attribution

Plants **plausible, format-valid fake secrets** (AWS-style keys, bearer tokens,
internal URLs, DB creds) so a naive AI-RE agent mines them and reports them as
real **findings** — poisoning its output and, per Quarkslab's observation that
agents confidently report plausible-but-wrong results, amplifying a
**hallucinated** conclusion the attacker then wastes time on. Every token is
**unique per build** and recorded in a **private ledger**, so it is also an
**attribution tripwire**: if one surfaces in a leaked crack, `check` matches it
back to the exact build.

```
python3 carapace_honeytokens.py plant sample_dev sample_dev.honey \
        --ledger private_ledger.json --count 10 --build-tag 2026-11-05-rc1
python3 carapace_honeytokens.py check --ledger private_ledger.json --input leak.txt
```

Placement: a **non-allocated** section (default `.carapace_honey`) — never mapped
at runtime, so the program is byte-identical and the tokens are provably
unreferenced decoys, yet still visible to a whole-file `strings` / `list_strings`
scan (the naive agent's mining path). Deterministic (seeded) for reproducible
builds + ledger.

**Tier:** *Speed-bump* as poison / time-waste (a careful analyst xref-validates a
"secret" and discards one nothing references); **Meaningful FOR DETECTION** as an
attribution tripwire — a unique token leaking is strong evidence the build was
reversed and names which build, but it is after-the-fact, **never prevention**.
**Named bypass:** behavioural validation drops unreferenced tokens; the default
section name is a tell (rename/randomise with `--section` for production; the
strongest blend is compiling decoys into real `.rodata` at build time — a
follow-on). A honeytoken is **not** a real secret.

Keep the ledger **PRIVATE** (out of the shipped artifact) — it is the key that
makes attribution work. Proof it fires + is non-breaking + attribution/uniqueness:
`../verify/test_slice_j.sh`.

---

## Mach-O local-symbol strip (Slice O) — the first Mach-O harden

`carapace_macho_strip.py` removes the **LOCAL** (static / internal) symbols from a
Mach-O's symbol table — exactly what `strip -x` does — so an AI-RE agent loses the
internal names it mines, while the **external / undefined** symbols the dynamic
linker needs are preserved. Byte-level, **no Apple/LLVM toolchain**, via
`LC_SYMTAB` + `LC_DYSYMTAB`.

```
python3 carapace_macho_strip.py --in app --out app.stripped      # or: carapace apply app
```

| Property | Result |
|---|---|
| local (static) symbols | removed (names gone from the bytes) |
| external / undefined symbols | preserved (dyld needs them) |
| segments / sections / file offsets | byte-identical (in-place, size stable) |
| fat/universal, empty symtab, no `LC_DYSYMTAB` | refused with guidance |

**Honest limit (CLAUDE.md §3):** we run on Linux and **cannot execute a Mach-O**,
so — unlike the ELF transforms — we do **not** claim runtime-identical here. The
verify proves the transform is **surgical** (only the local nlist entries + their
strings go; everything else is preserved); **runtime-identical is platform-gated
to a macOS host**. Stripping also invalidates an existing code signature, so the
correct order is strip → codesign on the build host (the tool warns if signed).

**Tier:** *Speed-bump→Meaningful*. **Named bypass:** the exported names remain and
a thorough agent recovers logic from behavior/xrefs regardless of names. Proof
(structural): `../verify/test_slice_o.sh`.

---

## Windows PE harden path (Slice P) — the first PE harden

PE was audit-only (Slice G, `audit/pe_exposure_audit.py`). Slice P gives it a
post-build **harden** path with three provable, non-breaking levers — all
byte-level, **no Windows toolchain**, proven **structurally** on Linux with no
Windows host (exactly how the Slice O Mach-O strip is proven). Drive the whole set
with `carapace harden <exe>`, or run a lever directly.

| Lever (`carapace_pe_*.py`) | What it does | Why it's non-breaking | Tier · named bypass |
|---|---|---|---|
| `carapace_pe_strip.py` | clears the **COFF symbol table** + **debug directory / CodeView PDB-path** | COFF symbols + debug data are never read by the running program (a debugger reads them); **in-place, size stable**; imports/exports/entry/sections/`SizeOfImage` byte-identical | **Speed-bump→Meaningful** · imports + exported names remain; behaviour recoverable |
| `carapace_pe_exhaust.py` | appends decoy **NON-MAPPED overlay** regions (surface exhaustion) | the loader builds the image from the section table up to `SizeOfImage`; **overlay bytes are never mapped**. Append-only → the original file is a byte-identical prefix | **Trivial→Speed-bump** · map only section-covered bytes (the overlay is ignored) |
| `carapace_pe_honeytokens.py` | plants unique plausible fake secrets into the overlay + a **private ledger** | overlay = non-mapped; append-only; tokens are whole-file-`strings` visible but provably unreferenced. `check` attributes a leaked token to its build | **Speed-bump** (poison) / **Meaningful FOR DETECTION** (attribution) · xref-validate + rename the footer marker |

```
python3 carapace_pe_strip.py --in app.exe --out app.stripped.exe
python3 carapace_pe_exhaust.py app.exe app.exh.exe --sections 4 --section-size 131072
python3 carapace_pe_honeytokens.py plant app.exe app.honey.exe --ledger private_ledger.json --build-tag rc1
python3 carapace_pe_honeytokens.py check --ledger private_ledger.json --input leak.txt
```

**Why the overlay (and not new section-table entries):** a provably non-mapped PE
*section* would need either a loader-specific "don't map" trick we can't verify
without a Windows host, or growing `SizeOfHeaders` (which shifts every file offset
and breaks the byte-stable claim). The overlay is the loader-independent,
structurally-provable non-mapped home, so the proof needs no Windows host.

**Honest limit (CLAUDE.md §3):** we run on Linux and **cannot execute a PE**, so —
like the Mach-O strip — we do **not** claim runtime-identical here. The verify
proves each lever is **surgical / append-only** and the decoys are **provably in
the overlay** (past every section's raw data); **runtime-identical is platform-
gated to a Windows host**. Appending overlay data or stripping metadata invalidates
an Authenticode signature, so sign **after** hardening (each tool warns if signed).
The honeytoken token generators are **shared** with the ELF pass
(`carapace_honeytokens.generate/check`). Keep every ledger **PRIVATE**. These are
**cost / detection, not prevention.** Proof: `../verify/test_slice_p.sh`.

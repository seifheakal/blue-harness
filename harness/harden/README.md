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

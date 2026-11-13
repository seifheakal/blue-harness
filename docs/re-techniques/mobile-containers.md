# Mobile containers (APK / AAB / IPA) — native-payload reach

- Category: mobile / packaging
- What it does: a mobile app ships as a ZIP container. An AI-assisted RE agent
  (`mobile-ai-re`, or a plain `unzip` + Track A tools) unpacks it and reverses the
  **native** code inside — Android `.so` (ELF under JNI) and iOS Mach-O (app
  binary + frameworks) — with exactly the static/dynamic tooling we already model
  for bare binaries (Ghidra/radare2/Frida, now LLM-driven).
- What it needs from the target: an unpackable container (always — it is a ZIP)
  and native payloads that still carry symbols / plaintext strings / an un-stripped
  structure. Carapace's job: reach **inside** the container and raise the cost of
  the native payloads using the existing per-format hardeners.
- Scope (CLAUDE.md §2): **native payloads only.** Dalvik/DEX (Java/Kotlin) is a
  separate track and **out of scope** — `classes*.dex` is enumerated-and-skipped,
  never hardened here.

## Attacker workflow (steps)
1. **Unpack** the container — `unzip`/`apktool`/`unzip Payload`. Trivial; the
   wrapper is not a barrier.
2. **Locate native code** — Android: `lib/<abi>/*.so`; iOS: `Payload/*.app/<bin>`
   + `…/Frameworks/*.framework/*` + `*.dylib`. (Managed code — DEX / the Obj-C/Swift
   metadata — is the *other* track; out of scope here.)
3. **Reverse the native payload** — load the `.so` / Mach-O in Ghidra/IDA/radare2
   (static) or hook it with Frida/objection (dynamic): read symbols, mine strings,
   find the check, patch or hook it. This is the Track A workflow, now driven by an
   LLM from one sentence (P0).
4. **Repack & re-sign** (if tampering) — rebuild the ZIP and re-sign; on-device the
   platform verifies the signature, so a crack that ships must carry a (self- or
   stripped-) signature the target device accepts.

## Defensive leverage (step → countermeasure)
| Attacker step | Countermeasure | Strength tier | Known bypass |
|---------------|----------------|---------------|--------------|
| 1 Unpack | none — do **not** pretend the ZIP is a barrier | — | n/a (it is a ZIP) |
| 2 Locate | — (enumeration is symmetric; we audit the same members) | — | — |
| 3a Reverse `.so` names | **ELF identity transform** (strip/map/decoy symbols + internal strings) — Slice B | Speed-bump→Meaningful | behavioural xref/value-flow ignores names |
| 3b Reverse — mine the inventory | **ELF exhaust** (decoy non-alloc sections + synthetic symbols) — Slice I | Trivial→Speed-bump | filter to SHF_ALLOC + code-referenced symbols |
| 3c Reverse — trust the strings | **ELF honeytokens** (plausible decoy secrets + private ledger) — Slice J | Speed-bump (poison) / Meaningful for DETECTION | xref-validate drops unreferenced tokens |
| 3d Reverse Mach-O names | **Mach-O local-symbol strip** (`strip -x`) — Slice O (+ decoy/honeytokens once Slice Q merges) | Speed-bump→Meaningful | exported names remain; behaviour recoverable |
| 4 Repack/re-sign | **none we provide** — stated as a limitation; on-device integrity rests on the **platform verifying the signature**, which a client harness cannot fake (server-side-truth, CLAUDE.md §3) | — | attacker self-signs for a rooted/jailbroken device; the trust anchor is the store/OS, not the artifact |

**The container layer adds no strength of its own.** Its value is *reach*: the
native payloads inside a mobile package get the same scored audit and the same
post-build hardeners as a bare binary, in one command. Every bit of strength (and
every bypass) is inherited from the delegated ELF/Mach-O slice.

## Honest signing limitation (non-negotiable)
Repacking changes bytes inside the container and therefore **invalidates its code
signature**:
- **APK/AAB** — the v2/v3 scheme is whole-file; any change outside the signing
  block invalidates it. The operator **must re-sign** (`apksigner`), which Carapace
  does **not** do and does **not** fake.
- **iOS** — the signature covers the Mach-O *and* the resource hashes; iOS refuses
  an app whose signature does not verify. The operator **must re-sign** (`codesign`
  + a valid provisioning profile). App Store binaries are also FairPlay-encrypted —
  harden the **pre-signing build**, not a store download.

Carapace repacks but never signs, and says so in every tool path and in the verify.

## Harness hooks
- Audit check(s): `harness/audit/mobile_container_audit.py` — unzip, enumerate
  native payloads by path + magic byte, delegate each to the ELF
  (`elf_exposure_audit`) or Mach-O (`macho_exposure_audit`) auditor, report a
  per-payload scored posture. Read-only.
- Hardening(s): `harness/harden/carapace_mobile.py` — for each enumerated payload,
  dispatch through the **stable Slice-M format entry point** (`skill/carapace.py
  harden`, falling back to `apply`) so it uses whatever the per-format hardener
  offers today and automatically picks up new levers (e.g. Slice Q Mach-O) once
  merged; collect the PRIVATE map/ledger sidecars **outside** the container; repack;
  print the signing limitation. Wired into the skill's magic-byte dispatch
  (`carapace audit|report|harden <app.apk|app.aab|app.ipa>`) and
  `make harden-apk|harden-ipa|harden-mobile`.
- Verify: `harness/verify/test_slice_r.sh` — synthetic ZIP fixtures (a tiny ELF
  `.so` + a tiny Mach-O) prove enumeration delegates correctly and that harden
  dispatches + repacks with the signing limitation stated. ZIP handling is pure
  Python → cross-platform (the ELF-harden sub-checks gate on `objcopy`/`gcc`, as the
  bare-ELF slices already do; the Mach-O path is toolchain-free).

## Sources
- APK Signature Scheme v2 (whole-file; repack invalidates) —
  <https://source.android.com/docs/security/apksigning/v2> (2026-11-13).
- Android ABIs (`/lib/<abi>/lib<name>.so`) —
  <https://developer.android.com/ndk/guides/abis> (2026-11-13).
- The Android App Bundle format (ZIP; `base/` module) —
  <https://developer.android.com/guide/app-bundle/app-bundle-format> (2026-11-13).
- Full facts + iOS signing/FairPlay notes:
  `research/findings/2026-11-13-mobile-container-reach.md`.

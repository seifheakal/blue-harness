# Mobile-container reach — facts for Slice R

- Date: 2026-11-13
- Author: slice-r-mobile-reach session (session 2 of 4)
- Purpose: ground the Slice R work — teach Carapace to unpack a mobile container
  (Android APK/AAB, iOS IPA), enumerate its **native** payloads, and apply the
  EXISTING per-format native hardeners (ELF / Mach-O) to them, then repack.
- Scope reminder (CLAUDE.md §2): **native payloads only.** Dalvik/DEX (Java/Kotlin
  bytecode) is a separate track and is **out of scope** here. Native `.so` under
  JNI is reversed with the Track A static/dynamic tools, so it is in scope.

---

## 1. Container formats are all ZIP

- **APK** — a ZIP. Typical members: `AndroidManifest.xml` (binary XML),
  `classes*.dex` (Dalvik bytecode — OUT of scope), `resources.arsc`, `res/…`,
  `META-INF/…` (signatures), and **`lib/<abi>/lib<name>.so`** (native ELF).
- **AAB** (Android App Bundle) — a ZIP, publishing format (not installed directly;
  Google Play / `bundletool` generate split APKs from it). The base module lives
  under `base/`, so native libraries sit at **`base/lib/<abi>/lib<name>.so`**
  (and `<module>/lib/<abi>/…` for feature modules). `BundleConfig.pb` /
  `*/manifest/`, `*.pb` protos mark it as a bundle.
- **IPA** — a ZIP. Everything lives under **`Payload/<AppName>.app/`**: the main
  app binary `Payload/<AppName>.app/<AppName>` (a **Mach-O**, no extension),
  embedded frameworks `Payload/<AppName>.app/Frameworks/*.framework/<Name>` and
  `*.dylib` (Mach-O), plus `Info.plist`, `_CodeSignature/CodeResources`, assets.

**Implication:** one ZIP-unpack path covers all three. The only per-format work is
(a) *where* native payloads live and (b) *which* native auditor/hardener to call.

### ABIs (Android)
`armeabi-v7a` (ELF32 ARM), `arm64-v8a` (ELF64 AArch64), `x86` (ELF32), `x86_64`
(ELF64). All are **ELF** → the existing ELF auditor + ELF hardeners apply.
Source: Android NDK "Android ABIs" — `/lib/<abi>/lib<name>.so`.

---

## 2. Native payload → existing Carapace format

| Container | Native payload members | Format | Carapace reach |
|-----------|------------------------|--------|----------------|
| APK | `lib/<abi>/*.so` | ELF (arm/arm64/x86) | ELF audit (Slice A/B/G-style) + ELF harden (identity/exhaust/honeytokens, Slices B/I/J) |
| AAB | `*/lib/<abi>/*.so` (e.g. `base/lib/…`) | ELF | same as APK |
| IPA | `Payload/*.app/<bin>`, `…/Frameworks/*.framework/*`, `*.dylib` | Mach-O | Mach-O audit (Slice N) + Mach-O harden (Slice O strip; Slice Q decoy/honeytokens once merged) |

The robust enumerator keys on **magic bytes**, not just path/extension: an `.so`
under `lib/<abi>/` is confirmed ELF by `\x7fELF`; a member under `Payload/…app/`
is a Mach-O payload if its first bytes are a Mach-O magic. Resources
(`.plist`, `.png`, `.arsc`, `.dex`, protobufs) are skipped — they are not native
code and are out of scope.

---

## 3. Signing — the honest limitation (DO NOT FAKE)

Hardening a payload changes bytes inside the container, which **invalidates the
container's code signature**. Carapace must state this plainly and must NOT
pretend to re-sign.

- **Android APK Signature Scheme v2/v3** is a **whole-file** scheme: an "APK
  Signing Block" is inserted immediately before the ZIP Central Directory, and
  the signature hashes **everything except that block**. *Any* modification
  outside the signing block (including ZIP metadata) invalidates the v2/v3
  signature. A stripped v2 signature is also rejected when the v1 (JAR) signature
  says v2 must be present. → after any repack the operator **must re-sign**
  (`apksigner sign …`, then `apksigner verify`). Source:
  <https://source.android.com/docs/security/apksigning/v2> (accessed 2026-11-13).
- **AAB** is itself signed and is further processed by Play; a modified bundle
  must be re-signed and re-uploaded. (Hardening an AAB's `.so` is really a
  pre-publish build step.)
- **iOS** code signing covers the Mach-O (`LC_CODE_SIGNATURE`) **and** resource
  hashes (`_CodeSignature/CodeResources`). Modifying any signed file breaks the
  signature; iOS will refuse to launch an app whose signature does not verify.
  → the operator **must re-sign** with `codesign` and a valid provisioning
  profile / distribution identity. App Store binaries are additionally
  FairPlay-**encrypted** (`LC_ENCRYPTION_INFO[_64]` cryptid=1); static hardening
  of an already-encrypted App Store binary is not meaningful (and decrypting it
  is the attacker's job — out of scope). Carapace targets the operator's **own
  pre-signing build**.

**Bottom line, stated in every tool path + the verify:** Carapace repacks but
**does not sign**. Re-signing is the operator's job with their own keystore /
signing identity, and **on-device integrity ultimately depends on the platform
verifying that signature** — something a client-side harness neither provides nor
can fake. This is the same server-side-truth discipline as the rest of the project
(CLAUDE.md §3): the trust anchor is not in the artifact.

---

## 4. Honesty tiers for the Slice R capabilities

Slice R adds **reach**, not a new countermeasure — the strength is whatever the
delegated ELF/Mach-O hardener provides, per its own slice's tier. The
container-level capabilities rate as:

- **Container audit (unpack + enumerate + delegate):** this is measurement, not a
  defense — no tier. Honest value: it makes the native attack surface *inside* a
  mobile package visible with the same scored posture as a bare binary. Bypass:
  n/a (read-only); limitation: it does not look at DEX (out of scope) and reports
  only what the per-format auditors can infer statically.
- **Container harden (dispatch native hardeners + repack):** tier is **inherited**
  from the delegated passes (ELF identity Speed-bump→Meaningful; exhaust
  Trivial→Speed-bump; honeytokens Speed-bump / Meaningful-for-DETECTION; Mach-O
  strip Speed-bump→Meaningful). The *container* layer adds **no** strength of its
  own. Named bypass (container level): re-signing is the operator's and the
  attacker simply re-unpacks the repacked container — the ZIP wrapper is not a
  barrier; the strength is entirely in the per-payload transforms, each with its
  own named bypass. **Overclaim to avoid:** "hardened the app" — we hardened the
  *native payloads*; the DEX/managed code and the server trust path are untouched.

---

## 5. What this buys the operator (and what it does not)

- Buys: the Android `.so` / iOS Mach-O inside the operator's package get the same
  identity/exhaust/honeytoken/strip treatment as a bare binary, in one command,
  with a scored before/after and an honest ordered plan — closing the one
  in-scope format family (mobile containers) that Carapace could not previously
  reach into.
- Does **not** buy: DEX/Dalvik protection (out of scope), re-signing, or any
  on-device enforcement. Those are explicitly the operator's / the platform's.

Sources: [APK signature scheme v2](https://source.android.com/docs/security/apksigning/v2),
[Android ABIs](https://developer.android.com/ndk/guides/abis),
[The Android App Bundle format](https://developer.android.com/guide/app-bundle/app-bundle-format).

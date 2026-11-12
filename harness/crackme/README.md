# harness/crackme — the Carapace CrackMe (Slice K)

A tiny, self-contained challenge for **empirical** measurement: the operator's own
binary, hardened by Carapace, offered to an AI-RE agent on a sandboxed VM so we can
*measure* how much harder it got. Defensive only — your own binary, your own VM.

- `crackme.c` — the challenge. One source, two builds. It checks `argv[1]` against
  a FLAG read through the Slice-F string loader (`carapace_cstr`).
- `build_crackme.sh` — builds the matched pair into `build/` (gitignored):
  - `crackme_baseline` — flag **plaintext**, no guards (easy target)
  - `crackme_hardened` — flag **encrypted** + build-time guards + post-build
    `carapace harden` (decoy / exhaust / honeytokens)
  - `crackme_hardened.honey-ledger.json` — **PRIVATE** attribution key (never ship)
  - `SEAL.json` — the **publishable** digest of the flag (a hash, not the flag)
- `seal.py` — `seal` writes `SEAL.json`; `verify` checks a claimed flag against it.
  This is what makes the CrackMe publishable without shipping the answer.

The flag plaintext is **never** committed: supply it via `$CARAPACE_CRACKME_SECRET`
or `secret.local.txt` (gitignored); a labelled default is used only for self-test.

Run it for real, and score it: **`docs/workflow/slice-k-empirical-runbook.md`**.
Prove the plumbing (no agent, no VM): `../verify/test_slice_k.sh`.

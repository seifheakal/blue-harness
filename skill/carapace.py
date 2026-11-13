#!/usr/bin/env python3
# Carapace — the harness driver the skill calls (Slice C).
#
# WHAT THIS IS
#   A thin, deterministic entry point over harness/ that implements the product
#   loop from CLAUDE.md "done and worth it" #4: run the AUDIT on an operator
#   target, read the scored posture + informativeness, and RECOMMEND the next
#   highest-value hardening — then optionally APPLY the one that is safe to apply
#   to an already-built binary.
#
#   It exists so the skill's behavior is reproducible and testable (a prose-only
#   skill can't be verified). SKILL.md tells Claude to call this; the policy lives
#   here, in one place, honest by construction.
#
# HONESTY (CLAUDE.md §3/§8): audit before harden. Every recommendation carries a
#   strength tier and a NAMED bypass, surfaced verbatim — never "unbreakable."
#   The only Strong tier is server-side relocation, stated when it applies.
#
# KINDS OF HARDENING (the skill must not conflate them):
#   post-build : applicable to the shipped binary as-is (the identity transform).
#   build-time : requires rebuilding from source (the core-dump / anti-ptrace
#                guards) — we RECOMMEND and show the integration step; we do NOT
#                pretend to patch an existing binary into having them.
#   roadmap    : a known-valuable hardening not yet implemented in this harness
#                (stated plainly, not silently skipped).

import os
import sys
import json
import argparse
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_DIR = os.path.join(REPO, "harness", "audit")
AUDIT = os.path.join(AUDIT_DIR, "elf_exposure_audit.py")
HARDEN_DIR = os.path.join(REPO, "harness", "harden")
TRANSFORM = os.path.join(HARDEN_DIR, "carapace_identity_transform.py")
EXHAUST = os.path.join(HARDEN_DIR, "carapace_exhaust.py")
HONEY = os.path.join(HARDEN_DIR, "carapace_honeytokens.py")
MACHO_STRIP = os.path.join(HARDEN_DIR, "carapace_macho_strip.py")
PE_STRIP = os.path.join(HARDEN_DIR, "carapace_pe_strip.py")
PE_EXHAUST = os.path.join(HARDEN_DIR, "carapace_pe_exhaust.py")
PE_HONEY = os.path.join(HARDEN_DIR, "carapace_pe_honeytokens.py")

sys.path.insert(0, AUDIT_DIR)
from elf_exposure_audit import analyze, render  # noqa: E402  (ELF: analyze/render)
import pe_exposure_audit as pe_audit            # noqa: E402  (PE: analyze/render/recommend)


def _rel(p):
    try:
        return os.path.relpath(p, REPO)
    except ValueError:
        return p


# ---- format dispatch (route by magic byte) --------------------------------
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",   # 32-bit (BE/LE)
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",   # 64-bit (BE/LE)
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",   # fat / universal
}


def _detect_format(path):
    """ELF / PE / Mach-O / mobile-container by magic, so one front door covers all.
    A ZIP (PK..) is a mobile container candidate (APK/AAB/IPA); the mobile tools
    classify it precisely and refuse a non-mobile ZIP cleanly."""
    with open(path, "rb") as f:
        head = f.read(4)
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:2] == b"MZ":
        return "pe"
    if head in _MACHO_MAGICS:
        return "macho"
    if head[:2] == b"PK":
        return "mobile"
    return "unknown"


# Mobile-container tools (Slice R) are wired lazily, like the Mach-O scanner, so
# the bare-binary path never pays their import cost.
def _mobile_audit():
    import importlib
    return importlib.import_module("mobile_container_audit")


def _mobile_harden():
    import importlib
    sys.path.insert(0, HARDEN_DIR)
    return importlib.import_module("carapace_mobile")


# Mach-O scanner is wired lazily so the ELF/PE path never pays its import cost
# and the skill still works if it isn't present yet.
def _macho_audit():
    import importlib
    return importlib.import_module("macho_exposure_audit")


_SERVER_TRUTH = (
    "  The only Strong tier is format-independent: relocate secrets & trust "
    "decisions\n  server-side — what the client never holds can't be reversed "
    "(CLAUDE.md §3).")


def _nonelf_note(fmt):
    return (f"  Note: this audit covers {fmt.upper()}. The harness's apply/harden "
            "countermeasures\n  currently target ELF; for other formats the audit is "
            "read-only today.\n" + _SERVER_TRUTH)


# ---- recommendation policy (ordered, highest value first) ----------------
# Each rule inspects the audit signals and, if it applies, returns a structured
# recommendation. Order encodes "next highest-value hardening."
def _rules(s, binpath):
    b = _rel(binpath)
    inf = s["informativeness"]
    out = []

    # 1. Identity exposure — names/strings an LLM agent reasons from. POST-BUILD.
    if s["symbols_present"] or s["debug_info_present"] or inf["symbol_total"] > 0:
        out.append({
            "id": "identity-transform",
            "title": "Degrade dev identity: strip / map / decoy symbols (+ internal strings)",
            "kind": "post-build",
            "weapon": "rea Cluster B/C + the AI layer (names/strings the agent reasons from)",
            "tier": "Speed-bump→Meaningful (Meaningful vs lazy/one-shot agents & junior analysts)",
            "bypass": "Behavioral cross-check (xrefs/value-flow) ignores names; a thorough agent "
                      "recovers logic, and rea's coverage ledger surfaces decoy contradictions.",
            "command": f"python3 harness/harden/carapace_identity_transform.py transform "
                       f"--mode D --in {b} --out {b}.release --map {b}.carapace-map.json",
            "note": "Keep the mapping file PRIVATE (out of the shipped artifact). Mode S strips, "
                    "M keeps a reversible opaque map, D plants plausible decoys.",
        })

    # 2. Core-dump exposure — a crash core hands the agent memory. BUILD-TIME.
    if not s["coredump_guard_present"]:
        out.append({
            "id": "coredump-guard",
            "title": "Add core-dump suppression guard",
            "kind": "build-time",
            "weapon": "rea Cluster E (inspect_recorded_crash)",
            "tier": "Speed-bump",
            "bypass": "Attacker re-enables cores on their own host, or reads live memory via Frida/GDB.",
            "command": "link harness/harden/carapace_guards.c and call carapace_guard_coredump() "
                       "at startup (see harness/harden/README.md)",
            "note": "Compile-time: requires a rebuild. setrlimit(RLIMIT_CORE,0)+prctl(PR_SET_DUMPABLE,0).",
        })

    # 3. Debug/instrumentation attach — the #1 practical threat. BUILD-TIME.
    if not s["antiptrace_guard_present"]:
        out.append({
            "id": "antiptrace-guard",
            "title": "Add anti-ptrace / anti-debug guard",
            "kind": "build-time",
            "weapon": "rea Cluster G (Frida attach, ptrace-based) + Cluster H (GDB)",
            "tier": "Meaningful",
            "bypass": "Frida can hook the check; a spawn-paused session loads a bypass before it runs.",
            "command": "link harness/harden/carapace_guards.c and call carapace_guard_antiptrace() "
                       "at startup (see harness/harden/README.md)",
            "note": "Compile-time: requires a rebuild. TracerPid read then PTRACE_TRACEME slot-claim.",
        })

    # 3b. Frida injection — rea's only in-process modification path. BUILD-TIME.
    if not s["antifrida_guard_present"]:
        out.append({
            "id": "antifrida-detector",
            "title": "Add anti-Frida detector (maps / thread-name / port-27042 scan)",
            "kind": "build-time",
            "weapon": "rea Cluster G (start_frida_session + load_frida_script — inject path)",
            "tier": "Meaningful",
            "bypass": "Frida stalker/stealth modes, a renamed gadget, a non-default port, or an "
                      "attacker who edits the signatures once found.",
            "command": "link harness/harden/carapace_antifrida.c and call carapace_antifrida_scan() "
                       "at startup / periodically (see harness/harden/README.md)",
            "note": "Compile-time. One of three signals trips detection; no single client check suffices.",
        })

    # 3c. Code integrity — defeats the VALUE of a patch, server-tied. BUILD-TIME.
    if not s["integrity_guard_present"]:
        out.append({
            "id": "integrity-attestation",
            "title": "Add runtime code-integrity self-checksum + server-nonce attestation",
            "kind": "build-time",
            "weapon": "rea Cluster G (patch a hot function, e.g. a license check)",
            "tier": "Meaningful→Strong (the server-nonce binding is what pushes it toward Strong)",
            "bypass": "A sustained live hook that recomputes the pristine checksum each challenge; "
                      "the client key can be extracted — so trust rests on the SERVER nonce + the "
                      "server holding the good checksum, not on client-side secrecy.",
            "command": "link harness/harden/carapace_integrity.c, attest with "
                       "carapace_integrity_response(nonce) to your server (ref: harness/harden/attest_server.py)",
            "note": "Compile-time + a server. Replay- and patch-resistant only with a per-challenge "
                    "server nonce; not a substitute for keeping the secret server-side.",
        })

    # 4. High plaintext-string density — free intel. BUILD-TIME (Slice F).
    if s["string_density"] >= 0.05 and not s["string_encryption_present"]:
        out.append({
            "id": "string-encryption",
            "title": "Encrypt live strings + decode on demand (removes them from a static view)",
            "kind": "build-time",
            "weapon": "rea Cluster B/C (list_strings)",
            "tier": "Speed-bump→Meaningful",
            "bypass": "The key is embedded — recover plaintext at rest (re-run the keystream) or "
                      "lift the decoded string from memory at runtime (Frida/GDB).",
            "command": "mark strings in a manifest, run harness/harden/carapace_string_encrypt.py gen, "
                       "link harness/harden/carapace_strings.c and use carapace_cstr(id) (see harden/README.md)",
            "note": "Compile-time. Not a secret store — a secret that truly can't leak belongs "
                    "server-side. The identity transform's decoy pass covers internal strings; this "
                    "covers live, used strings.",
        })

    # 4b. Analysis-surface exhaustion — tax the naive agent's budget. POST-BUILD.
    if not s.get("exhaustion_present"):
        out.append({
            "id": "exhaustion",
            "title": "Inflate analysis surface: decoy non-alloc sections + synthetic symbols",
            "kind": "post-build",
            "weapon": "the naive 'ingest everything' AI-RE agent (context/token/inventory budget)",
            "tier": "Trivial→Speed-bump (taxes the lazy automated path; not a comprehension blocker)",
            "bypass": "Restrict analysis to allocated/executable (SHF_ALLOC) sections and to "
                      "code-referenced symbols — our decoys are never mapped and never called.",
            "command": f"python3 harness/harden/carapace_exhaust.py {b} {b}.exh "
                       f"--sections 4 --section-size 131072 --symbols 300",
            "note": "Post-build; runtime byte-identical, exports untouched (verified). Pairs with the "
                    "identity transform — exhaust AFTER decoying so the surface stays plausible.",
        })

    # 4c. Honeytokens / canaries — poison the agent's findings + attribution. POST-BUILD.
    if not s.get("honeytokens_present"):
        out.append({
            "id": "honeytokens",
            "title": "Plant honeytokens / canaries (plausible decoy secrets + private ledger)",
            "kind": "post-build",
            "weapon": "the naive agent's string-mining 'findings' (poison) + leak attribution",
            "tier": "Speed-bump (poison) / Meaningful FOR DETECTION (attribution — not prevention)",
            "bypass": "A careful analyst xref-validates a 'secret' and drops one nothing references; "
                      "the default section name is a tell, so rename/randomise it for production.",
            "command": f"python3 harness/harden/carapace_honeytokens.py plant {b} {b}.honey "
                       f"--ledger {b}.honey-ledger.json --count 10 --build-tag <build-id>",
            "note": "Post-build; runtime byte-identical, exports untouched (verified). Keep the ledger "
                    "PRIVATE — it attributes a leaked token to the exact build. Detects/attributes a "
                    "crack; it does not stop one.",
        })

    # 5. Link hardening — raises effort, not a decompile blocker.
    if s["hardening"]["relro"] != "full":
        out.append({
            "id": "full-relro",
            "title": "Link with full RELRO + BIND_NOW",
            "kind": "build-time",
            "weapon": "generic exploitation surface (parity with rea's inspect_binary_layout)",
            "tier": "Trivial→Speed-bump (raises effort; not a comprehension blocker)",
            "bypass": "Flags don't stop decompilation; purely a runtime-integrity nicety.",
            "command": "rebuild with -Wl,-z,relro,-z,now",
            "note": "Compile/link-time.",
        })

    # Always-true closing truth: the only Strong tier.
    out.append({
        "id": "server-relocation",
        "title": "Relocate secrets & trust decisions server-side",
        "kind": "design",
        "weapon": "all client-side analysis (the honest #1 recommendation, CLAUDE.md §3)",
        "tier": "Strong (the ONLY Strong tier — what the client never holds can't be reversed)",
        "bypass": "None for the relocated secret itself; the client still needs anti-tamper for the "
                  "request path, which a server nonce-challenge backs.",
        "command": "(architecture change — move the secret/logic off the client)",
        "note": "Applies whenever the client holds something it cannot afford to leak.",
    })
    return out


def recommend(binpath, want_all=False):
    s = analyze(binpath)
    rules = _rules(s, binpath)
    # the "next highest-value hardening" = first that is actually actionable now
    # (post-build or build-time), not the always-on design note, unless nothing
    # else applies.
    actionable = [r for r in rules if r["id"] != "server-relocation"]
    top = actionable[0] if actionable else rules[-1]
    return s, (rules if want_all else [top])


# ---- rendering -----------------------------------------------------------
def _fmt_rec(r):
    L = [f"  [{r['kind'].upper()}] {r['title']}",
         f"      denies/degrades : {r['weapon']}",
         f"      strength tier   : {r['tier']}",
         f"      named bypass    : {r['bypass']}",
         f"      how             : {r['command']}"]
    if r.get("note"):
        L.append(f"      note            : {r['note']}")
    return "\n".join(L)


def _unknown(path):
    raise ValueError(f"unrecognized format (not ELF/PE/Mach-O): {_rel(path)}")


def cmd_audit(args):
    fmt = _detect_format(args.binary)
    if fmt == "elf":
        print(render(analyze(args.binary)))
    elif fmt == "pe":
        print(pe_audit.render(pe_audit.analyze(args.binary)))
    elif fmt == "macho":
        m = _macho_audit()
        print(m.render(m.analyze(args.binary)))
    elif fmt == "mobile":
        mca = _mobile_audit()
        try:
            print(mca.render(mca.analyze(args.binary)))
        except mca.ContainerError as e:
            print(f"carapace error: {e}", file=sys.stderr)
            return 2
    else:
        _unknown(args.binary)
    return 0


def cmd_recommend(args):
    fmt = _detect_format(args.binary)
    if fmt == "mobile":
        mca = _mobile_audit()
        try:
            s = mca.analyze(args.binary)
        except mca.ContainerError as e:
            print(f"carapace error: {e}", file=sys.stderr)
            return 2
        print(f"Carapace — next hardening for {_rel(args.binary)} "
              f"[{s['kind'].upper()} / {s['os']}]")
        print(f"  {s['payload_count']} native payload(s); worst exposure "
              f"{s['max_score']}/100")
        print()
        print(f"  {mca.recommend(s)}")
        print()
        print(_SERVER_TRUTH)
        return 0
    if fmt in ("pe", "macho"):
        if fmt == "pe":
            s = pe_audit.analyze(args.binary)
            line = pe_audit.recommend(s)
        else:
            m = _macho_audit()
            s = m.analyze(args.binary)
            line = m.recommend(s)
        print(f"Carapace — next hardening for {_rel(args.binary)} [{fmt.upper()}]")
        print(f"  exposure score {s['score']}/100 — {s['tier']}")
        print()
        print(f"  {line}")
        print()
        print(_nonelf_note(fmt))
        return 0
    if fmt != "elf":
        _unknown(args.binary)
    s, recs = recommend(args.binary, want_all=args.all)
    if args.json:
        print(json.dumps({"score": s["score"], "tier": s["tier"], "recommendations": recs}, indent=2))
        return 0
    print(f"Carapace — next hardening for {_rel(args.binary)}")
    print(f"  exposure score {s['score']}/100 — {s['tier']}")
    print()
    for r in recs:
        print(_fmt_rec(r))
        print()
    print("  Honest footer: nothing here is unbreakable — anti-RE only raises the")
    print("  attacker's cost. The only Strong tier is moving the secret off the client.")
    return 0


def cmd_report(args):
    """Full audit + the ordered hardening plan, in one call — the one-shot
    readout for an operator or for the skill to relay. ELF gets the full plan;
    PE/Mach-O get the format's read-only audit + the server-side truth."""
    fmt = _detect_format(args.binary)
    if fmt == "mobile":
        mca = _mobile_audit()
        try:
            s = mca.analyze(args.binary)
        except mca.ContainerError as e:
            print(f"carapace error: {e}", file=sys.stderr)
            return 2
        print(mca.render(s))
        print()
        print(f"  Next: {mca.recommend(s)}")
        print()
        print(_SERVER_TRUTH)
        return 0
    if fmt in ("pe", "macho"):
        if fmt == "pe":
            print(pe_audit.render(pe_audit.analyze(args.binary)))
        else:
            m = _macho_audit()
            print(m.render(m.analyze(args.binary)))
        print()
        print(_nonelf_note(fmt))
        return 0
    if fmt != "elf":
        _unknown(args.binary)
    s = analyze(args.binary)
    print(render(s))
    print()
    _, recs = recommend(args.binary, want_all=True)
    print(f"Ordered hardening plan for {_rel(args.binary)} (highest value first):")
    print()
    for r in recs:
        print(_fmt_rec(r))
        print()
    print("  Honest footer: nothing here is unbreakable — anti-RE only raises the")
    print("  attacker's cost. The only Strong tier is moving the secret off the client.")
    return 0


def cmd_apply(args):
    fmt = _detect_format(args.binary)
    if fmt == "mobile":
        print(f"carapace: {_rel(args.binary)} is a mobile container — use "
              "`carapace harden` for containers.")
        print("  It dispatches the per-format native hardeners to each payload "
              "inside and repacks;")
        print("  then re-sign (apksigner/codesign). `carapace audit` gives the "
              "read-only posture.")
        return 3
    if fmt == "macho":
        # the one safe Mach-O post-build pass: strip LOCAL symbols (strip -x).
        out = args.out or (args.binary + ".stripped")
        r = subprocess.run(["python3", MACHO_STRIP, "--in", args.binary, "--out", out],
                           capture_output=True, text=True)
        sys.stdout.write(r.stdout)
        if r.returncode != 0:
            sys.stderr.write(r.stderr)
            return r.returncode
        print(f"  applied -> {_rel(out)}   (Mach-O local-symbol strip)")
        print("  re-audit with `carapace audit`; runtime-identical needs a macOS host to confirm.")
        return 0
    if fmt == "pe":
        # the one safe PE post-build pass: COFF-symbol + debug/PDB strip.
        out = args.out or (args.binary + ".stripped")
        r = subprocess.run(["python3", PE_STRIP, "--in", args.binary, "--out", out],
                           capture_output=True, text=True)
        sys.stdout.write(r.stdout)
        if r.returncode != 0:
            sys.stderr.write(r.stderr)
            return r.returncode
        print(f"  applied -> {_rel(out)}   (PE COFF-symbol + debug/PDB strip)")
        print("  re-audit with `carapace audit`; runtime-identical needs a Windows host to confirm.")
        return 0
    if fmt != "elf":
        print(f"carapace: apply targets ELF; {_rel(args.binary)} is {fmt.upper()}.")
        print("  The post-build transforms (identity/exhaust/honeytokens) are ELF-only today;")
        print("  run `carapace audit` for the read-only posture, and keep secrets server-side.")
        return 3
    s, recs = recommend(args.binary, want_all=False)
    top = recs[0]
    print(f"Top recommendation: {top['title']}  [{top['kind']}]")
    if top["kind"] != "post-build":
        print(f"  This is a {top['kind']} hardening — it cannot be patched into an already-built")
        print(f"  binary. Integration step: {top['command']}")
        print("  (Rebuild from source, then re-run `carapace recommend` to confirm.)")
        return 3
    # post-build: apply the identity transform
    out = args.out or (args.binary + ".release")
    mp = args.map or (args.binary + ".carapace-map.json")
    cmd = ["python3", TRANSFORM, "transform", "--mode", args.mode,
           "--in", args.binary, "--out", out, "--map", mp]
    if args.string_decoys:
        cmd += ["--string-decoys", args.string_decoys]
    r = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        return r.returncode
    print(f"  applied -> {_rel(out)}   (private map: {_rel(mp)})")
    print("  re-audit the result with `carapace recommend` to see the next step.")
    return 0


def _harden_pe(args, binary):
    """PE one-command harden: chain the post-build passes (COFF/debug strip →
    decoy-overlay exhaust → honeytokens), then honestly list the build-time levers
    that still need a relink/rebuild. Never fakes a build-time guard onto a built
    PE; mirrors the ELF harden, PE-flavoured. Structural — runtime-identical needs
    a Windows host (CLAUDE.md §3)."""
    import tempfile
    import shutil as _sh
    out = args.out or (binary + ".hardened")
    s = pe_audit.analyze(binary)

    tmpd = tempfile.mkdtemp(prefix="carapace_pe_harden_")
    cur = os.path.join(tmpd, "stage0")
    _sh.copy2(binary, cur)
    stage = 0

    def _next():
        nonlocal stage
        stage += 1
        return os.path.join(tmpd, f"stage{stage}")

    def _run_pass(cmd):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stderr or r.stdout)
            raise RuntimeError("hardening pass failed")
        return r.stdout

    applied = []
    try:
        if s["symbols_present"] or s["debug_info_present"]:
            nf = _next()
            _run_pass(["python3", PE_STRIP, "--in", cur, "--out", nf])
            cur = nf
            applied.append(("COFF-symbol + debug/PDB strip",
                            "Speed-bump→Meaningful",
                            "imports + exported names remain; behaviour recoverable",
                            "surgical in-place strip (size stable)"))

        if not pe_audit.analyze(cur)["decoy_overlay_present"]:
            nf = _next()
            _run_pass(["python3", PE_EXHAUST, cur, nf,
                       "--sections", "4", "--section-size", "131072"])
            cur = nf
            applied.append(("analysis-surface exhaustion (decoy non-mapped overlay)",
                            "Trivial→Speed-bump",
                            "map only section-covered bytes (the overlay is ignored)",
                            "decoy overlay regions (provably non-mapped)"))

        if not pe_audit.analyze(cur)["honeytokens_present"]:
            nf = _next()
            ledger = out + ".honey-ledger.json"
            _run_pass(["python3", PE_HONEY, "plant", cur, nf,
                       "--ledger", ledger, "--count", "10", "--build-tag", args.build_tag])
            cur = nf
            applied.append(("honeytokens / canaries (overlay)",
                            "Speed-bump (poison) / Meaningful for DETECTION",
                            "xref-validate drops unreferenced tokens; rename the tell-tale marker",
                            f"PRIVATE ledger → {_rel(ledger)}"))

        _sh.copy2(cur, out)
    except RuntimeError:
        _sh.rmtree(tmpd, ignore_errors=True)
        return 1
    finally:
        _sh.rmtree(tmpd, ignore_errors=True)

    print(f"Carapace harden (PE) — {_rel(binary)} → {_rel(out)}")
    print(f"  exposure score {s['score']}/100 → (re-audit {_rel(out)} to see the new posture)")
    print()
    print(f"  APPLIED (post-build, {len(applied)}):")
    for t, tier, byp, art in applied:
        print(f"    ✓ {t}")
        print(f"        tier   : {tier}")
        print(f"        bypass : {byp}")
        print(f"        artifact: {art}")
    if not applied:
        print("    (nothing post-build applied — already hardened, or no symbols/debug)")
    print()
    print("  NOT APPLIED — build-time, needs a relink/rebuild from source:")
    print("    • Link /DYNAMICBASE /NXCOMPAT /GUARD:CF /HIGHENTROPYVA  [raises exploitation effort;")
    print("        NOT a decompilation blocker]")
    print("    • Encrypt live strings + decode on demand (harness/harden/carapace_string_encrypt.py)")
    print("        [Speed-bump→Meaningful; bypass: runtime key recovery]")
    print("    • Authenticode-sign AND verify at runtime server-side  [Meaningful only WITH the")
    print("        server check — a signature on disk is read, not verified, by an RE agent]")
    print()
    print("  THE ONLY STRONG TIER: relocate secrets & trust decisions server-side (CLAUDE.md §3).")
    print()
    print("  Keep every PRIVATE ledger OUT of the shipped artifact — it is the key.")
    print("  Honest footer: nothing here is unbreakable — anti-RE only raises the attacker's cost.")
    print("  Post-build passes are COST/DETECTION; runtime-identical needs a Windows host to confirm.")
    return 0


def cmd_harden(args):
    """One command: audit, then apply EVERY applicable POST-BUILD hardening in a
    safe order, and honestly list the build-time ones that still need a rebuild.
    The UX-parity entry point (cf. a one-command `harden .`), but it never fakes a
    build-time guard onto an already-built binary."""
    import tempfile
    import shutil as _sh
    binary = args.binary
    fmt = _detect_format(binary)
    if fmt == "mobile":
        mob = _mobile_harden()
        try:
            res = mob.harden(binary, out=args.out, build_tag=args.build_tag)
        except (mob.MobileHardenError, mob.mca.ContainerError,
                FileNotFoundError) as e:
            print(f"carapace error: {e}", file=sys.stderr)
            return 2
        print(mob.render(res))
        return 0
    if fmt == "pe":
        return _harden_pe(args, binary)
    if fmt != "elf":
        print(f"carapace: harden targets ELF/PE; {_rel(binary)} is {fmt.upper()}.")
        print("  The post-build passes are ELF/PE today (Mach-O has apply = local-symbol strip);")
        print("  run `carapace audit` for the read-only posture, and keep secrets server-side.")
        return 3
    out = args.out or (binary + ".hardened")
    s = analyze(binary)

    tmpd = tempfile.mkdtemp(prefix="carapace_harden_")
    cur = os.path.join(tmpd, "stage0")
    _sh.copy2(binary, cur)
    stage = 0

    def _next():
        nonlocal stage
        stage += 1
        return os.path.join(tmpd, f"stage{stage}")

    def _run_pass(cmd):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stderr or r.stdout)
            raise RuntimeError("hardening pass failed")
        return r.stdout

    applied = []   # (title, tier, bypass, artifact-note)
    try:
        # order matters: identity FIRST (it renames/strips OWN symbols), THEN the
        # additive passes (exhaust / honeytokens) so they aren't touched by it.
        if s["symbols_present"] or s["debug_info_present"] or s["informativeness"]["symbol_total"] > 0:
            nf = _next()
            mp = out + ".carapace-map.json"
            _run_pass(["python3", TRANSFORM, "transform", "--mode", "D",
                       "--in", cur, "--out", nf, "--map", mp])
            cur = nf
            applied.append(("identity transform (decoy symbols)",
                            "Speed-bump→Meaningful",
                            "behavioural xref/value-flow ignores names",
                            f"PRIVATE map → {_rel(mp)}"))

        if not analyze(cur).get("exhaustion_present"):
            nf = _next()
            _run_pass(["python3", EXHAUST, cur, nf,
                       "--sections", "4", "--section-size", "131072", "--symbols", "300"])
            cur = nf
            applied.append(("analysis-surface exhaustion",
                            "Trivial→Speed-bump",
                            "filter to SHF_ALLOC sections + code-referenced symbols",
                            "decoy non-alloc sections + synthetic symbols"))

        if not analyze(cur).get("honeytokens_present"):
            nf = _next()
            ledger = out + ".honey-ledger.json"
            _run_pass(["python3", HONEY, "plant", cur, nf,
                       "--ledger", ledger, "--count", "10", "--build-tag", args.build_tag])
            cur = nf
            applied.append(("honeytokens / canaries",
                            "Speed-bump (poison) / Meaningful for DETECTION",
                            "xref-validate drops unreferenced tokens; rename the tell-tale section",
                            f"PRIVATE ledger → {_rel(ledger)}"))

        _sh.copy2(cur, out)
    except RuntimeError:
        _sh.rmtree(tmpd, ignore_errors=True)
        return 1
    finally:
        _sh.rmtree(tmpd, ignore_errors=True)

    # what we did NOT do: the build-time guards (rebuild needed) + the Strong truth.
    _, recs = recommend(out, want_all=True)
    deferred = [r for r in recs if r["kind"] == "build-time"]
    design = [r for r in recs if r["kind"] == "design"]

    print(f"Carapace harden — {_rel(binary)} → {_rel(out)}")
    print(f"  exposure score {s['score']}/100 → (re-audit {_rel(out)} to see the new posture)")
    print()
    print(f"  APPLIED (post-build, {len(applied)}):")
    for t, tier, byp, art in applied:
        print(f"    ✓ {t}")
        print(f"        tier   : {tier}")
        print(f"        bypass : {byp}")
        print(f"        artifact: {art}")
    if not applied:
        print("    (nothing post-build applied — already hardened, or no symbols)")
    print()
    print(f"  NOT APPLIED — build-time, needs a rebuild from source ({len(deferred)}):")
    for r in deferred:
        print(f"    • {r['title']}  [{r['tier']}]")
        print(f"        how: {r['command']}")
    print()
    if design:
        d = design[0]
        print(f"  THE ONLY STRONG TIER: {d['title']}")
        print(f"        {d['tier']}")
    print()
    print("  Keep every PRIVATE map/ledger OUT of the shipped artifact — they are the keys.")
    print("  Honest footer: nothing here is unbreakable — anti-RE only raises the attacker's")
    print("  cost. Post-build passes are COST/DETECTION; the build-time guards and the")
    print("  server-side relocation above are where real strength lives.")
    return 0


def cmd_install(args):
    """Install the skill by symlinking skill/ into a .claude/skills/carapace dir —
    the one-command 'make it available to Claude' step (install parity)."""
    skill_dir = os.path.join(REPO, "skill")
    base = args.dir or os.path.join(os.path.expanduser("~") if args.user else os.getcwd(),
                                     ".claude", "skills")
    target = os.path.join(base, "carapace")
    os.makedirs(base, exist_ok=True)
    if os.path.islink(target):
        os.unlink(target)
    elif os.path.exists(target):
        print(f"carapace error: {target} exists and is not a symlink — remove it first",
              file=sys.stderr)
        return 2
    os.symlink(skill_dir, target)
    print(f"carapace skill installed: {target} -> {skill_dir}")
    print("  Claude Code will discover it as the 'carapace' skill. Verify with: "
          "ls -l " + target)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="carapace",
        description="Drive the Carapace harness: audit a build, recommend and apply hardening.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="print the full exposure report")
    a.add_argument("binary")
    a.set_defaults(fn=cmd_audit)

    rp = sub.add_parser("report", help="full audit + the ordered hardening plan, in one call")
    rp.add_argument("binary")
    rp.set_defaults(fn=cmd_report)

    r = sub.add_parser("recommend", help="the next highest-value hardening (honest tier + bypass)")
    r.add_argument("binary")
    r.add_argument("--all", action="store_true", help="list the full ordered plan")
    r.add_argument("--json", action="store_true")
    r.set_defaults(fn=cmd_recommend)

    p = sub.add_parser("apply", help="apply the top recommendation if it is post-build-safe")
    p.add_argument("binary")
    p.add_argument("--mode", choices=["S", "M", "D"], default="D")
    p.add_argument("--out")
    p.add_argument("--map")
    p.add_argument("--string-decoys")
    p.set_defaults(fn=cmd_apply)

    h = sub.add_parser("harden", help="one command: apply every applicable post-build hardening")
    h.add_argument("binary")
    h.add_argument("--out", help="output path (default <binary>.hardened)")
    h.add_argument("--build-tag", default="dev-build", help="build id recorded in the honeytoken ledger")
    h.set_defaults(fn=cmd_harden)

    i = sub.add_parser("install", help="symlink the skill into .claude/skills/carapace")
    i.add_argument("--user", action="store_true", help="install into ~/.claude/skills instead of ./")
    i.add_argument("--dir", help="explicit .claude/skills base dir (overrides --user)")
    i.set_defaults(fn=cmd_install)

    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except (FileNotFoundError, IsADirectoryError, ValueError, pe_audit.PEError) as e:
        print(f"carapace error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

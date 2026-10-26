#!/usr/bin/env python3
# Carapace — dev<->release IDENTITY TRANSFORM (Slice B).
#
# WHAT THIS IS
#   A build-time transform that keeps ONE clean dev source/binary and emits a
#   SHIPPED binary whose human-readable identity is degraded, plus a PRIVATE
#   mapping file (the "key") kept out of the shipped artifact. It targets the AI
#   layer directly: LLM agents form hypotheses primarily from names and strings
#   (docs/re-techniques/rea.md, "Dev<->release identity transform").
#
#   It operates on the COMPILED ELF (the artifact the attacker actually gets),
#   using binutils (objcopy/strip) for symbols and a same-length .rodata patch
#   for opt-in internal strings. The dev tree is never touched.
#
# THREE MODES (operator picks per build):
#   S (strip)  : remove .symtab + debug info entirely. For identity you never
#                need to recover. Unrecoverable by design — mapping is an audit
#                record only.
#   M (map)    : rename own symbols to opaque tokens (cp_000001...). Keep a
#                private mapping to recover real names for crash triage (the
#                R8 mapping.txt / iOS dSYM pattern). Reversible.
#   D (decoy)  : rename own symbols to plausible-but-WRONG names from a decoy
#                dictionary. Maximum AI-agent misdirection. Reversible via map.
#
# HONESTY (CLAUDE.md §3): this is COST, not prevention.
#   Tier: Speed-bump->Meaningful (Meaningful vs lazy/one-shot agents & junior
#   analysts; Speed-bump vs a thorough agent that verifies names against behavior
#   via xrefs/value-flow). Named bypass: behavioral cross-check ignores names;
#   rea's unknowns/coverage ledger surfaces contradictions a decoy introduces.
#   Scope is INTERNAL symbols only (own FUNC/OBJECT) — we never rename libc
#   imports or anything whose true name the shipped artifact must keep.
#
# NOT DONE HERE (stated, not silently skipped): encryption of *live* strings
#   needs a runtime decode loader and is a separate hardening. This tool only
#   does opt-in, same-length decoys of strings the operator declares internal
#   (non-output); the verify step guards behavior so a mis-scoped string fails
#   loudly rather than silently corrupting output.

import os
import sys
import json
import shutil
import argparse
import subprocess
from datetime import datetime, timezone

# Reuse the audit's ELF parser + own-symbol selection so audit and transform
# agree on exactly which symbols count as "app identity."
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "audit"))
from elf_exposure_audit import ELF, own_symbols  # noqa: E402


def _run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed: {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout


def load_decoys(path):
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def build_symbol_map(names, mode, decoy_path):
    """Return {old_name: new_name} for the rename, deterministic on sorted names."""
    names = sorted(names)
    mapping = {}
    if mode == "M":
        for i, n in enumerate(names, 1):
            mapping[n] = f"cp_{i:06d}"
    elif mode == "D":
        decoys = load_decoys(decoy_path)
        if len(decoys) < len(names):
            raise RuntimeError(f"decoy dictionary too small: need {len(names)}, have {len(decoys)}")
        for n, d in zip(names, decoys):
            mapping[n] = d
    return mapping  # S returns {} (nothing renamed; everything stripped)


def patch_strings(elf_path, pairs):
    """Apply same-length decoy swaps inside .rodata. pairs: list of (old, new).
    Refuses unequal lengths or a target not found uniquely in .rodata."""
    if not pairs:
        return {}
    elf = ELF(elf_path)
    ro = elf.sections.get(".rodata")
    if not ro:
        raise RuntimeError("no .rodata to patch strings in")
    ro_off, ro_size = ro["offset"], ro["size"]
    data = bytearray(open(elf_path, "rb").read())
    window = bytes(data[ro_off:ro_off + ro_size])
    applied = {}
    for old, new in pairs:
        ob, nb = old.encode(), new.encode()
        if len(ob) != len(nb):
            raise RuntimeError(f"string decoy must be same length: '{old}' ({len(ob)}) != '{new}' ({len(nb)})")
        first = window.find(ob)
        if first < 0:
            raise RuntimeError(f"internal string not found in .rodata: '{old}'")
        if window.find(ob, first + 1) >= 0:
            raise RuntimeError(f"internal string is ambiguous (appears >1x) in .rodata: '{old}'")
        data[ro_off + first: ro_off + first + len(ob)] = nb
        applied[new] = old
    with open(elf_path, "wb") as fh:
        fh.write(data)
    return applied


def transform(dev, out, mode, map_path, decoy_path, string_pairs):
    names = own_symbols(ELF(dev))
    if not names and mode != "S":
        raise RuntimeError("no own symbols to rename (already stripped?) — use mode S")

    sym_map = build_symbol_map(names, mode, decoy_path)

    # Always drop DWARF debug info on the shipped artifact (dev names live there
    # too, and objcopy --redefine-sym does NOT touch DWARF).
    objcopy_cmd = ["objcopy", "--strip-debug"]

    redefine_file = None
    if mode in ("M", "D"):
        redefine_file = out + ".redefine.tmp"
        with open(redefine_file, "w") as fh:
            for old, new in sym_map.items():
                fh.write(f"{old} {new}\n")
        objcopy_cmd += [f"--redefine-syms={redefine_file}"]

    objcopy_cmd += [dev, out]
    _run(objcopy_cmd)
    if redefine_file:
        os.remove(redefine_file)

    if mode == "S":
        _run(["strip", "--strip-all", out])  # remove .symtab entirely

    str_map = patch_strings(out, string_pairs)

    mapping = {
        "mode": mode,
        "created": datetime.now(timezone.utc).isoformat(),
        "source": os.path.basename(dev),
        "artifact": os.path.basename(out),
        # new -> old, so a release name seen in a crash resolves to the dev name
        "symbols": {new: old for old, new in sym_map.items()},
        "strings": str_map,
        "note": ("PRIVATE KEY — keep OUT of the shipped artifact. Mode S removed "
                 "symbols entirely; 'symbols' records what was removed, not a "
                 "recoverable map." if mode == "S" else
                 "PRIVATE KEY — keep OUT of the shipped artifact. Resolve a "
                 "release name to its dev original for crash triage."),
    }
    with open(map_path, "w") as fh:
        json.dump(mapping, fh, indent=2)
    return mapping


def resolve(map_path, name):
    m = json.load(open(map_path))
    if name in m.get("symbols", {}):
        return m["symbols"][name]
    if name in m.get("strings", {}):
        return m["strings"][name]
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="Carapace dev<->release identity transform.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("transform", help="produce a release binary + private mapping")
    t.add_argument("--mode", choices=["S", "M", "D"], required=True)
    t.add_argument("--in", dest="dev", required=True, help="dev ELF (clean, with symbols)")
    t.add_argument("--out", required=True, help="release ELF to write")
    t.add_argument("--map", required=True, help="private mapping JSON to write")
    t.add_argument("--decoy-dict", default=os.path.join(os.path.dirname(__file__), "decoy_dictionary.txt"))
    t.add_argument("--string-decoys", help="JSON list of [old,new] same-length internal-string swaps")

    r = sub.add_parser("resolve", help="recover a dev name from a release name")
    r.add_argument("--map", required=True)
    r.add_argument("name")

    args = ap.parse_args(argv)

    if args.cmd == "transform":
        pairs = []
        if args.string_decoys:
            pairs = [tuple(p) for p in json.load(open(args.string_decoys))]
        try:
            m = transform(args.dev, args.out, args.mode, args.map, args.decoy_dict, pairs)
        except (RuntimeError, FileNotFoundError) as e:
            print(f"transform error: {e}", file=sys.stderr)
            return 2
        print(f"mode {m['mode']}: renamed {len(m['symbols'])} symbols, "
              f"{len(m['strings'])} strings -> {args.out}  (map: {args.map})")
        return 0

    if args.cmd == "resolve":
        orig = resolve(args.map, args.name)
        if orig is None:
            print(f"(no mapping for '{args.name}')", file=sys.stderr)
            return 1
        print(orig)
        return 0


if __name__ == "__main__":
    sys.exit(main())

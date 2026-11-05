#!/usr/bin/env python3
# Carapace — analysis-surface EXHAUSTION (Slice I).
#
# WHAT THIS IS
#   A build-time pass over the COMPILED ELF that inflates the volume of material
#   an AI-RE agent must ingest and reason over, WITHOUT changing what the program
#   does. It absorbs the "Exhaust" axis of the commodity AI-RE defender space
#   (peers push artifacts past an agent's documented inventory / context budgets)
#   into Carapace's native lane — and, unlike a size-diff "verify", we prove the
#   runtime is byte-identical and the dynamic surface is untouched
#   (harness/verify/test_slice_i.sh).
#
# TWO NON-BREAKING LEVERS (binutils only; both verified in-repo):
#   1. Decoy NON-ALLOCATED sections (.carapace_exh_<i>): SHT_PROGBITS with the
#      SHF_ALLOC flag CLEAR. The loader never maps a non-alloc section, so there
#      is zero runtime cost and zero behaviour change — but a static tool or agent
#      that inventories and dumps every section must read all of it.
#   2. Synthetic LOCAL FUNC symbols (carapace_exh_fn_<i>) added to .symtab only
#      (never .dynsym). They inflate the function inventory an agent enumerates
#      and budgets per-symbol analysis against. LOCAL + symtab-only => dynamic
#      linking and exports are unaffected.
#
# WHY IT BITES THE P0 TARGET
#   The headline threat is the NAIVE, automated "point an agent at it and ingest
#   everything" workflow. That path pays the full token/context cost of the
#   inflated surface. A skilled analyst does not — see the bypass.
#
# HONESTY (CLAUDE.md §3): this is COST, not prevention.
#   Tier: Trivial->Speed-bump. Speed-bump against a naive ingest-everything agent
#   (burns its context/token budget, can truncate its inventory); Trivial against
#   anyone who filters. NAMED BYPASS: restrict analysis to allocated/executable
#   sections (SHF_ALLOC) and to symbols that are referenced by code — our decoy
#   sections are never mapped and our synthetic symbols are never called, so a
#   one-line filter drops them. We never claim it blocks analysis; it taxes the
#   lazy automated path, which is exactly the commodity-cracking path.
#
#   Deterministic output (seeded) so builds are reproducible and the verify can
#   assert byte-identical *runtime* behaviour against a clean baseline.

import os
import sys
import shutil
import random
import argparse
import tempfile
import subprocess

# Reuse the audit's ELF parser so we read .text geometry exactly as the audit does.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "audit"))
from elf_exposure_audit import ELF  # noqa: E402

SEC_PREFIX = ".carapace_exh_"
SYM_PREFIX = "carapace_exh_fn_"


def _run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed: {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout


def _det_bytes(seed, n):
    """Deterministic incompressible bytes (reproducible builds)."""
    rnd = random.Random(seed)
    try:
        return rnd.randbytes(n)                       # Python 3.9+
    except AttributeError:                            # fallback
        return bytes(rnd.getrandbits(8) for _ in range(n))


def exhaust(src, dst, n_sections, section_size, n_symbols, objcopy="objcopy"):
    shutil.copy2(src, dst)      # copy2 preserves mode (keep the +x bit)

    # --- lever 1: decoy non-alloc sections, all in one objcopy call ----------
    tmpdir = tempfile.mkdtemp(prefix="carapace_exh_")
    added_sections = 0
    decoy_bytes = 0
    try:
        if n_sections > 0 and section_size > 0:
            cmd = [objcopy]
            for i in range(n_sections):
                name = f"{SEC_PREFIX}{i}"
                blobpath = os.path.join(tmpdir, f"{i}.bin")
                blob = _det_bytes(0xC0FFEE + i, section_size)
                with open(blobpath, "wb") as f:
                    f.write(blob)
                cmd += [f"--add-section", f"{name}={blobpath}",
                        f"--set-section-flags", f"{name}=noload,readonly"]
                added_sections += 1
                decoy_bytes += section_size
            cmd += [dst, dst]
            _run(cmd)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # --- lever 2: synthetic LOCAL FUNC symbols into .symtab ------------------
    added_symbols = 0
    if n_symbols > 0:
        elf = ELF(dst)
        text = elf.sections.get(".text")
        if not text or text["size"] == 0:
            raise RuntimeError("no .text section to anchor synthetic symbols to")
        text_size = text["size"]
        cmd = [objcopy]
        for i in range(n_symbols):
            # spread valid offsets across .text; LOCAL + function type.
            off = (i * 16) % max(1, text_size)
            cmd += ["--add-symbol", f"{SYM_PREFIX}{i}=.text:0x{off:x},local,function"]
            added_symbols += 1
        cmd += [dst, dst]
        _run(cmd)

    return {
        "sections": added_sections,
        "decoy_bytes": decoy_bytes,
        "symbols": added_symbols,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Carapace analysis-surface exhaustion (non-breaking; COST not prevention).")
    ap.add_argument("src", help="input ELF (the clean compiled binary)")
    ap.add_argument("dst", help="output ELF (the exhausted, shippable binary)")
    ap.add_argument("--sections", type=int, default=4,
                    help="number of decoy non-alloc sections (default 4)")
    ap.add_argument("--section-size", type=int, default=131072,
                    help="bytes per decoy section (default 131072 = 128 KiB)")
    ap.add_argument("--symbols", type=int, default=300,
                    help="number of synthetic LOCAL FUNC symbols (default 300)")
    ap.add_argument("--objcopy", default="objcopy", help="objcopy binary to use")
    args = ap.parse_args(argv)

    if not os.path.exists(args.src):
        ap.error(f"input not found: {args.src}")
    info = exhaust(args.src, args.dst, args.sections, args.section_size,
                   args.symbols, args.objcopy)
    print(f"[carapace-exhaust] {args.src} -> {args.dst}")
    print(f"  decoy sections ..... {info['sections']}  "
          f"({info['decoy_bytes']} bytes, non-alloc: never mapped at runtime)")
    print(f"  synthetic symbols .. {info['symbols']}  (LOCAL FUNC, .symtab only)")
    print("  tier: Trivial->Speed-bump. bypass: filter to SHF_ALLOC sections + "
          "code-referenced symbols. COST, not prevention (CLAUDE.md §3).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

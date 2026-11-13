#!/usr/bin/env python3
# Carapace — Mach-O analysis-surface EXHAUSTION (Slice Q): decoy NON-MAPPED segment.
#
# WHAT THIS IS
#   The Mach-O analog of the ELF exhaust pass (Slice I) and the PE decoy overlay
#   (Slice P). It inflates the volume of material an AI-RE agent must ingest and reason
#   over WITHOUT changing the loaded program, two ways:
#     (1) bulk deterministic decoy bytes appended to the file TRAILER — past every
#         segment/section/table the file declares, so the loader maps none of them,
#         yet a whole-file strings/entropy/"dump every range" sweep still reads them
#         (the Mach-O analog of the PE overlay); and
#     (2) a real, added LC_SEGMENT_64 named __CARAPACE_EXH with vmsize = 0
#         (initprot = maxprot = 0, nsects = 0) — a genuine load command that dyld
#         IGNORES (a vmsize==0 segment reserves no address space → maps nothing), so a
#         load-command / segment dump (otool -l-style, which the agent reads to build
#         its map) now carries an extra, inert entry. It is spliced into the header pad
#         IN PLACE (nothing else moves). When the pad is too small we keep lever (1)
#         and skip (2), reporting it with the -headerpad_max_install_names remedy —
#         never a silent skip, never a corrupted file.
#
# PROOF (harness/verify/test_slice_q.sh), with NO macOS host:
#   - surgical splice: the ONLY changed in-file bytes are the mach-header ncmds /
#     sizeofcmds fields and the zero header-pad we overwrote with the 72-byte LC;
#   - the added segment has vmsize == 0 (maps nothing);
#   - the decoy trailer sits at the original EOF, >= mapped_end (non-mapped), append-only.
#
# HONESTY (CLAUDE.md §3): this is COST, not prevention.
#   Tier: Trivial->Speed-bump. Speed-bump against a naive ingest-everything agent (burns
#   its context/token budget, can truncate its inventory); Trivial against anyone who
#   filters. NAMED BYPASS: a loader-faithful tool reads only mapped segments and drops
#   vmsize==0 load commands + the trailer (a one-line filter). Deterministic (seeded).
#   Splicing/appending invalidates a code signature (we WARN; strip->sign order).
#   Runtime-identical + real-dyld acceptance of the decoy LC are platform-gated to a
#   macOS host; here the structure is proven, not a run.

import os
import sys
import random
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from carapace_macho_segment import (append_trailer, add_decoy_segment, SegError)  # noqa: E402

MARKER = b"__CARAPACE_MACHO_EXH_"
DECOY_SEGNAME = "__CARAPACE_EXH"


def _det_bytes(seed, n):
    rnd = random.Random(seed)
    try:
        return rnd.randbytes(n)
    except AttributeError:
        return bytes(rnd.getrandbits(8) for _ in range(n))


def exhaust(src, dst, n_regions, region_size, seed=0xC0FFEE):
    with open(src, "rb") as f:
        data = f.read()

    blob = bytearray()
    for i in range(n_regions):
        blob += b"\n" + MARKER + str(i).encode() + b"__\n"
        blob += _det_bytes(seed + i, region_size)

    out, tinfo = append_trailer(data, bytes(blob))      # raises SegError on a non/ fat/32-bit Mach-O
    out, sinfo = add_decoy_segment(out, DECOY_SEGNAME)

    info = dict(tinfo)
    info.update({
        "decoy_regions": n_regions,
        "decoy_bytes": len(blob),
        "load_command_added": sinfo["load_command_added"],
        "decoy_segname": DECOY_SEGNAME,
        "segment_vmsize": sinfo["vmsize"],
        "slack": sinfo["slack"],
        "lc_reason": sinfo.get("reason"),
    })
    with open(dst, "wb") as f:
        f.write(out)
    if src != dst:
        import shutil
        shutil.copymode(src, dst)
    return info


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Carapace Mach-O analysis-surface exhaustion (decoy NON-MAPPED segment + "
                    "trailer; COST not prevention).")
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--regions", type=int, default=4, help="number of decoy trailer regions (default 4)")
    ap.add_argument("--region-size", type=int, default=131072,
                    help="bytes per decoy region (default 131072 = 128 KiB)")
    ap.add_argument("--seed", type=lambda x: int(x, 0), default=0xC0FFEE)
    a = ap.parse_args(argv)
    if not os.path.exists(a.src):
        ap.error(f"input not found: {a.src}")
    try:
        info = exhaust(a.src, a.dst, a.regions, a.region_size, a.seed)
    except (SegError, IsADirectoryError) as e:
        print(f"carapace-macho-exhaust error: {e}", file=sys.stderr)
        return 2
    print(f"[carapace-macho-exhaust] {a.src} -> {a.dst}")
    print(f"  decoy trailer ...... {info['decoy_regions']} regions ({info['decoy_bytes']} bytes) "
          f"at offset {info['trailer_off']}")
    print(f"  non-mapped proof ... trailer at {info['trailer_off']} >= mapped_end "
          f"{info['mapped_end']} -> {info['non_mapped']}")
    if info["load_command_added"]:
        print(f"  decoy segment ...... added LC_SEGMENT_64 {info['decoy_segname']} with "
              f"vmsize={info['segment_vmsize']} (dyld ignores it -> maps nothing); spliced in place")
    else:
        print(f"  decoy segment ...... NOT added ({info['lc_reason']})")
        print("                       trailer decoy still applied; relink as above for the added LC")
    if info["code_signed"]:
        print("  WARNING: input carries a code signature — appending/splicing invalidates it. "
              "Re-sign on the build host (strip/harden -> codesign).")
    print("  tier: Trivial→Speed-bump. bypass: a loader-faithful tool reads only mapped segments "
          "and drops vmsize==0 LCs + the trailer. COST, not prevention (CLAUDE.md §3).")
    print("  NOTE: runtime-identical + real-dyld acceptance need a macOS host to confirm; "
          "not run here (structural proof only).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

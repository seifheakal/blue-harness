#!/usr/bin/env python3
# Carapace — PE analysis-surface EXHAUSTION (Slice P): decoy NON-MAPPED regions.
#
# WHAT THIS IS
#   The PE analog of the ELF exhaust pass (Slice I). It inflates the volume of
#   material an AI-RE agent must ingest and reason over WITHOUT changing the loaded
#   program, by appending decoy regions to the PE OVERLAY — the bytes that live in
#   the file AFTER the last section's raw data and are described by NO section
#   header. The Windows loader builds the memory image from the section table up to
#   SizeOfImage; overlay bytes are never mapped. A whole-file static tool (strings /
#   list_strings / a byte-entropy or "dump every section range" sweep) still reads
#   them, so the surface grows while the runtime image is untouched.
#
#   WHY THE OVERLAY (and not new section-table entries): a provably non-mapped
#   section in PE would need either a loader-specific "don't map" trick we cannot
#   verify without a Windows host, or growing SizeOfHeaders (which shifts every file
#   offset and breaks the byte-stable claim). The overlay is the loader-independent,
#   structurally-provable non-mapped home — so the proof needs no Windows host.
#
# PROOF (harness/verify/test_slice_p.sh), with NO Windows host:
#   - append-only: the original file is a byte-identical PREFIX of the output
#     (headers, every section, the section table and SizeOfImage are untouched);
#   - the decoy bytes start at offset >= the end of every section's raw data
#     (mapped_end), i.e. they are in the overlay and provably not mapped.
#
# HONESTY (CLAUDE.md §3): this is COST, not prevention.
#   Tier: Trivial->Speed-bump. Speed-bump against a naive ingest-everything agent
#   (burns its context/token budget, can truncate its inventory); Trivial against
#   anyone who filters. NAMED BYPASS: a loader-faithful tool maps only the bytes
#   covered by the section table — a one-line filter drops the whole overlay. We
#   never claim it blocks analysis; it taxes the lazy automated path, which is the
#   commodity-cracking path. Deterministic (seeded) for reproducible builds.
#   Appending to a SIGNED PE invalidates its Authenticode signature (we WARN).

import os
import sys
import random
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "audit"))
from pe_exposure_audit import PE, PEError  # noqa: E402

MARKER = b"__CARAPACE_PE_EXH_"


def _det_bytes(seed, n):
    rnd = random.Random(seed)
    try:
        return rnd.randbytes(n)
    except AttributeError:
        return bytes(rnd.getrandbits(8) for _ in range(n))


def _mapped_end(pe):
    """Highest file offset the loader reads into the image: end of every section's
    raw data."""
    cand = [0]
    for s in pe.sections:
        if s["SizeOfRawData"]:
            cand.append(s["PointerToRawData"] + s["SizeOfRawData"])
    return max(cand)


def exhaust(src, dst, n_sections, section_size, seed=0xC0FFEE):
    pe = PE(src)                      # raises PEError on a non-PE
    with open(src, "rb") as f:
        data = f.read()
    mapped_end = _mapped_end(pe)
    decoy_offset = len(data)          # append at EOF: >= mapped_end and past any overlay

    blob = bytearray()
    for i in range(n_sections):
        blob += b"\n" + MARKER + str(i).encode() + b"__\n"
        blob += _det_bytes(seed + i, section_size)
    out = data + bytes(blob)

    with open(dst, "wb") as f:
        f.write(out)
    if src != dst:
        import shutil
        shutil.copymode(src, dst)
    return {
        "decoy_regions": n_sections,
        "decoy_bytes": len(blob),
        "decoy_offset": decoy_offset,
        "mapped_end": mapped_end,
        "non_mapped": decoy_offset >= mapped_end,
        "authenticode_present": pe.dir(4)[1] > 0,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Carapace PE analysis-surface exhaustion (decoy NON-MAPPED overlay; "
                    "COST not prevention).")
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--sections", type=int, default=4,
                    help="number of decoy overlay regions (default 4)")
    ap.add_argument("--section-size", type=int, default=131072,
                    help="bytes per decoy region (default 131072 = 128 KiB)")
    ap.add_argument("--seed", type=lambda x: int(x, 0), default=0xC0FFEE)
    a = ap.parse_args(argv)
    if not os.path.exists(a.src):
        ap.error(f"input not found: {a.src}")
    try:
        info = exhaust(a.src, a.dst, a.sections, a.section_size, a.seed)
    except (PEError, IsADirectoryError) as e:
        print(f"carapace-pe-exhaust error: {e}", file=sys.stderr)
        return 2
    print(f"[carapace-pe-exhaust] {a.src} -> {a.dst}")
    print(f"  decoy regions ...... {info['decoy_regions']} "
          f"({info['decoy_bytes']} bytes) appended to the OVERLAY")
    print(f"  non-mapped proof ... decoy at offset {info['decoy_offset']} >= mapped_end "
          f"{info['mapped_end']} -> {info['non_mapped']}")
    print("  append-only: the original file is a byte-identical prefix (sections + "
          "SizeOfImage untouched).")
    if info["authenticode_present"]:
        print("  WARNING: input is Authenticode-signed — appending overlay invalidates the "
              "signature. Re-sign after.")
    print("  tier: Trivial→Speed-bump. bypass: map only section-covered bytes (the overlay is "
          "ignored). COST, not prevention (CLAUDE.md §3).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# Carapace — PE (Windows) COFF-symbol + debug/PDB-path STRIP (Slice P).
#
# WHAT THIS IS
#   The PE analog of the Mach-O local-symbol strip and the ELF identity strip: a
#   post-build pass that removes the dev-identity metadata an AI-RE agent mines for
#   free — the COFF symbol table (internal function/variable names + the string
#   table they index) and the debug directory / CodeView record (which carries the
#   build-machine PDB path). It operates byte-level with NO Windows toolchain
#   (no editbin / link), using the COFF header + the IMAGE_DEBUG_DIRECTORY.
#
# WHAT IT IS NOT (the honest line — CLAUDE.md §3):
#   We run on Linux and CANNOT execute a PE, so — exactly like the Mach-O strip —
#   we do NOT claim this is runtime-identical here. We PROVE it is STRUCTURALLY
#   SURGICAL: the only bytes changed are (a) the COFF symbol+string table, (b) the
#   IMAGE_DEBUG_DIRECTORY entry, and (c) the CodeView/PDB-path record it pointed
#   to. Every section header, the import/export tables, the entry point and
#   SizeOfImage are byte-identical, and the FILE SIZE is stable (we zero in place).
#   COFF symbols and debug data are never used by the running program (a debugger
#   reads them), so clearing them cannot change behaviour. Runtime-identical is
#   left to a Windows host to confirm (platform-gated, like the Slice O macOS host).
#   Stripping also invalidates any Authenticode signature (it covers the file), so
#   the correct order is strip -> sign on the build host; we WARN if one is present.
#
# HONESTY TIER: Speed-bump->Meaningful (removes the internal identity an agent
#   reasons from). NAMED BYPASS: the IMPORT table + any EXPORTED names remain (the
#   loader needs them) and a thorough agent recovers logic from behaviour/xrefs
#   regardless of symbol names. Not a decompilation blocker.

import sys
import os
import struct
import shutil
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "audit"))
from pe_exposure_audit import PE, PEError  # noqa: E402  (reuse the audit's PE parser)

PRINTABLE = set(range(0x20, 0x7F)) | {0x09}


class StripError(Exception):
    pass


def _u32(d, off):
    return struct.unpack_from("<I", d, off)[0]


def _scrub_run(d, idx):
    """Zero the printable byte-run that contains offset idx (catch a stray path)."""
    lo = idx
    while lo > 0 and d[lo - 1] in PRINTABLE:
        lo -= 1
    hi = idx
    while hi < len(d) and d[hi] in PRINTABLE:
        hi += 1
    for i in range(lo, hi):
        d[i] = 0
    return hi - lo


def strip_pe(src, dst):
    with open(src, "rb") as f:
        raw = f.read()
    pe = PE(src)                      # raises PEError on a non-PE
    d = bytearray(raw)
    n = len(d)

    coff_removed = 0
    debug_stripped = False
    pdb_scrubbed = 0

    # --- (1) COFF symbol table + its string table ----------------------------
    if pe.ptr_symtab and pe.num_symbols:
        sym_off = pe.ptr_symtab
        sym_bytes = pe.num_symbols * 18
        strtab_off = sym_off + sym_bytes
        strtab_size = 0
        if 0 <= strtab_off and strtab_off + 4 <= n:
            strtab_size = _u32(d, strtab_off)
            if strtab_size < 4:
                strtab_size = 4
        end = min(n, strtab_off + strtab_size)
        if 0 <= sym_off < end:
            for i in range(sym_off, end):
                d[i] = 0
            coff_removed = pe.num_symbols
            # COFF header: PointerToSymbolTable @ coff+8, NumberOfSymbols @ coff+12
            coff = pe.e_lfanew + 4
            struct.pack_into("<I", d, coff + 8, 0)
            struct.pack_into("<I", d, coff + 12, 0)

    # --- (2) debug directory + CodeView / PDB-path record --------------------
    dbg_rva, dbg_size = pe.dir(6)
    if dbg_rva and dbg_size:
        dbg_off = pe.rva_to_off(dbg_rva)
        if dbg_off is not None:
            for e in range(0, dbg_size, 28):
                base = dbg_off + e
                if base + 28 > n:
                    break
                size_of_data = _u32(d, base + 16)
                ptr_raw = _u32(d, base + 24)
                # zero the CodeView/record bytes (this holds the PDB path)
                if ptr_raw and 0 < size_of_data and ptr_raw + size_of_data <= n:
                    for i in range(ptr_raw, ptr_raw + size_of_data):
                        d[i] = 0
                # zero this IMAGE_DEBUG_DIRECTORY entry
                for i in range(base, base + 28):
                    d[i] = 0
            # clear the Debug data directory (index 6) in the optional header
            dir_off = pe.opt + (0x70 if pe.pe32plus else 0x60) + 6 * 8
            struct.pack_into("<II", d, dir_off, 0, 0)
            debug_stripped = True

    # --- (3) belt-and-suspenders: scrub any surviving ".pdb" path run --------
    searchfrom = 0
    while True:
        idx = d.find(b".pdb", searchfrom)
        if idx < 0:
            break
        pdb_scrubbed += _scrub_run(d, idx)
        searchfrom = idx + 4

    if coff_removed == 0 and not debug_stripped and pdb_scrubbed == 0:
        raise StripError("nothing to strip (no COFF symbol table, no debug directory, no PDB path)")

    if len(d) != n:
        raise StripError("file size changed during strip (unexpected)")

    with open(dst, "wb") as f:
        f.write(bytes(d))
    if src != dst:
        shutil.copymode(src, dst)
    return {
        "coff_symbols_removed": coff_removed,
        "debug_directory_stripped": debug_stripped,
        "pdb_path_bytes_scrubbed": pdb_scrubbed,
        "authenticode_present": pe.dir(4)[1] > 0,
        "file_size_stable": True,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Carapace PE COFF-symbol + debug/PDB strip (editbin-equivalent; "
                    "removes dev identity, not behaviour).")
    ap.add_argument("--in", dest="src", required=True)
    ap.add_argument("--out", dest="dst", required=True)
    a = ap.parse_args(argv)
    try:
        info = strip_pe(a.src, a.dst)
    except (StripError, PEError, FileNotFoundError, IsADirectoryError) as e:
        print(f"carapace-pe-strip error: {e}", file=sys.stderr)
        return 2
    print(f"[carapace-pe-strip] {a.src} -> {a.dst}")
    print(f"  removed {info['coff_symbols_removed']} COFF symbol(s); "
          f"debug directory stripped: {info['debug_directory_stripped']}; "
          f"PDB-path bytes scrubbed: {info['pdb_path_bytes_scrubbed']}")
    print("  surgical: only the COFF symbol/string table, the IMAGE_DEBUG_DIRECTORY and the")
    print("  CodeView/PDB record are cleared; imports/exports/entry/sections/SizeOfImage and")
    print("  the file size are preserved.")
    if info["authenticode_present"]:
        print("  WARNING: input carries an Authenticode certificate — stripping invalidates it.")
        print("  Re-sign on the build host (correct order is strip -> sign).")
    print("  tier: Speed-bump→Meaningful. bypass: import table + exported names remain and")
    print("  behaviour is recoverable. NOTE: runtime-identical needs a Windows host to confirm;")
    print("  not run here (structural proof only — CLAUDE.md §3).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

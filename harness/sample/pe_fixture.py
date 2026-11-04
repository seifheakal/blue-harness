#!/usr/bin/env python3
# Carapace — minimal PE32+ fixture generator (Slice G verify helper).
#
# No mingw / pefile in the dev container, so the verify builds its own PE test
# inputs here: a structurally valid PE32+ (x86-64) with configurable
# DllCharacteristics, a real import table, plaintext strings, an optional PDB/
# debug directory, an Authenticode certificate table, a .NET directory, and
# packer-style section names. Enough to exercise every path the PE scanner reads
# — these are inputs for a READ-ONLY audit, not loadable executables.

import os
import struct
import argparse

DC_HIGH_ENTROPY_VA = 0x0020
DC_DYNAMIC_BASE    = 0x0040
DC_NX_COMPAT       = 0x0100
DC_GUARD_CF        = 0x4000

PROFILES = {
    "soft":   dict(dll_characteristics=0, pdb=True, signed=False),
    "hard":   dict(dll_characteristics=DC_DYNAMIC_BASE | DC_NX_COMPAT | DC_GUARD_CF | DC_HIGH_ENTROPY_VA,
                   pdb=False, signed=True),
    "packed": dict(dll_characteristics=0, packer=True, high_entropy_text=True),
}

DEFAULT_IMPORTS = {"KERNEL32.dll": ["CreateFileW", "VirtualProtect", "GetProcAddress"]}
DEFAULT_STRINGS = [
    "https://license.example.test/activate?sku=PRO",
    "ENTITLEMENT=pro_unlocked",
    "trial expired - purchase a license to continue",
]

E_LFANEW = 0x80
SIZE_OPT = 0xF0
SIZE_HEADERS = 0x200
RDATA_RVA = 0x2000
RDATA_OFF = 0x400


def build(path, dll_characteristics=0, imports=None, strings=None,
          pdb=False, signed=False, dotnet=False, packer=False,
          high_entropy_text=False):
    imports = imports or DEFAULT_IMPORTS
    strings = strings or DEFAULT_STRINGS

    rd = bytearray()

    def add(blob):
        if len(rd) % 2:
            rd.append(0)
        rva = RDATA_RVA + len(rd)
        rd.extend(blob)
        return rva

    def rva_off(rva):
        return RDATA_OFF + (rva - RDATA_RVA)

    # import tables (pointed-to data first, then the descriptor array)
    descriptors = []
    for dll, funcs in imports.items():
        thunks = []
        for fn in funcs:
            r = add(struct.pack("<H", 0) + fn.encode() + b"\x00")  # Hint(2)+name
            thunks.append(r)
        ilt = b"".join(struct.pack("<Q", t) for t in thunks) + struct.pack("<Q", 0)
        ilt_rva = add(ilt)
        iat_rva = add(ilt)
        name_rva = add(dll.encode() + b"\x00")
        descriptors.append((ilt_rva, name_rva, iat_rva))
    dtbl = bytearray()
    for ilt, name, iat in descriptors:
        dtbl += struct.pack("<IIIII", ilt, 0, 0, name, iat)
    dtbl += b"\x00" * 20
    import_rva = add(bytes(dtbl))
    import_size = len(dtbl)

    for sv in strings:
        add(sv.encode() + b"\x00")

    debug_dir = (0, 0)
    if pdb:
        cv = b"RSDS" + bytes(16) + struct.pack("<I", 1) + b"C:\\build\\carapace\\sample_soft.pdb\x00"
        cv_rva = add(cv)
        dbg = struct.pack("<IIHHIII", 0, 0, 0, 0, 2, len(cv), cv_rva) + struct.pack("<I", rva_off(cv_rva))
        dbg_rva = add(dbg)
        debug_dir = (dbg_rva, 28)

    clr_dir = (0, 0)
    if dotnet:
        clr_dir = (add(b"\x00" * 8), 8)

    # ---- sections ----
    text = bytearray(os.urandom(0x200) if high_entropy_text else (b"\x55\x48\x89\xe5\x90\x90\xc3\x00" * 0x40))
    text = bytes(text[:0x200]).ljust(0x200, b"\x00")
    rdata_raw = bytes(rd).ljust(((len(rd) + 0x1FF) // 0x200) * 0x200 or 0x200, b"\x00")
    text_name = b"UPX0" if packer else b".text"
    rdata_name = b"UPX1" if packer else b".rdata"

    size_image = RDATA_RVA + ((len(rdata_raw) + 0xFFF) // 0x1000) * 0x1000

    # ---- optional header (PE32+) ----
    opt = bytearray(SIZE_OPT)
    struct.pack_into("<H", opt, 0x00, 0x20B)          # Magic PE32+
    struct.pack_into("<I", opt, 0x04, len(text))      # SizeOfCode
    struct.pack_into("<I", opt, 0x10, 0x1000)         # AddressOfEntryPoint
    struct.pack_into("<I", opt, 0x14, 0x1000)         # BaseOfCode
    struct.pack_into("<Q", opt, 0x18, 0x140000000)    # ImageBase
    struct.pack_into("<I", opt, 0x20, 0x1000)         # SectionAlignment
    struct.pack_into("<I", opt, 0x24, 0x200)          # FileAlignment
    struct.pack_into("<H", opt, 0x30, 6)              # MajorSubsystemVersion
    struct.pack_into("<I", opt, 0x38, size_image)     # SizeOfImage
    struct.pack_into("<I", opt, 0x3C, SIZE_HEADERS)   # SizeOfHeaders
    struct.pack_into("<H", opt, 0x44, 3)              # Subsystem = console
    struct.pack_into("<H", opt, 0x46, dll_characteristics)
    struct.pack_into("<I", opt, 0x6C, 16)             # NumberOfRvaAndSizes
    dirs = [(0, 0)] * 16
    dirs[1] = (import_rva, import_size)               # Import
    dirs[6] = debug_dir                               # Debug
    dirs[14] = clr_dir                                # CLR
    # security (cert) dir set after we know file size

    # ---- COFF header ----
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, SIZE_OPT, 0x0022)

    # ---- section table ----
    def sec(name, vsize, vaddr, rawsize, rawptr, char):
        return name.ljust(8, b"\x00") + struct.pack("<IIII", vsize, vaddr, rawsize, rawptr) \
            + struct.pack("<IIHH", 0, 0, 0, 0) + struct.pack("<I", char)
    sects = sec(text_name, len(text), 0x1000, len(text), 0x200, 0x60000020) \
        + sec(rdata_name, len(rd), RDATA_RVA, len(rdata_raw), RDATA_OFF, 0x40000040)

    # ---- assemble headers region ----
    headers = bytearray(SIZE_HEADERS)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, E_LFANEW)
    headers[0x40:0x40 + 40] = b"This program cannot be run in DOS mode.\x00"[:40]
    headers[E_LFANEW:E_LFANEW + 4] = b"PE\x00\x00"
    headers[E_LFANEW + 4:E_LFANEW + 4 + 20] = coff
    off = E_LFANEW + 24
    headers[off:off + SIZE_OPT] = opt
    soff = off + SIZE_OPT
    headers[soff:soff + len(sects)] = sects

    body = bytes(headers) + text + rdata_raw
    cert = b""
    if signed:
        cert_off = len(body)
        cert = b"\x30\x82\x01\x00" + os.urandom(0x80)   # a dummy PKCS#7-ish blob
        dirs[4] = (cert_off, len(cert))

    # write the (possibly updated) data directories back into the header bytes
    dir_base = E_LFANEW + 24 + 0x70
    for i, (r, s) in enumerate(dirs):
        struct.pack_into("<II", headers, dir_base + i * 8, r, s)
    body = bytes(headers) + text + rdata_raw + cert

    with open(path, "wb") as fh:
        fh.write(body)
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate a minimal PE32+ fixture for the audit.")
    ap.add_argument("--out", required=True)
    ap.add_argument("--profile", choices=sorted(PROFILES), default="soft")
    args = ap.parse_args(argv)
    build(args.out, **PROFILES[args.profile])
    print(f"wrote {args.profile} PE fixture -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

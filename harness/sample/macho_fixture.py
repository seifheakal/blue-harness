#!/usr/bin/env python3
# Carapace — minimal Mach-O fixture generator (Slice N verify helper).
#
# No Apple toolchain in the dev container, so the verify builds its own Mach-O
# test inputs here: a structurally valid thin 64-bit (x86-64) Mach-O with a
# configurable symbol table, a __TEXT,__cstring section of plaintext strings, PIE/
# stack-exec flags, an optional code signature, an optional __RESTRICT segment,
# and an optional LC_ENCRYPTION_INFO_64 — plus a fat/universal wrapper. Enough to
# exercise every path the Mach-O scanner reads; these are READ-ONLY audit inputs,
# not loadable executables.

import struct
import argparse

MH_MAGIC_64 = 0xFEEDFACF
CPU_X86_64 = 0x01000007
MH_EXECUTE = 2
MH_PIE = 0x200000
MH_ALLOW_STACK_EXECUTION = 0x20000

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO_64 = 0x2C

DYLIB = b"/usr/lib/libSystem.B.dylib\x00"
STRINGS = [b"https://license.example.test/activate?sku=PRO",
           b"ENTITLEMENT=pro_unlocked",
           b"trial expired - purchase a license to continue"]
SYMS = [b"_main", b"_validate_license", b"_decrypt_blob", b"_g_secret_key",
        b"_compute_checksum", b"_phone_home"]
TEXT = (b"\x55\x48\x89\xe5\x90\x90\xc3\x00") * 8   # 64 bytes, low entropy

PROFILES = {
    "soft": dict(pie=False, stack_exec=True, syms=True, cstring=True,
                 signed=False, restrict=False, encrypted=False),
    "hard": dict(pie=True, stack_exec=False, syms=False, cstring=False,
                 signed=True, restrict=True, encrypted=False),
    "encrypted": dict(pie=True, stack_exec=False, syms=False, cstring=False,
                      signed=True, restrict=True, encrypted=True),
}


def _align8(n):
    return (n + 7) & ~7


def _seg64(segname, sections, segflags=0):
    """sections: list of (sectname, fileoff, size). Returns the LC bytes."""
    nsects = len(sections)
    cmdsize = 72 + 80 * nsects
    out = struct.pack("<II", LC_SEGMENT_64, cmdsize)
    out += segname.encode().ljust(16, b"\x00")
    out += struct.pack("<QQQQ", 0, 0, 0, 0)       # vmaddr, vmsize, fileoff, filesize
    out += struct.pack("<iiII", 7, 5, nsects, segflags)  # maxprot, initprot, nsects, flags
    for sectname, foff, size in sections:
        out += sectname.encode().ljust(16, b"\x00")
        out += segname.encode().ljust(16, b"\x00")
        out += struct.pack("<QQ", 0, size)        # addr, size
        out += struct.pack("<II", foff, 0)        # offset, align
        out += struct.pack("<III", 0, 0, 0)       # reloff, nreloc, flags
        out += struct.pack("<III", 0, 0, 0)       # reserved1/2/3
    assert len(out) == cmdsize
    return out


def build(path, pie, stack_exec, syms, cstring, signed, restrict, encrypted):
    # ---- decide section layout (offsets filled after we know sizeofcmds) -----
    text = bytes(TEXT)
    cstr = (b"\x00".join(STRINGS) + b"\x00") if cstring else b""

    # symbol + string tables
    if syms:
        strtab = b"\x00"
        strx = []
        for nm in SYMS:
            strx.append(len(strtab))
            strtab += nm + b"\x00"
        nsyms = len(SYMS)
    else:
        strtab = b""
        strx = []
        nsyms = 0

    # ---- compute sizeofcmds (sizes are independent of offset values) --------
    text_sects = [("__text", 0, len(text))]
    if cstring:
        text_sects.append(("__cstring", 0, len(cstr)))
    cmds_sizes = []
    cmds_sizes.append(72 + 80 * len(text_sects))        # LC_SEGMENT_64 __TEXT
    if restrict:
        cmds_sizes.append(72)                           # LC_SEGMENT_64 __RESTRICT (0 sects)
    cmds_sizes.append(24)                               # LC_SYMTAB
    dylib_cmdsize = _align8(24 + len(DYLIB))            # cmd/size + 16 + name(padded)
    cmds_sizes.append(dylib_cmdsize)                    # LC_LOAD_DYLIB
    cmds_sizes.append(24)                               # LC_UUID
    if encrypted:
        cmds_sizes.append(24)                           # LC_ENCRYPTION_INFO_64
    if signed:
        cmds_sizes.append(16)                           # LC_CODE_SIGNATURE
    sizeofcmds = sum(cmds_sizes)
    ncmds = len(cmds_sizes)

    # ---- concrete file offsets ----------------------------------------------
    data_start = 32 + sizeofcmds
    text_off = data_start
    cstr_off = text_off + len(text)
    symoff = _align8(cstr_off + len(cstr))
    stroff = symoff + nsyms * 16
    crypt_off = stroff + len(strtab)
    csig_off = crypt_off + (0x20 if encrypted else 0)

    # ---- build load commands with real offsets ------------------------------
    lc = b""
    sects = [("__text", text_off, len(text))]
    if cstring:
        sects.append(("__cstring", cstr_off, len(cstr)))
    lc += _seg64("__TEXT", sects)
    if restrict:
        lc += _seg64("__RESTRICT", [])
    lc += struct.pack("<IIIIII", LC_SYMTAB, 24, symoff, nsyms, stroff, len(strtab))
    dylib = struct.pack("<IIIIII", LC_LOAD_DYLIB, dylib_cmdsize, 24, 0, 0, 0) + DYLIB
    dylib = dylib.ljust(dylib_cmdsize, b"\x00")
    lc += dylib
    lc += struct.pack("<II", LC_UUID, 24) + bytes(range(16))
    if encrypted:
        lc += struct.pack("<IIIII", LC_ENCRYPTION_INFO_64, 24, crypt_off, 0x20, 1) + struct.pack("<I", 0)
    if signed:
        lc += struct.pack("<IIII", LC_CODE_SIGNATURE, 16, csig_off, 0x40)
    assert len(lc) == sizeofcmds, (len(lc), sizeofcmds)

    # ---- header --------------------------------------------------------------
    flags = 0
    if pie:
        flags |= MH_PIE
    if stack_exec:
        flags |= MH_ALLOW_STACK_EXECUTION
    header = struct.pack("<IIIIIIII", MH_MAGIC_64, CPU_X86_64, 3, MH_EXECUTE,
                         ncmds, sizeofcmds, flags, 0)

    # ---- assemble ------------------------------------------------------------
    body = bytearray(header + lc + text + cstr)
    body = body.ljust(symoff, b"\x00")
    for i, nm in enumerate(SYMS if syms else []):
        body += struct.pack("<IBBHQ", strx[i], 0x0E, 1, 0, 0x1000 + i * 16)
    body += strtab
    if encrypted:
        body += b"\x00" * 0x20
    if signed:
        body += b"\xfa\xde\x0c\xc0" + b"\x00" * 0x3C   # a dummy CSMAGIC_EMBEDDED_SIGNATURE-ish blob
    with open(path, "wb") as f:
        f.write(bytes(body))
    return bytes(body)


def build_fat(path, thin_bytes):
    """Wrap a thin Mach-O in a 1-slice fat/universal container (big-endian header)."""
    slice_off = 0x1000
    header = struct.pack(">II", 0xCAFEBABE, 1)
    arch = struct.pack(">IIIII", CPU_X86_64 & 0xFFFFFFFF, 3, slice_off, len(thin_bytes), 12)
    blob = header + arch
    blob = blob.ljust(slice_off, b"\x00") + thin_bytes
    with open(path, "wb") as f:
        f.write(blob)
    return blob


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate a minimal Mach-O fixture for the audit.")
    ap.add_argument("--out", required=True)
    ap.add_argument("--profile", choices=sorted(PROFILES), default="soft")
    ap.add_argument("--fat", action="store_true", help="wrap in a fat/universal container")
    args = ap.parse_args(argv)
    thin = build(args.out if not args.fat else args.out + ".thin", **PROFILES[args.profile])
    if args.fat:
        build_fat(args.out, thin)
        import os
        os.remove(args.out + ".thin")
    print(f"wrote {args.profile}{' fat' if args.fat else ''} Mach-O fixture -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

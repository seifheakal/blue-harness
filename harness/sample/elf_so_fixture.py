#!/usr/bin/env python3
# Carapace — minimal ELF shared-object fixture (Slice R verify helper).
#
# No cross-compiler in the dev container, and the Mach-O/PE fixtures set the
# precedent: build a structurally valid ELF64 AArch64 shared object (ET_DYN, the
# Android arm64-v8a `.so` shape) by hand, with a symbol table (local + global,
# JNI-flavoured names), a __plaintext__ .rodata, a .text, and an NX stack — enough
# for the self-contained ELF auditor to read symbols + string density + entropy.
#
# This is a READ-ONLY audit input, cross-platform (pure Python). It is NOT meant
# to load or to be objcopy'd — the harden-dispatch path in the Slice R verify
# builds a REAL `.so` with gcc when a toolchain is present, and gates otherwise.

import struct
import argparse

ET_DYN = 3
EM_AARCH64 = 0xB7
PT_LOAD = 1
PT_GNU_STACK = 0x6474E551

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHF_ALLOC = 0x2
SHF_EXEC = 0x4

STB_LOCAL = 0
STB_GLOBAL = 1
STT_OBJECT = 1
STT_FUNC = 2

# JNI-flavoured so the fixture reads like a real Android native lib.
LOCALS = [("compute_license_key", STT_FUNC), ("g_secret_seed", STT_OBJECT),
          ("decrypt_payload", STT_FUNC)]
GLOBALS = [("JNI_OnLoad", STT_FUNC), ("Java_com_example_app_check", STT_FUNC)]
RODATA_STRINGS = [b"https://api.example.test/v1/activate?sku=PRO",
                  b"LICENSE_VALID", b"trial expired - purchase to continue",
                  b"ENTITLEMENT=pro_unlocked"]
TEXT = bytes([0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91] * 4)  # 32 B, low entropy


def _align8(n):
    return (n + 7) & ~7


def _strtab(names):
    blob = b"\x00"
    offs = {}
    for n in names:
        offs[n] = len(blob)
        blob += n.encode() + b"\x00"
    return blob, offs


def build(path):
    rodata = b"\x00".join(RODATA_STRINGS) + b"\x00"

    sym_names = [n for n, _ in LOCALS] + [n for n, _ in GLOBALS]
    strtab, soff = _strtab(sym_names)
    sh_names = [".text", ".rodata", ".symtab", ".strtab", ".shstrtab"]
    shstrtab, shoff_names = _strtab(sh_names)

    ehsize, phentsize, phnum, shentsize, shnum = 64, 56, 2, 64, 6
    text_off = ehsize + phentsize * phnum          # 176
    rodata_off = text_off + len(TEXT)
    symtab_off = _align8(rodata_off + len(rodata))
    nsyms = 1 + len(sym_names)                      # index 0 is the null symbol
    symtab_sz = nsyms * 24
    strtab_off = symtab_off + symtab_sz
    shstrtab_off = strtab_off + len(strtab)
    sh_off = _align8(shstrtab_off + len(shstrtab))
    total = sh_off + shentsize * shnum

    # ---- ELF header ----
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        ET_DYN, EM_AARCH64, 1, 0, ehsize, sh_off, 0,
        ehsize, phentsize, phnum, shentsize, shnum, 5)

    # ---- program headers (PIE/.so shape + NX stack) ----
    p_load = struct.pack("<IIQQQQQQ", PT_LOAD, 5, 0, 0, 0, total, total, 0x1000)
    p_stack = struct.pack("<IIQQQQQQ", PT_GNU_STACK, 6, 0, 0, 0, 0, 0, 0x10)  # RW, no X
    phdrs = p_load + p_stack

    # ---- symbol table (null, then locals, then globals) ----
    syms = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    for n, t in LOCALS:
        info = (STB_LOCAL << 4) | t
        syms += struct.pack("<IBBHQQ", soff[n], info, 0, 1, 0x1000, 8)   # shndx .text
    for n, t in GLOBALS:
        info = (STB_GLOBAL << 4) | t
        syms += struct.pack("<IBBHQQ", soff[n], info, 0, 1, 0x1000, 8)
    first_global = 1 + len(LOCALS)

    # ---- section headers ----
    def shdr(name_off, stype, flags, offset, size, link, info, entsize):
        return struct.pack("<IIQQQQIIQQ", name_off, stype, flags, 0, offset, size,
                           link, info, 0, entsize)

    shdrs = shdr(0, 0, 0, 0, 0, 0, 0, 0)                                   # NULL
    shdrs += shdr(shoff_names[".text"], SHT_PROGBITS, SHF_ALLOC | SHF_EXEC,
                  text_off, len(TEXT), 0, 0, 0)
    shdrs += shdr(shoff_names[".rodata"], SHT_PROGBITS, SHF_ALLOC,
                  rodata_off, len(rodata), 0, 0, 0)
    shdrs += shdr(shoff_names[".symtab"], SHT_SYMTAB, 0,
                  symtab_off, symtab_sz, 4, first_global, 24)              # link -> .strtab (idx 4)
    shdrs += shdr(shoff_names[".strtab"], SHT_STRTAB, 0,
                  strtab_off, len(strtab), 0, 0, 0)
    shdrs += shdr(shoff_names[".shstrtab"], SHT_STRTAB, 0,
                  shstrtab_off, len(shstrtab), 0, 0, 0)

    buf = bytearray(total)
    buf[0:len(ehdr)] = ehdr
    buf[ehsize:ehsize + len(phdrs)] = phdrs
    buf[text_off:text_off + len(TEXT)] = TEXT
    buf[rodata_off:rodata_off + len(rodata)] = rodata
    buf[symtab_off:symtab_off + len(syms)] = syms
    buf[strtab_off:strtab_off + len(strtab)] = strtab
    buf[shstrtab_off:shstrtab_off + len(shstrtab)] = shstrtab
    buf[sh_off:sh_off + len(shdrs)] = shdrs

    with open(path, "wb") as f:
        f.write(bytes(buf))
    return bytes(buf)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate a minimal ELF64 AArch64 .so fixture.")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    build(args.out)
    print(f"wrote ELF64 AArch64 .so fixture -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

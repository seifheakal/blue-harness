#!/usr/bin/env python3
# Carapace — Mach-O LOCAL-symbol strip (Slice O): the first Mach-O harden.
#
# WHAT THIS IS
#   A post-build pass that removes the LOCAL (static / internal) symbols from a
#   Mach-O's symbol table — exactly what `strip -x` does — so an AI-RE agent loses
#   the internal function/variable names it mines, while the EXTERNAL and UNDEFINED
#   symbols the dynamic linker needs are preserved. It operates byte-level with no
#   Apple/LLVM toolchain, using LC_SYMTAB + LC_DYSYMTAB.
#
# WHAT IT IS NOT (the honest line — CLAUDE.md §3):
#   We run on Linux and CANNOT execute a Mach-O, so — unlike the ELF transforms —
#   we do NOT claim this is runtime-identical here. We PROVE it is SURGICAL (only
#   the local nlist entries + their name strings are removed; every load command,
#   segment and section is preserved, and all file offsets are kept stable), and
#   leave runtime verification to a macOS host (platform-gated, like the Slice K
#   VM). Stripping also invalidates any existing code signature, so the correct
#   order is strip -> codesign on the build host; we WARN if a signature is present.
#
# HONESTY TIER: Speed-bump->Meaningful (removes internal identity an agent reasons
#   from). NAMED BYPASS: the EXTERNAL/exported names remain (dyld needs them) and a
#   thorough agent recovers logic from behavior/xrefs regardless of names.

import sys
import struct
import shutil
import argparse

MAGICS = {b"\xcf\xfa\xed\xfe": ("<", True), b"\xfe\xed\xfa\xcf": (">", True),
          b"\xce\xfa\xed\xfe": ("<", False), b"\xfe\xed\xfa\xce": (">", False)}
FAT_MAGICS = {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}
LC_REQ_DYLD = 0x80000000
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_CODE_SIGNATURE = 0x1D


class StripError(Exception):
    pass


class _MO:
    def __init__(self, data):
        self.d = bytearray(data)
        head = bytes(self.d[:4])
        if head in FAT_MAGICS:
            raise StripError("fat/universal Mach-O: strip each thin slice separately (not supported here)")
        if head not in MAGICS:
            raise StripError("not a thin Mach-O")
        self.e, self.is64 = MAGICS[head]
        self.ncmds = self._u("I", 16)
        self.hdr = 32 if self.is64 else 28
        self.symtab_off = None
        self.dysym_off = None
        self.code_sig = False
        self._scan()

    def _u(self, fmt, off):
        return struct.unpack_from(self.e + fmt, self.d, off)[0]

    def _scan(self):
        off = self.hdr
        for _ in range(self.ncmds):
            cmd = self._u("I", off) & ~LC_REQ_DYLD
            sz = self._u("I", off + 4)
            if sz < 8:
                break
            if cmd == LC_SYMTAB:
                self.symtab_off = off
            elif cmd == LC_DYSYMTAB:
                self.dysym_off = off
            elif cmd == LC_CODE_SIGNATURE:
                self.code_sig = True
            off += sz


def strip_locals(src, dst):
    with open(src, "rb") as f:
        mo = _MO(f.read())
    e = mo.e
    if mo.symtab_off is None:
        raise StripError("no LC_SYMTAB — nothing to strip")
    so = mo.symtab_off
    symoff = mo._u("I", so + 8)
    nsyms = mo._u("I", so + 12)
    stroff = mo._u("I", so + 16)
    strsize = mo._u("I", so + 20)
    if nsyms == 0:
        raise StripError("symbol table is empty — nothing to strip")
    if mo.dysym_off is None:
        raise StripError("no LC_DYSYMTAB — cannot identify the LOCAL block safely; "
                         "refusing (a blind full strip could break dynamic linking)")
    dy = mo.dysym_off
    ilocal = mo._u("I", dy + 8)
    nlocal = mo._u("I", dy + 12)
    iext = mo._u("I", dy + 16)
    next_ = mo._u("I", dy + 20)
    iundef = mo._u("I", dy + 24)
    nundef = mo._u("I", dy + 28)

    nl = 16 if mo.is64 else 12          # nlist_64 / nlist size
    d = mo.d

    def nlist(i):
        base = symoff + i * nl
        n_strx = mo._u("I", base)
        rest = bytes(d[base + 4:base + nl])
        return n_strx, rest

    # keep every symbol EXCEPT the local block [ilocal, ilocal+nlocal)
    keep = [i for i in range(nsyms) if not (ilocal <= i < ilocal + nlocal)]
    strblob = bytes(d[stroff:stroff + strsize])

    new_syms = bytearray()
    new_str = bytearray(b"\x00")        # index 0 = empty name, by convention
    strmap = {0: 0}
    for i in keep:
        n_strx, rest = nlist(i)
        if n_strx == 0:
            new_strx = 0
        elif n_strx in strmap:
            new_strx = strmap[n_strx]
        else:
            end = strblob.find(b"\x00", n_strx)
            name = strblob[n_strx:end if end >= 0 else len(strblob)]
            new_strx = len(new_str)
            new_str += name + b"\x00"
            strmap[n_strx] = new_strx
        new_syms += struct.pack(e + "I", new_strx) + rest

    new_nsyms = len(keep)
    # ---- write back IN PLACE, keeping all file offsets stable ---------------
    old_sym_bytes = nsyms * nl
    old_str_bytes = strsize
    if len(new_syms) > old_sym_bytes or len(new_str) > old_str_bytes:
        raise StripError("stripped tables are larger than the originals (unexpected)")
    # symbol table region: new (smaller) array, zero-fill the freed tail
    d[symoff:symoff + old_sym_bytes] = bytes(new_syms).ljust(old_sym_bytes, b"\x00")
    # string table region: new (smaller) table, zero-fill the freed tail
    d[stroff:stroff + old_str_bytes] = bytes(new_str).ljust(old_str_bytes, b"\x00")
    # LC_SYMTAB: nsyms, strsize shrink; offsets unchanged
    struct.pack_into(e + "I", d, so + 12, new_nsyms)
    struct.pack_into(e + "I", d, so + 20, len(new_str))
    # LC_DYSYMTAB: local block gone; ext now starts at 0, undef after it
    struct.pack_into(e + "I", d, dy + 8, 0)                 # ilocalsym
    struct.pack_into(e + "I", d, dy + 12, 0)                # nlocalsym
    struct.pack_into(e + "I", d, dy + 16, 0)                # iextdefsym
    struct.pack_into(e + "I", d, dy + 20, next_)            # nextdefsym (unchanged)
    struct.pack_into(e + "I", d, dy + 24, next_)            # iundefsym
    struct.pack_into(e + "I", d, dy + 28, nundef)           # nundefsym (unchanged)

    with open(dst, "wb") as f:
        f.write(bytes(d))
    if src != dst:
        shutil.copymode(src, dst)
    return {
        "removed_locals": nlocal,
        "kept": new_nsyms,
        "externals": next_,
        "undefined": nundef,
        "code_signed": mo.code_sig,
        "file_size_stable": True,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Carapace Mach-O local-symbol strip (strip -x equivalent; COST, not prevention).")
    ap.add_argument("--in", dest="src", required=True)
    ap.add_argument("--out", dest="dst", required=True)
    a = ap.parse_args(argv)
    try:
        info = strip_locals(a.src, a.dst)
    except (StripError, FileNotFoundError, IsADirectoryError) as e:
        print(f"carapace-macho-strip error: {e}", file=sys.stderr)
        return 2
    print(f"[carapace-macho-strip] {a.src} -> {a.dst}")
    print(f"  removed {info['removed_locals']} LOCAL symbol(s); kept "
          f"{info['externals']} external + {info['undefined']} undefined (dyld needs these)")
    print("  surgical: only the local nlist entries + their name strings removed; all load")
    print("  commands, segments, sections and file offsets preserved.")
    if info["code_signed"]:
        print("  WARNING: input carries a code signature — stripping invalidates it. Re-sign on")
        print("  the build host (correct order is strip -> codesign).")
    print("  tier: Speed-bump→Meaningful. bypass: external/exported names remain + behavior is")
    print("  recoverable. NOTE: runtime-identical needs a macOS host to confirm; not run here.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# Carapace — Mach-O exposure audit (read-only). The third format (Slice N).
#
# A self-contained Mach-O parser (no macholib / no Apple toolchain) that reads the
# same signals an AI-assisted RE agent (e.g. rea) reads for free from a Mach-O —
# symbol table size, __TEXT,__cstring string density, section entropy, linked
# dylibs, PIE / stack-exec flags, a code signature (READ-ONLY — presence only,
# NOT verified, the honest note it prints), and __TEXT encryption (LC_ENCRYPTION_
# INFO cryptid) — and scores a tiered posture parallel to the ELF and PE scanners.
#
# Handles thin 32/64-bit (both byte orders) and fat/universal (parses the first
# slice, reports the slice count). These are inputs for a read-only audit.
#
# Honest: heuristic posture, never a guarantee; a code signature on disk is read,
# not verified — its value is only in a runtime, server-checked signature.

import os
import sys
import json
import struct
import argparse

# magics (as the 4 leading file bytes)
MAGICS = {
    b"\xcf\xfa\xed\xfe": ("<", True),    # 64-bit little-endian
    b"\xfe\xed\xfa\xcf": (">", True),    # 64-bit big-endian
    b"\xce\xfa\xed\xfe": ("<", False),   # 32-bit little-endian
    b"\xfe\xed\xfa\xce": (">", False),   # 32-bit big-endian
}
FAT_MAGICS = {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}

LC_REQ_DYLD = 0x80000000
LC_SEGMENT        = 0x1
LC_SYMTAB         = 0x2
LC_LOAD_DYLIB     = 0xc
LC_LOAD_WEAK_DYLIB = 0x18
LC_REEXPORT_DYLIB = 0x1f
LC_SEGMENT_64     = 0x19
LC_UUID           = 0x1b
LC_CODE_SIGNATURE = 0x1d
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2c
LC_MAIN           = 0x28

CPU = {
    0x01000007: "x86-64", 0x7: "i386",
    0x0100000c: "arm64", 0xc: "arm", 0x0200000c: "arm64_32",
}
FILETYPE = {1: "OBJECT", 2: "EXECUTE", 3: "FVMLIB", 4: "CORE", 5: "PRELOAD",
            6: "DYLIB", 7: "DYLINKER", 8: "BUNDLE", 10: "DSYM"}

MH_PIE = 0x200000
MH_ALLOW_STACK_EXECUTION = 0x20000
MH_NO_HEAP_EXECUTION = 0x1000000


class MachOError(Exception):
    pass


def shannon_entropy(buf):
    if not buf:
        return 0.0
    from math import log2
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    n = len(buf)
    return -sum((c / n) * log2(c / n) for c in counts if c)


def printable_density(buf):
    if not buf:
        return 0.0, 0
    printable = sum(1 for b in buf if 0x20 <= b < 0x7f)
    runs, cur = 0, 0
    for b in buf:
        if 0x20 <= b < 0x7f:
            cur += 1
        else:
            if cur >= 4:
                runs += 1
            cur = 0
    if cur >= 4:
        runs += 1
    return printable / len(buf), runs


class MachO:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if len(d) < 4:
            raise MachOError("too small to be Mach-O")
        head = d[:4]
        self.is_fat = False
        self.n_slices = 1
        base = 0
        if head in FAT_MAGICS:
            self.is_fat = True
            # fat header + fat_arch are big-endian
            nfat = struct.unpack_from(">I", d, 4)[0]
            self.n_slices = nfat
            if nfat == 0:
                raise MachOError("fat binary with no slices")
            # fat_arch: cputype, cpusubtype, offset, size, align (all BE u32)
            base = struct.unpack_from(">I", d, 8 + 8)[0]   # offset field of arch[0]
            head = d[base:base + 4]
            if head not in MAGICS:
                raise MachOError("fat slice is not a thin Mach-O")
        if head not in MAGICS:
            raise MachOError("not a Mach-O file")
        self.base = base
        self.e, self.is64 = MAGICS[head]
        self._parse_header()
        self._parse_commands()

    def _u(self, fmt, off):
        return struct.unpack_from(self.e + fmt, self.data, off)[0]

    def _parse_header(self):
        b = self.base
        # magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags (+reserved on 64)
        self.cputype = self._u("I", b + 4)
        self.filetype = self._u("I", b + 12)
        self.ncmds = self._u("I", b + 16)
        self.flags = self._u("I", b + 24)
        self.hdr_size = 32 if self.is64 else 28

    def _cstr(self, off):
        end = self.data.find(b"\x00", off)
        return self.data[off:end if end >= 0 else off].decode("utf-8", "replace")

    def _parse_commands(self):
        self.segments = []     # (segname, [ (sectname, offset, size) ])
        self.sections = []     # (segname, sectname, offset, size)
        self.symtab = None     # (symoff, nsyms, stroff, strsize)
        self.dylibs = []
        self.uuid_present = False
        self.code_signature = None   # (dataoff, datasize)
        self.encryption = None       # cryptid
        self.has_main = False

        off = self.base + self.hdr_size
        for _ in range(self.ncmds):
            if off + 8 > len(self.data):
                break
            cmd = self._u("I", off)
            cmdsize = self._u("I", off + 4)
            if cmdsize < 8:
                break
            raw = cmd & ~LC_REQ_DYLD
            if raw in (LC_SEGMENT_64, LC_SEGMENT):
                self._parse_segment(off, raw == LC_SEGMENT_64)
            elif raw == LC_SYMTAB:
                self.symtab = (self._u("I", off + 8), self._u("I", off + 12),
                               self._u("I", off + 16), self._u("I", off + 20))
            elif raw in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
                name_off = self._u("I", off + 8)
                self.dylibs.append(self._cstr(off + name_off))
            elif raw == LC_UUID:
                self.uuid_present = True
            elif raw == LC_CODE_SIGNATURE:
                self.code_signature = (self._u("I", off + 8), self._u("I", off + 12))
            elif raw in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                self.encryption = self._u("I", off + 16)   # cryptid
            elif raw == LC_MAIN:
                self.has_main = True
            off += cmdsize

    def _parse_segment(self, off, is64):
        segname = self.data[off + 8:off + 24].split(b"\x00")[0].decode("latin-1")
        if is64:
            nsects = self._u("I", off + 64)
            sec = off + 72
            step = 80
        else:
            nsects = self._u("I", off + 48)
            sec = off + 56
            step = 68
        sects = []
        for i in range(nsects):
            so = sec + i * step
            if so + step > len(self.data):
                break
            sectname = self.data[so:so + 16].split(b"\x00")[0].decode("latin-1")
            if is64:
                size = self._u("Q", so + 40)
                foff = self._u("I", so + 48)
            else:
                size = self._u("I", so + 36)
                foff = self._u("I", so + 40)
            sects.append((sectname, foff, size))
            self.sections.append((segname, sectname, foff, size))
        self.segments.append((segname, sects))

    def section_bytes(self, segname, sectname):
        for sg, st, foff, size in self.sections:
            if sg == segname and st == sectname:
                start = self.base + foff
                return self.data[start:start + size]
        return b""

    def has_segment(self, segname):
        return any(sg == segname for sg, _ in self.segments)


def analyze(path):
    m = MachO(path)
    d = m.data

    nsyms = m.symtab[1] if m.symtab else 0
    symbols_present = nsyms > 0

    # strings over the read-heavy sections an agent mines
    str_target = m.section_bytes("__TEXT", "__cstring") + m.section_bytes("__TEXT", "__const")
    if not str_target:
        str_target = d
    str_density, str_runs = printable_density(str_target)

    entropy_map = {}
    for sg, st, foff, size in m.sections:
        b = d[m.base + foff:m.base + foff + size]
        if b:
            entropy_map[f"{sg},{st}"] = round(shannon_entropy(b), 3)
    whole_entropy = round(shannon_entropy(d), 3)
    high_entropy = any(v >= 7.2 for v in entropy_map.values()) or whole_entropy >= 7.4

    encrypted = bool(m.encryption)   # cryptid != 0 => __TEXT encrypted at rest
    hardening = {
        "pie": bool(m.flags & MH_PIE),
        "stack_exec_allowed": bool(m.flags & MH_ALLOW_STACK_EXECUTION),
        "no_heap_exec": bool(m.flags & MH_NO_HEAP_EXECUTION),
        "restrict_segment": m.has_segment("__RESTRICT"),
        "encrypted": encrypted,
    }

    packer = []
    if b"UPX!" in d:
        packer.append("UPX-packed")
    if high_entropy and not packer and not encrypted:
        packer.append("high-entropy (possible packing)")

    s = {
        "file": os.path.basename(path),
        "format": ("Mach-O64" if m.is64 else "Mach-O32") + ("-FAT" if m.is_fat else ""),
        "machine": CPU.get(m.cputype, f"{m.cputype:#010x}"),
        "filetype": FILETYPE.get(m.filetype, str(m.filetype)),
        "fat_slices": m.n_slices,
        "symbols_present": symbols_present,
        "symbol_count": nsyms,
        "stripped": not symbols_present,
        "string_density": round(str_density, 4),
        "string_runs": str_runs,
        "entropy_map": entropy_map,
        "whole_file_entropy": whole_entropy,
        "high_entropy": high_entropy,
        "hardening": hardening,
        "code_signature_present": m.code_signature is not None,   # READ-ONLY, not verified
        "uuid_present": m.uuid_present,
        "dylibs": [os.path.basename(x) for x in m.dylibs][:16],
        "dylib_count": len(m.dylibs),
        "packer": packer,
    }
    s["score"], s["tier"], s["recommendation"] = score(s)
    return s


def score(s):
    pts = 0
    why = []
    h = s["hardening"]
    if s["symbols_present"]:
        pts += 20
        why.append(f"symbol table present ({s['symbol_count']} syms an agent reads)")
    if s["string_density"] >= 0.05:
        pts += 18
        why.append("high plaintext-string density (__cstring)")
    elif s["string_density"] >= 0.01:
        pts += 9
        why.append("moderate plaintext-string density")
    if not h["pie"]:
        pts += 10
        why.append("no PIE (MH_PIE off) — position fixed")
    if h["stack_exec_allowed"]:
        pts += 10
        why.append("stack execution allowed (MH_ALLOW_STACK_EXECUTION)")
    if not s["code_signature_present"]:
        pts += 6
        why.append("no code signature (note: an on-disk signature is not itself a defense)")
    if h["encrypted"]:
        pts -= 40
        why.append("__TEXT encrypted at rest (LC_ENCRYPTION_INFO cryptid != 0) — static view is ciphertext")
    pts = max(0, min(pts, 100))
    if pts >= 70:
        tier = "WIDE-OPEN (trivial for an AI-assisted agent)"
    elif pts >= 45:
        tier = "EXPOSED (speed-bump at best)"
    elif pts >= 20:
        tier = "PARTIALLY HARDENED (meaningful cost added)"
    else:
        tier = "HARDENED SURFACE (cost raised; never unbreakable)"
    return pts, tier, {"exposure_drivers": why, "next_hardening": recommend(s)}


def recommend(s):
    h = s["hardening"]
    if s["symbols_present"]:
        return ("Strip LOCAL/static symbols (harness/harden/carapace_macho_strip.py, or "
                "`carapace apply`) and don't ship a companion dSYM — Tier: Speed-bump→Meaningful. "
                "Bypass: exported names remain (dyld needs them); the agent reasons from behavior.")
    if s["string_density"] >= 0.05:
        return ("Encrypt / decode-on-demand high-density plaintext strings "
                "(see harness/harden/carapace_string_encrypt.py). Tier: Speed-bump→Meaningful. "
                "Bypass: runtime key recovery from memory.")
    if not h["pie"]:
        return ("Build position-independent (-fPIE -pie) so load addresses vary. "
                "Tier: raises exploitation effort — it does NOT block decompilation.")
    if not s["code_signature_present"]:
        return ("Code-sign AND verify at runtime server-side. Tier: Meaningful only WITH the "
                "runtime+server check — a signature on disk alone is read, not verified, by rea.")
    return ("Surface hardened. The only Strong tier is server-side relocation of secrets and "
            "trust decisions (CLAUDE.md §3).")


def render(s):
    h = s["hardening"]

    def yn(b, y="yes", n="no"):
        return y if b else n
    L = []
    L.append("=" * 68)
    L.append(f"  Carapace Mach-O Exposure Audit — {s['file']}  "
             f"[{s['format']} / {s['machine']} / {s['filetype']}]")
    if s["fat_slices"] > 1:
        L.append(f"  (fat/universal: {s['fat_slices']} slices — audited the first)")
    L.append("=" * 68)
    L.append(f"  EXPOSURE SCORE : {s['score']}/100")
    L.append(f"  POSTURE TIER   : {s['tier']}")
    L.append("")
    L.append("  Signals an AI-assisted RE agent (e.g. rea) reads for free:")
    L.append(f"    symbol table ........... {yn(s['symbols_present'],'PRESENT','stripped')}"
             f"  ({s['symbol_count']} symbols)")
    L.append(f"    string density ......... {s['string_density']:.4f} ({s['string_runs']} runs >=4)")
    emap = ", ".join(f"{k}={v}" for k, v in list(s["entropy_map"].items())[:6]) or "n/a"
    L.append(f"    section entropy ........ {emap}  (whole={s['whole_file_entropy']})")
    L.append(f"    linked dylibs .......... {s['dylib_count']}"
             + (f"  ({', '.join(s['dylibs'][:5])})" if s['dylibs'] else ""))
    L.append(f"    packer ................. {', '.join(s['packer']) or 'none'}")
    L.append("")
    L.append("  Hardening flags (parity with rea's Mach-O inspection):")
    L.append(f"    PIE={yn(h['pie'])} | stack-exec-allowed={yn(h['stack_exec_allowed'])} | "
             f"__RESTRICT={yn(h['restrict_segment'])} | __TEXT-encrypted={yn(h['encrypted'])}")
    L.append(f"    code signature present (READ-ONLY, not verified): {yn(s['code_signature_present'])}")
    L.append(f"    build UUID present: {yn(s['uuid_present'])}")
    L.append("")
    L.append("  Exposure drivers:")
    for r in s["recommendation"]["exposure_drivers"]:
        L.append(f"    - {r}")
    L.append("")
    L.append("  NEXT HIGHEST-VALUE HARDENING:")
    L.append(f"    {s['recommendation']['next_hardening']}")
    L.append("")
    L.append("  NOTE: heuristic posture, not a guarantee. A code signature on disk is NOT a")
    L.append("  defense — rea only READS it; value comes from a RUNTIME server-checked")
    L.append("  signature. __TEXT encryption is an Apple-platform control, not something this")
    L.append("  harness adds. Anti-RE raises cost; nothing here is unbreakable (CLAUDE.md §3).")
    L.append("=" * 68)
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Carapace Mach-O exposure audit (read-only).")
    ap.add_argument("binary")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        s = analyze(args.binary)
    except (MachOError, FileNotFoundError, IsADirectoryError) as e:
        print(f"audit error: {e}", file=sys.stderr)
        return 2
    print(json.dumps(s, indent=2) if args.json else render(s))
    return 0


if __name__ == "__main__":
    sys.exit(main())

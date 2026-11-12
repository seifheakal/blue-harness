#!/usr/bin/env python3
# Carapace — PE (Windows) exposure AUDIT scanner (Slice G).
#
# The Track-A sibling of elf_exposure_audit.py: a read-only scanner for a single
# Windows PE that reads the SAME signals an AI-assisted RE agent such as `rea`
# reads from its PE inspectors (inspect_binary_layout / inspect_pe_load_config /
# list_strings / inspect_byte_entropy) and reports a scored, tiered posture.
# Windows PE is the #1 commodity-cracking target, so this broadens the harness
# beyond ELF (CLAUDE.md §2). It NEVER modifies the target.
#
# HONESTY (CLAUDE.md §3): heuristic posture, not a guarantee. Note in particular
# (docs/re-techniques/rea.md): an Authenticode signature's presence on disk is NOT
# a defense — rea's inspect_pe_certificates only READS it, it does not verify. A
# signature only helps via a RUNTIME check that reports to a server.
#
# NO EXTERNAL DEPS: self-contained PE parser (no `pefile`), PE32 and PE32+.

import sys
import os
import math
import struct
import argparse
import json

# DllCharacteristics bits
DC_HIGH_ENTROPY_VA = 0x0020
DC_DYNAMIC_BASE    = 0x0040   # ASLR
DC_FORCE_INTEGRITY = 0x0080
DC_NX_COMPAT       = 0x0100   # DEP
DC_NO_SEH          = 0x0400
DC_GUARD_CF        = 0x4000   # Control Flow Guard

MACHINES = {0x8664: "x86-64", 0x014c: "x86", 0xAA64: "ARM64", 0x01c0: "ARM",
            0x0200: "IA64", 0x5032: "RISCV32", 0x5064: "RISCV64"}

PRINTABLE = set(range(0x20, 0x7F)) | {0x09}


class PEError(Exception):
    pass


class PE:
    def __init__(self, path):
        with open(path, "rb") as fh:
            self.data = fh.read()
        d = self.data
        if len(d) < 0x40 or d[:2] != b"MZ":
            raise PEError("not a PE/MZ file")
        self.e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if self.e_lfanew + 24 > len(d) or d[self.e_lfanew:self.e_lfanew + 4] != b"PE\x00\x00":
            raise PEError("no PE signature")
        coff = self.e_lfanew + 4
        (self.machine, self.num_sections, _ts, self.ptr_symtab, self.num_symbols,
         self.size_opt, self.characteristics) = struct.unpack_from("<HHIIIHH", d, coff)
        opt = coff + 20
        self.opt = opt
        self.magic = struct.unpack_from("<H", d, opt)[0]
        self.pe32plus = self.magic == 0x20B
        # DllCharacteristics sits at optional-header offset 0x46 for BOTH PE32/PE32+
        self.dll_char = struct.unpack_from("<H", d, opt + 0x46)[0]
        # Data directories: start at 0x60 (PE32) or 0x70 (PE32+); numbered count just before
        if self.pe32plus:
            self.num_dirs = struct.unpack_from("<I", d, opt + 0x6C)[0]
            dir_off = opt + 0x70
        else:
            self.num_dirs = struct.unpack_from("<I", d, opt + 0x5C)[0]
            dir_off = opt + 0x60
        self.dirs = []
        for i in range(min(self.num_dirs, 16)):
            rva, size = struct.unpack_from("<II", d, dir_off + i * 8)
            self.dirs.append((rva, size))
        # Sections
        sec_off = opt + self.size_opt
        self.sections = []
        for i in range(self.num_sections):
            base = sec_off + i * 40
            if base + 40 > len(d):
                break
            name = d[base:base + 8].rstrip(b"\x00").decode("latin-1", "replace")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", d, base + 8)
            char = struct.unpack_from("<I", d, base + 36)[0]
            self.sections.append({"name": name, "VirtualSize": vsize, "VirtualAddress": vaddr,
                                  "SizeOfRawData": rawsize, "PointerToRawData": rawptr,
                                  "Characteristics": char})

    def dir(self, i):
        return self.dirs[i] if i < len(self.dirs) else (0, 0)

    def rva_to_off(self, rva):
        for s in self.sections:
            va = s["VirtualAddress"]
            span = max(s["VirtualSize"], s["SizeOfRawData"])
            if va <= rva < va + span:
                off = rva - va + s["PointerToRawData"]
                return off if 0 <= off < len(self.data) else None
        return None

    def cstr(self, off, maxlen=512):
        if off is None or off < 0 or off >= len(self.data):
            return ""
        end = self.data.find(b"\x00", off, off + maxlen)
        if end < 0:
            end = min(off + maxlen, len(self.data))
        return self.data[off:end].decode("latin-1", "replace")

    def section_bytes(self, name):
        for s in self.sections:
            if s["name"] == name:
                o, n = s["PointerToRawData"], s["SizeOfRawData"]
                return self.data[o:o + n]
        return b""

    # -- imports (what rea's inspect reads) -------------------------------
    def imports(self, cap_dlls=32, cap_funcs=64):
        rva, size = self.dir(1)
        if not rva:
            return {}
        out = {}
        thunk_sz = 8 if self.pe32plus else 4
        ord_flag = (1 << 63) if self.pe32plus else (1 << 31)
        base = self.rva_to_off(rva)
        if base is None:
            return {}
        for i in range(cap_dlls):
            d = base + i * 20
            if d + 20 > len(self.data):
                break
            oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", self.data, d)
            if oft == 0 and name_rva == 0 and ft == 0:
                break
            dll = self.cstr(self.rva_to_off(name_rva)) or f"<rva:{name_rva:#x}>"
            funcs = []
            thunk_rva = oft or ft
            toff = self.rva_to_off(thunk_rva)
            j = 0
            while toff is not None and j < cap_funcs:
                if self.pe32plus:
                    val = struct.unpack_from("<Q", self.data, toff)[0]
                else:
                    val = struct.unpack_from("<I", self.data, toff)[0]
                if val == 0:
                    break
                if val & ord_flag:
                    funcs.append(f"#ordinal_{val & 0xFFFF}")
                else:
                    nm = self.cstr(self.rva_to_off((val & 0x7FFFFFFF) + 2))  # skip Hint(2)
                    funcs.append(nm or f"<rva:{val:#x}>")
                toff += thunk_sz
                j += 1
            out[dll] = funcs
        return out

    def export_count(self):
        rva, size = self.dir(0)
        if not rva:
            return 0
        off = self.rva_to_off(rva)
        if off is None or off + 24 > len(self.data):
            return 0
        return struct.unpack_from("<I", self.data, off + 24)[0]  # NumberOfNames


def shannon_entropy(buf):
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    n = len(buf)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def printable_density(buf):
    if not buf:
        return 0.0, 0
    run = 0
    in_runs = 0
    runs = 0
    for b in buf:
        if b in PRINTABLE:
            run += 1
        else:
            if run >= 4:
                in_runs += run
                runs += 1
            run = 0
    if run >= 4:
        in_runs += run
        runs += 1
    return in_runs / len(buf), runs


PACKER_SECTIONS = ("UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".petite",
                   "MPRESS1", "MPRESS2", ".themida", ".vmp0", ".vmp1", ".enigma1")


def analyze(path):
    pe = PE(path)
    d = pe.data

    dc = pe.dll_char
    hardening = {
        "aslr": bool(dc & DC_DYNAMIC_BASE),
        "dep_nx": bool(dc & DC_NX_COMPAT),
        "cfg": bool(dc & DC_GUARD_CF),
        "high_entropy_va": bool(dc & DC_HIGH_ENTROPY_VA),
        "force_integrity": bool(dc & DC_FORCE_INTEGRITY),
        "seh": not (dc & DC_NO_SEH),
    }

    symbols_present = pe.ptr_symtab != 0 and pe.num_symbols != 0
    debug_present = pe.dir(6)[1] > 0

    # strings over the read-heavy sections an agent mines
    str_target = pe.section_bytes(".rdata") + pe.section_bytes(".data")
    if not str_target:
        str_target = d
    str_density, str_runs = printable_density(str_target)
    low = d
    pdb_path = None
    idx = low.find(b".pdb")
    if idx >= 0:
        s = max(0, idx - 200)
        chunk = low[s:idx + 4]
        start = max((chunk.rfind(bytes([c])) for c in (0, 0x22) if chunk.rfind(bytes([c])) >= 0), default=-1)
        pdb_path = chunk[start + 1:].decode("latin-1", "replace")
        debug_present = True

    entropy_map = {}
    for s in pe.sections:
        b = d[s["PointerToRawData"]:s["PointerToRawData"] + s["SizeOfRawData"]]
        if b:
            entropy_map[s["name"] or "?"] = round(shannon_entropy(b), 3)
    whole_entropy = round(shannon_entropy(d), 3)
    high_entropy = any(v >= 7.2 for v in entropy_map.values()) or whole_entropy >= 7.4

    authenticode_present = pe.dir(4)[1] > 0        # Security dir — READ only, NOT verified
    dotnet = pe.dir(14)[1] > 0

    imports = pe.imports()
    if any(dll.lower() == "mscoree.dll" for dll in imports):
        dotnet = True
    import_count = sum(len(v) for v in imports.values())

    packer = [s["name"] for s in pe.sections if s["name"] in PACKER_SECTIONS]
    if high_entropy and not packer:
        packer.append("high-entropy (possible packing)")

    # Carapace post-build levers (overlay-resident; detected, never scored — they
    # are COST/DETECTION, not an exposure change). Mirrors the ELF guards section.
    decoy_overlay_present = b"__CARAPACE_PE_EXH_" in d
    honeytokens_present = b"__CARAPACE_PE_HONEY__" in d

    s = {
        "file": os.path.basename(path),
        "format": "PE32+" if pe.pe32plus else "PE32",
        "machine": MACHINES.get(pe.machine, f"{pe.machine:#06x}"),
        "symbols_present": symbols_present,
        "debug_info_present": debug_present,
        "pdb_path": pdb_path,
        "string_density": round(str_density, 4),
        "string_runs": str_runs,
        "entropy_map": entropy_map,
        "whole_file_entropy": whole_entropy,
        "high_entropy": high_entropy,
        "hardening": hardening,
        "authenticode_present": authenticode_present,
        "dotnet": dotnet,
        "packer": packer,
        "imports": {k: v[:16] for k, v in list(imports.items())[:16]},
        "import_count": import_count,
        "export_count": pe.export_count(),
        "decoy_overlay_present": decoy_overlay_present,
        "honeytokens_present": honeytokens_present,
    }
    s["score"], s["tier"], s["recommendation"] = score(s)
    return s


def score(s):
    pts = 0
    why = []
    h = s["hardening"]
    if not h["aslr"]:
        pts += 15; why.append("no ASLR (/DYNAMICBASE off)")
    if not h["dep_nx"]:
        pts += 12; why.append("no DEP/NX (/NXCOMPAT off)")
    if not h["cfg"]:
        pts += 10; why.append("no Control Flow Guard (/GUARD:CF off)")
    if not h["high_entropy_va"]:
        pts += 4; why.append("no high-entropy ASLR")
    if s["symbols_present"]:
        pts += 10; why.append("COFF symbol table present")
    if s["debug_info_present"]:
        pts += 15; why.append("debug directory / PDB path present")
    if s["string_density"] >= 0.05:
        pts += 15; why.append("high plaintext-string density")
    elif s["string_density"] >= 0.01:
        pts += 8; why.append("moderate plaintext-string density")
    if not s["authenticode_present"]:
        pts += 6; why.append("no Authenticode signature (note: on-disk signature is not itself a defense)")
    pts = min(pts, 100)
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
    if s["debug_info_present"] or s["symbols_present"]:
        return ("Strip the COFF symbol table + debug directory / PDB path "
                "(harness/harden/carapace_pe_strip.py). Tier: Speed-bump→Meaningful. "
                "Bypass: the agent reasons from imports/behavior without symbols.")
    if not (h["aslr"] and h["dep_nx"] and h["cfg"]):
        return ("Link with /DYNAMICBASE /NXCOMPAT /GUARD:CF /HIGHENTROPYVA. "
                "Tier: raises exploitation effort — it does NOT block decompilation.")
    if s["string_density"] >= 0.05:
        return ("Encrypt / decode-on-demand high-density plaintext strings "
                "(see harness/harden/carapace_string_encrypt.py). Tier: Speed-bump→Meaningful. "
                "Bypass: runtime key recovery.")
    if not s["authenticode_present"]:
        return ("Authenticode-sign AND verify at runtime server-side. Tier: Meaningful only WITH "
                "the runtime+server check — the signature on disk alone is read, not verified, by rea.")
    return ("Surface hardened. The only Strong tier is server-side relocation of secrets and trust "
            "decisions (CLAUDE.md §3).")


def render(s):
    h = s["hardening"]
    def yn(b, y="yes", n="no"):
        return y if b else n
    L = []
    L.append("=" * 68)
    L.append(f"  Carapace PE Exposure Audit — {s['file']}  [{s['format']} / {s['machine']}]")
    L.append("=" * 68)
    L.append(f"  EXPOSURE SCORE : {s['score']}/100")
    L.append(f"  POSTURE TIER   : {s['tier']}")
    L.append("")
    L.append("  Signals an AI-assisted RE agent (e.g. rea) reads for free:")
    L.append(f"    COFF symbols ........... {yn(s['symbols_present'],'PRESENT','absent')}")
    L.append(f"    debug dir / PDB ........ {yn(s['debug_info_present'],'PRESENT','absent')}"
             + (f"  ({s['pdb_path']})" if s['pdb_path'] else ""))
    L.append(f"    string density ......... {s['string_density']:.4f} ({s['string_runs']} runs >=4)")
    emap = ", ".join(f"{k}={v}" for k, v in s["entropy_map"].items()) or "n/a"
    L.append(f"    section entropy ........ {emap}  (whole={s['whole_file_entropy']})")
    L.append(f"    imports ................ {s['import_count']} funcs across {len(s['imports'])} DLL(s)")
    for dll, fns in list(s["imports"].items())[:4]:
        L.append(f"      {dll}: {', '.join(fns[:6])}{' …' if len(fns) > 6 else ''}")
    L.append(f"    .NET / packer .......... dotnet={yn(s['dotnet'])}; packer={', '.join(s['packer']) or 'none'}")
    L.append(f"    Carapace levers ........ decoy-overlay={yn(s.get('decoy_overlay_present', False))}; "
             f"honeytokens={yn(s.get('honeytokens_present', False))}  (post-build; COST/DETECTION, not scored)")
    L.append("")
    L.append("  Hardening flags (parity with rea's inspect_pe_load_config):")
    L.append(f"    ASLR={yn(h['aslr'])} | DEP/NX={yn(h['dep_nx'])} | CFG={yn(h['cfg'])} | "
             f"HighEntropyVA={yn(h['high_entropy_va'])} | SEH={yn(h['seh'])}")
    L.append(f"    Authenticode present (READ-ONLY, not verified): {yn(s['authenticode_present'])}")
    L.append("")
    L.append("  Exposure drivers:")
    for r in s["recommendation"]["exposure_drivers"]:
        L.append(f"    - {r}")
    L.append("")
    L.append("  NEXT HIGHEST-VALUE HARDENING:")
    L.append(f"    {s['recommendation']['next_hardening']}")
    L.append("")
    L.append("  NOTE: heuristic posture, not a guarantee. An Authenticode signature on disk is")
    L.append("  NOT a defense — rea only READS it; value comes from a RUNTIME server-checked")
    L.append("  signature. Anti-RE raises cost; nothing here is unbreakable (CLAUDE.md §3).")
    L.append("=" * 68)
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Carapace PE exposure audit (read-only).")
    ap.add_argument("binary")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        s = analyze(args.binary)
    except (PEError, FileNotFoundError, IsADirectoryError) as e:
        print(f"audit error: {e}", file=sys.stderr)
        return 2
    print(json.dumps(s, indent=2) if args.json else render(s))
    return 0


if __name__ == "__main__":
    sys.exit(main())

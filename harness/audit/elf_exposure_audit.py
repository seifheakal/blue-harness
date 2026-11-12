#!/usr/bin/env python3
# Carapace — ELF exposure AUDIT scanner (audit before harden; CLAUDE.md §8)
#
# WHAT THIS IS
#   A read-only exposure scanner for a single Linux ELF. It reads the *same
#   signals* an AI-assisted RE agent such as `rea` reads from its static
#   inspectors (list_names / list_strings / inspect_binary_layout /
#   inspect_byte_entropy / the Go/Rust/PyInstaller inspectors) and reports a
#   scored, tiered exposure posture plus the next highest-value hardening.
#   See docs/re-techniques/rea.md (Cluster B/C, E, G/H) for the mapping.
#
#   It NEVER modifies the target. Harden lives in ../harden; verify in ../verify.
#
# HONESTY (CLAUDE.md §3)
#   This is a *heuristic posture* report, not a guarantee. "Guard present" here
#   means "the binary references the syscalls / reads the files that guard uses"
#   — the same inference the attacker's agent makes from symbols and strings.
#   Whether a guard is wired correctly and actually *fires* is proven by the
#   tests in ../verify, not by this scanner. No score here means "unbreakable."
#
# NO EXTERNAL DEPS: self-contained pure-Python ELF parser (no pyelftools), so
#   the audit runs anywhere Python 3 does and cannot be fooled by a missing
#   readelf. Big/little endian + ELF32/64 supported; x86-64 LE is the tested path.

import sys
import os
import json
import math
import struct
import argparse

# ---- ELF constants -------------------------------------------------------
PT_INTERP      = 3
PT_DYNAMIC     = 2
PT_GNU_STACK   = 0x6474E551
PT_GNU_RELRO   = 0x6474E552

ET_EXEC        = 2
ET_DYN         = 3

SHT_SYMTAB     = 2
SHT_DYNSYM     = 11

SHN_UNDEF      = 0
STT_OBJECT     = 1
STT_FUNC       = 2

# dynamic tags
DT_NULL        = 0
DT_BIND_NOW    = 24
DT_FLAGS       = 30
DT_FLAGS_1     = 0x6FFFFFFB
DF_BIND_NOW    = 0x08
DF_1_NOW       = 0x00000001

PF_X           = 0x1

PRINTABLE = set(range(0x20, 0x7F)) | {0x09}


class ELFError(Exception):
    pass


class ELF:
    """Minimal, defensive ELF reader. Parses what the audit needs and no more."""

    def __init__(self, path):
        with open(path, "rb") as fh:
            self.data = fh.read()
        self.path = path
        d = self.data
        if len(d) < 64 or d[:4] != b"\x7fELF":
            raise ELFError("not an ELF file")
        self.ei_class = d[4]            # 1=32, 2=64
        self.ei_data = d[5]             # 1=LE, 2=BE
        self.is64 = self.ei_class == 2
        self.end = "<" if self.ei_data == 1 else ">"
        self._parse_header()
        self._parse_phdrs()
        self._parse_shdrs()

    # -- header ------------------------------------------------------------
    def _u(self, fmt, off):
        sz = struct.calcsize(self.end + fmt)
        return struct.unpack_from(self.end + fmt, self.data, off)[0] if sz else 0

    def _parse_header(self):
        self.e_type = self._u("H", 16)
        if self.is64:
            self.e_phoff = self._u("Q", 32)
            self.e_shoff = self._u("Q", 40)
            self.e_phentsize = self._u("H", 54)
            self.e_phnum = self._u("H", 56)
            self.e_shentsize = self._u("H", 58)
            self.e_shnum = self._u("H", 60)
            self.e_shstrndx = self._u("H", 62)
        else:
            self.e_phoff = self._u("I", 28)
            self.e_shoff = self._u("I", 32)
            self.e_phentsize = self._u("H", 42)
            self.e_phnum = self._u("H", 44)
            self.e_shentsize = self._u("H", 46)
            self.e_shnum = self._u("H", 48)
            self.e_shstrndx = self._u("H", 50)

    # -- program headers ---------------------------------------------------
    def _parse_phdrs(self):
        self.phdrs = []
        for i in range(self.e_phnum):
            base = self.e_phoff + i * self.e_phentsize
            if base + self.e_phentsize > len(self.data):
                break
            if self.is64:
                p_type = self._u("I", base + 0)
                p_flags = self._u("I", base + 4)
            else:
                p_type = self._u("I", base + 0)
                p_flags = self._u("I", base + 24)
            self.phdrs.append({"type": p_type, "flags": p_flags})

    # -- section headers ---------------------------------------------------
    def _parse_shdrs(self):
        self.sections = {}      # name -> dict
        self._sections_by_idx = []
        if self.e_shoff == 0 or self.e_shnum == 0:
            return
        raw = []
        for i in range(self.e_shnum):
            base = self.e_shoff + i * self.e_shentsize
            if base + self.e_shentsize > len(self.data):
                break
            if self.is64:
                sh = {
                    "name_off": self._u("I", base + 0),
                    "type": self._u("I", base + 4),
                    "flags": self._u("Q", base + 8),
                    "offset": self._u("Q", base + 24),
                    "size": self._u("Q", base + 32),
                    "link": self._u("I", base + 40),
                    "entsize": self._u("Q", base + 56),
                }
            else:
                sh = {
                    "name_off": self._u("I", base + 0),
                    "type": self._u("I", base + 4),
                    "flags": self._u("I", base + 8),
                    "offset": self._u("I", base + 16),
                    "size": self._u("I", base + 20),
                    "link": self._u("I", base + 24),
                    "entsize": self._u("I", base + 36),
                }
            raw.append(sh)
        self._sections_by_idx = raw
        # resolve names via shstrtab
        if self.e_shstrndx < len(raw):
            strtab = self._blob(raw[self.e_shstrndx])
            for sh in raw:
                sh["name"] = self._cstr(strtab, sh["name_off"])
                self.sections[sh["name"]] = sh

    def _blob(self, sh):
        off, size = sh["offset"], sh["size"]
        if sh["type"] == 8:  # SHT_NOBITS has no file bytes
            return b""
        return self.data[off:off + size]

    @staticmethod
    def _cstr(buf, off):
        end = buf.find(b"\x00", off)
        if end < 0:
            end = len(buf)
        try:
            return buf[off:end].decode("utf-8", "replace")
        except Exception:
            return ""

    # -- helpers used by the audit ----------------------------------------
    def has_phdr(self, p_type):
        return any(p["type"] == p_type for p in self.phdrs)

    def phdr(self, p_type):
        for p in self.phdrs:
            if p["type"] == p_type:
                return p
        return None

    def section_bytes(self, name):
        sh = self.sections.get(name)
        return self._blob(sh) if sh else b""

    def symbol_names(self):
        """Union of names from .dynsym and .symtab (imports + local)."""
        names = set()
        for symname, strname in ((".dynsym", ".dynstr"), (".symtab", ".strtab")):
            sh = self.sections.get(symname)
            st = self.sections.get(strname)
            if not sh or not st:
                continue
            strblob = self._blob(st)
            symblob = self._blob(sh)
            entsize = sh["entsize"] or (24 if self.is64 else 16)
            if entsize <= 0:
                continue
            for off in range(0, len(symblob) - entsize + 1, entsize):
                name_off = struct.unpack_from(self.end + "I", symblob, off)[0]
                nm = self._cstr(strblob, name_off)
                if nm:
                    names.add(nm)
        return names

    def iter_symbols(self):
        """Yield {name,type,shndx} from .symtab (preferred) or .dynsym.
        Field order differs between ELF32 and ELF64 — both handled."""
        for symname, strname in ((".symtab", ".strtab"), (".dynsym", ".dynstr")):
            sh = self.sections.get(symname)
            st = self.sections.get(strname)
            if not sh or not st:
                continue
            strblob = self._blob(st)
            symblob = self._blob(sh)
            entsize = sh["entsize"] or (24 if self.is64 else 16)
            if entsize <= 0:
                continue
            for off in range(0, len(symblob) - entsize + 1, entsize):
                name_off = struct.unpack_from(self.end + "I", symblob, off)[0]
                if self.is64:
                    info = symblob[off + 4]
                    shndx = struct.unpack_from(self.end + "H", symblob, off + 6)[0]
                else:
                    info = symblob[off + 12]
                    shndx = struct.unpack_from(self.end + "H", symblob, off + 14)[0]
                yield {
                    "name": self._cstr(strblob, name_off),
                    "type": info & 0xF,
                    "shndx": shndx,
                }
            return  # .symtab wins; don't also walk .dynsym

    def dynamic_flags(self):
        sh = self.sections.get(".dynamic")
        flags = 0
        flags1 = 0
        bind_now = False
        if not sh:
            return {"DT_FLAGS": 0, "DT_FLAGS_1": 0, "bind_now": False}
        blob = self._blob(sh)
        step = 16 if self.is64 else 8
        rd = (lambda o: struct.unpack_from(self.end + "q", blob, o)[0]) if self.is64 \
            else (lambda o: struct.unpack_from(self.end + "i", blob, o)[0])
        for off in range(0, len(blob) - step + 1, step):
            tag = rd(off)
            val = rd(off + step // 2)
            if tag == DT_NULL:
                break
            if tag == DT_FLAGS:
                flags = val
            elif tag == DT_FLAGS_1:
                flags1 = val
            elif tag == DT_BIND_NOW:
                bind_now = True
        if flags & DF_BIND_NOW or flags1 & DF_1_NOW:
            bind_now = True
        return {"DT_FLAGS": flags, "DT_FLAGS_1": flags1, "bind_now": bind_now}


# ---- signal extraction ---------------------------------------------------
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
    """Fraction of bytes that belong to a printable run of length >= 4.
    This is the 'free intel' an agent's list_strings harvests."""
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


# ---- identifier / string informativeness (Slice B) -----------------------
# How much free, *human-readable* intel the binary hands an LLM agent, which
# forms hypotheses primarily from names and strings. This is a heuristic signal,
# labeled as such — not a guarantee (CLAUDE.md §3). It does NOT feed the main
# exposure score (that keeps Slice A's test invariant stable); it is reported on
# its own so the dev->release identity transform can be measured.
import re as _re

# Compact, honest heuristic wordlist: "does this identifier read as English?"
_WORDS = set("""
get set init start stop run main loop check verify validate compute calc hash
encrypt decrypt encode decode parse format print read write open close load save
config license key token session user auth login logout sign signature cert
telemetry flush buffer handler callback request response client server socket
connect send recv message packet header payload length size count index value
string char byte word data file path name list table entry node tree map array
alloc free copy move swap compare sort search find insert remove update delete
error warn info debug trace log level status state flag mode type class object
build prod release version patch slot region secret private public master sample
guard protect detect scan monitor report score audit harden checksum license
""".split())

# Compiler/CRT symbols that aren't app-authored identity (noise for this metric).
_CRT_DENY = {
    "register_tm_clones", "deregister_tm_clones", "frame_dummy",
    "completed", "do_global_dtors_aux", "abi_tag",
    "stdout", "stderr", "stdin",
}


def _split_ident(name):
    s = name.lstrip("_")
    parts = _re.split(r"[_.$0-9]+", s)
    out = []
    for p in parts:
        out += _re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+", p)
    return [t.lower() for t in out if t]


def is_informative_name(name):
    """True if the identifier reads like English/domain words (free intel),
    False if it reads as opaque (sub_401000, cp_000001, a)."""
    toks = _split_ident(name)
    if any(len(t) >= 3 and t in _WORDS for t in toks):
        return True
    wordish = [t for t in toks if len(t) >= 3 and any(c in "aeiou" for c in t)]
    return len(wordish) >= 2


def extract_runs(buf, minlen=4):
    out, cur = [], bytearray()
    for b in buf:
        if b in PRINTABLE:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii", "replace"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "replace"))
    return out


def own_symbols(elf):
    """The binary's own defined FUNC/OBJECT symbols — the app-authored identity
    an agent reads as logic (libc imports, versioned and CRT symbols excluded).
    Shared by the audit and the identity transform so both agree on scope."""
    own = []
    seen = set()
    for s in elf.iter_symbols():
        n = s["name"]
        if not n or n in seen or s["shndx"] == SHN_UNDEF:
            continue
        if s["type"] not in (STT_FUNC, STT_OBJECT):
            continue
        if "@" in n or n.startswith("_"):      # versioned/libc imports, compiler internals
            continue
        if n.split(".")[0] in _CRT_DENY:        # drop compiler-local suffix (completed.0)
            continue
        own.append(n)
        seen.add(n)
    return own


def informativeness(elf, str_target):
    own = own_symbols(elf)
    total = len(own)
    inform = [n for n in own if is_informative_name(n)]
    ratio = round(len(inform) / total, 4) if total else 0.0

    # informative strings: messages / format strings / URLs / worded tokens
    runs = extract_runs(str_target)
    istr = 0
    for r in runs:
        rl = r.lower()
        if "%" in r or " " in r or "://" in r or \
                any(w in rl for w in _WORDS if len(w) >= 4):
            istr += 1

    return {
        "symbol_total": total,
        "symbol_informative": len(inform),
        "symbol_informative_ratio": ratio,
        "informative_strings": istr,
        "sample_symbols": sorted(own)[:12],
    }


def analyze(path):
    elf = ELF(path)
    syms = elf.symbol_names()
    dyn = elf.dynamic_flags()

    # --- hardening flags (same ones rea's inspect_* reads) ---------------
    # PIE
    if elf.e_type == ET_DYN and elf.has_phdr(PT_INTERP):
        pie = "PIE"
    elif elf.e_type == ET_DYN:
        pie = "DYN (shared/static-pie)"
    else:
        pie = "No-PIE (ET_EXEC)"

    # NX (executable stack?)
    gs = elf.phdr(PT_GNU_STACK)
    if gs is None:
        nx = "not marked (assumed NX)"
    elif gs["flags"] & PF_X:
        nx = "DISABLED (exec stack)"
    else:
        nx = "enabled"

    # RELRO
    if not elf.has_phdr(PT_GNU_RELRO):
        relro = "none"
    elif dyn["bind_now"]:
        relro = "full"
    else:
        relro = "partial"

    canary = ("__stack_chk_fail" in syms) or ("__stack_chk_guard" in syms)
    cet = ".note.gnu.property" in elf.sections  # IBT/SHSTK note (heuristic)

    # --- symbols / debug info --------------------------------------------
    symbols_present = ".symtab" in elf.sections
    debug_info_present = any(
        n.startswith(".debug_") or n.startswith(".zdebug_") or n == ".gnu_debuglink"
        for n in elf.sections
    )

    # --- strings density (over the read-heavy sections an agent mines) ---
    str_target = b""
    for s in (".rodata", ".data", ".data.rel.ro"):
        str_target += elf.section_bytes(s)
    if not str_target:                      # fall back to whole file
        str_target = elf.data
    str_density, str_runs = printable_density(str_target)

    # --- section entropy map ---------------------------------------------
    entropy_map = {}
    for name in (".text", ".rodata", ".data"):
        b = elf.section_bytes(name)
        if b:
            entropy_map[name] = round(shannon_entropy(b), 3)
    whole_entropy = round(shannon_entropy(elf.data), 3)
    high_entropy = any(v >= 7.2 for v in entropy_map.values()) or whole_entropy >= 7.4

    # --- toolchain / packer metadata -------------------------------------
    blob_lower = elf.data  # byte search
    meta = []
    if ".go.buildinfo" in elf.sections or b"Go build ID" in blob_lower or \
            any(n.startswith("runtime.") for n in syms):
        meta.append("Go")
    if b"cargo-auditable" in blob_lower or b"rustc/" in blob_lower or \
            b"/rust/" in blob_lower or b"RUST_BACKTRACE" in blob_lower:
        meta.append("Rust")
    if b"PyInstaller" in blob_lower or b"_MEIPASS" in blob_lower or b"pyi-" in blob_lower:
        meta.append("PyInstaller")
    if b"UPX!" in blob_lower:
        meta.append("UPX-packed")

    # --- the guard-presence signals (the audit<->harden flip) ------------
    # Heuristic: the binary *references* the syscalls / files the guard uses.
    # This mirrors what rea's list_names / list_strings would surface.
    coredump_guard_present = ("setrlimit" in syms) and ("prctl" in syms)
    antiptrace_guard_present = (
        ("ptrace" in syms)
        or (b"/proc/self/status" in blob_lower and b"TracerPid" in blob_lower)
    )
    # Runtime code-integrity / attestation: our guard symbols, or a SHA-256
    # implementation tell (the first two FIPS 180-4 round constants, LE bytes).
    sha256_tell = (b"\x98\x2f\x8a\x42" in blob_lower) and (b"\x91\x44\x37\x71" in blob_lower)
    integrity_guard_present = (
        ("carapace_hotfn_checksum" in syms) or ("carapace_integrity_response" in syms)
        or sha256_tell
    )
    # Anti-Frida detector: our scan symbol, or the Frida signature strings it embeds.
    antifrida_guard_present = (
        ("carapace_antifrida_scan" in syms)
        or (b"gum-js-loop" in blob_lower) or (b"frida-agent" in blob_lower)
    )
    # Build-time string encryption: the enc-mode marker symbol (a name, not a
    # plaintext tell). The loader alone isn't enough — a plaintext build also
    # links it; only the encrypted build carries this marker.
    string_encryption_present = "carapace_strings_enc" in syms

    # Build-time analysis-surface EXHAUSTION (Slice I). Our decoy non-alloc
    # sections (SHF_ALLOC clear -> never mapped at runtime) and synthetic LOCAL
    # FUNC symbols balloon the inventory a naive "ingest everything" AI-RE agent
    # must read, while runtime behaviour is byte-identical. Detection keys on our
    # markers; the ratio is a measurement, not a claim.
    SHF_ALLOC = 0x2
    SHT_PROGBITS = 1
    exh_sections = [sh for name, sh in elf.sections.items()
                    if name.startswith(".carapace_exh")]
    exh_decoy_bytes = sum(sh["size"] for sh in exh_sections)
    exh_synth_symbols = sum(1 for s in elf.iter_symbols()
                            if s["name"].startswith("carapace_exh_"))
    # general static-surface inflation: PROGBITS sections NOT mapped into memory
    # (flags lack SHF_ALLOC) as a fraction of the whole file. Baseline carries a
    # little (.comment); our pass drives it up.
    nonalloc_bytes = sum(sh["size"] for sh in elf.sections.values()
                         if sh["type"] == SHT_PROGBITS and not (sh["flags"] & SHF_ALLOC))
    nonalloc_ratio = round(nonalloc_bytes / max(1, len(elf.data)), 4)
    exhaustion_present = bool(exh_sections) or exh_synth_symbols > 0

    # Honeytokens / canaries (Slice J). Plausible fake secrets an AI-RE agent
    # surfaces as "findings" (poison) and that double as an attribution tripwire
    # if one leaks. Harness default section name is the tell; production renames
    # it (so detection here is a convenience, not the defense — see honey README).
    honey_blob = elf.section_bytes(".carapace_honey")
    honeytoken_count = sum(1 for ln in honey_blob.split(b"\n") if ln.strip())
    honeytokens_present = honeytoken_count > 0

    signals = {
        "file": os.path.basename(path),
        "arch": ("ELF64" if elf.is64 else "ELF32") + ("-LE" if elf.ei_data == 1 else "-BE"),
        "symbols_present": symbols_present,
        "debug_info_present": debug_info_present,
        "string_density": round(str_density, 4),
        "string_runs": str_runs,
        "entropy_map": entropy_map,
        "whole_file_entropy": whole_entropy,
        "high_entropy": high_entropy,
        "hardening": {
            "pie": pie, "nx": nx, "relro": relro,
            "canary": canary, "cet_note": cet,
        },
        "toolchain_metadata": meta,
        "coredump_guard_present": coredump_guard_present,
        "antiptrace_guard_present": antiptrace_guard_present,
        "integrity_guard_present": integrity_guard_present,
        "antifrida_guard_present": antifrida_guard_present,
        "string_encryption_present": string_encryption_present,
        "exhaustion_present": exhaustion_present,
        "exhaust_decoy_bytes": exh_decoy_bytes,
        "exhaust_synth_symbols": exh_synth_symbols,
        "nonalloc_byte_ratio": nonalloc_ratio,
        "honeytokens_present": honeytokens_present,
        "honeytoken_count": honeytoken_count,
        "informativeness": informativeness(elf, str_target),
    }
    signals["score"], signals["tier"], signals["recommendation"] = score(signals)
    return signals


# ---- scoring (honest, heuristic) -----------------------------------------
# Exposure points: higher = more free intel / less resistance for an RE agent.
# This is a *relative posture indicator*, never a guarantee (CLAUDE.md §3).
def score(s):
    pts = 0
    reasons = []
    if s["symbols_present"]:
        pts += 25; reasons.append("unstripped symbols (.symtab)")
    if s["debug_info_present"]:
        pts += 20; reasons.append("debug info (DWARF) present")
    if s["string_density"] >= 0.05:
        pts += 15; reasons.append("high plaintext-string density")
    elif s["string_density"] >= 0.01:
        pts += 8; reasons.append("moderate plaintext-string density")
    if not s["coredump_guard_present"]:
        pts += 12; reasons.append("no core-dump suppression guard")
    if not s["antiptrace_guard_present"]:
        pts += 12; reasons.append("no anti-debug / anti-ptrace guard")
    h = s["hardening"]
    if h["relro"] != "full":
        pts += 4; reasons.append("RELRO not full")
    if not h["canary"]:
        pts += 4; reasons.append("no stack canary")
    if h["pie"].startswith("No-PIE"):
        pts += 4; reasons.append("No-PIE")
    if h["nx"].startswith("DISABLED"):
        pts += 4; reasons.append("executable stack (NX off)")

    pts = min(pts, 100)
    # Tier bands name the *exposure*, honestly. These describe how much an
    # AI-assisted agent gets for free — not that any state is "safe".
    if pts >= 70:
        tier = "WIDE-OPEN (trivial for an AI-assisted agent)"
    elif pts >= 45:
        tier = "EXPOSED (speed-bump at best)"
    elif pts >= 20:
        tier = "PARTIALLY HARDENED (meaningful cost added)"
    else:
        tier = "HARDENED SURFACE (cost raised; never unbreakable)"

    # next highest-value hardening (audit-first → point at the cheapest win)
    rec = recommend(s)
    return pts, tier, {"exposure_drivers": reasons, "next_hardening": rec}


def recommend(s):
    # ordered by value/cost per docs/re-techniques/rea.md
    if s["symbols_present"] or s["debug_info_present"]:
        return ("Strip symbols + debug info (Cluster B/C). Tier: Meaningful. "
                "Bypass: library/pattern signatures + behavioral reasoning.")
    if not s["coredump_guard_present"]:
        return ("Add core-dump suppression guard — setrlimit(RLIMIT_CORE,0) + "
                "prctl(PR_SET_DUMPABLE,0) (denies rea Cluster E / inspect_recorded_crash). "
                "Tier: Speed-bump. Bypass: attacker enables cores on their own host, "
                "or reads live memory via Frida/GDB.")
    if not s["antiptrace_guard_present"]:
        return ("Add anti-ptrace guard — PTRACE_TRACEME + /proc/self/status TracerPid poll "
                "(denies rea Cluster G Frida-attach / Cluster H GDB). Tier: Meaningful. "
                "Bypass: Frida can hook the check; spawn-paused loads a bypass first.")
    if s["string_density"] >= 0.05:
        return ("Encrypt / decode-on-demand the high-density plaintext strings "
                "(Cluster B/C). Tier: Speed-bump→Meaningful. Bypass: runtime key recovery.")
    if s["hardening"]["relro"] != "full":
        return ("Link with full RELRO + BIND_NOW (-Wl,-z,relro,-z,now). "
                "Tier: raises effort, not a decompile blocker.")
    return ("Core surface hardened. Next front is server-side relocation of secrets "
            "and trust decisions — the only *Strong* tier (CLAUDE.md §3).")


# ---- reporting -----------------------------------------------------------
def render(s):
    h = s["hardening"]
    def yn(b, yes="PRESENT", no="absent"):
        return yes if b else no
    L = []
    L.append("=" * 68)
    L.append(f"  Carapace ELF Exposure Audit — {s['file']}  [{s['arch']}]")
    L.append("=" * 68)
    L.append(f"  EXPOSURE SCORE : {s['score']}/100")
    L.append(f"  POSTURE TIER   : {s['tier']}")
    L.append("")
    L.append("  Signals an AI-assisted RE agent (e.g. rea) reads for free:")
    L.append(f"    symbols (.symtab) ...... {yn(s['symbols_present'])}")
    L.append(f"    debug info (DWARF) ..... {yn(s['debug_info_present'])}")
    L.append(f"    string density ......... {s['string_density']:.4f} "
             f"({s['string_runs']} runs >=4 chars)")
    emap = ", ".join(f"{k}={v}" for k, v in s["entropy_map"].items()) or "n/a"
    L.append(f"    section entropy ........ {emap}  (whole={s['whole_file_entropy']})")
    if s["high_entropy"]:
        L.append("                             ^ high entropy — possible packing/encryption")
    L.append(f"    toolchain metadata ..... {', '.join(s['toolchain_metadata']) or 'none detected'}")
    inf = s["informativeness"]
    L.append("")
    L.append("  Identifier / string informativeness (free intel for an LLM agent):")
    L.append(f"    own named symbols ...... {inf['symbol_total']} "
             f"({inf['symbol_informative']} read as English words, "
             f"ratio={inf['symbol_informative_ratio']})")
    L.append(f"    informative strings .... {inf['informative_strings']} "
             "(messages / formats / URLs / worded tokens)")
    if inf["sample_symbols"]:
        L.append(f"    e.g. {', '.join(inf['sample_symbols'][:8])}")
    L.append("")
    L.append("  Hardening flags (parity with rea's inspect_binary_layout):")
    L.append(f"    PIE={h['pie']} | NX={h['nx']} | RELRO={h['relro']} | "
             f"canary={yn(h['canary'],'yes','no')} | CET-note={yn(h['cet_note'],'yes','no')}")
    L.append("")
    L.append("  Self-defense guards (the audit<->harden flip):")
    L.append(f"    core-dump suppression .. {yn(s['coredump_guard_present'])}"
             "   (vs rea Cluster E / inspect_recorded_crash)")
    L.append(f"    anti-ptrace / anti-dbg . {yn(s['antiptrace_guard_present'])}"
             "   (vs rea Cluster G Frida-attach + Cluster H GDB)")
    L.append(f"    code-integrity/attest .. {yn(s['integrity_guard_present'])}"
             "   (vs rea Cluster G patch; server-nonce = →Strong)")
    L.append(f"    anti-Frida detector .... {yn(s['antifrida_guard_present'])}"
             "   (vs rea Cluster G Frida inject)")
    L.append(f"    string encryption ...... {yn(s['string_encryption_present'])}"
             "   (vs rea Cluster B/C list_strings)")
    L.append(f"    analysis exhaustion .... {yn(s['exhaustion_present'])}"
             f"   (decoy {s['exhaust_decoy_bytes']}B + {s['exhaust_synth_symbols']} synth syms; "
             f"non-alloc {s['nonalloc_byte_ratio']})")
    L.append(f"    honeytokens / canaries . {yn(s['honeytokens_present'])}"
             f"   ({s['honeytoken_count']} planted; poison + attribution tripwire)")
    L.append("")
    L.append("  Exposure drivers:")
    for r in s["recommendation"]["exposure_drivers"]:
        L.append(f"    - {r}")
    L.append("")
    L.append("  NEXT HIGHEST-VALUE HARDENING:")
    L.append(f"    {s['recommendation']['next_hardening']}")
    L.append("")
    L.append("  NOTE: heuristic posture, not a guarantee. 'Guard PRESENT' means the")
    L.append("  binary references that guard's syscalls/strings — the same inference")
    L.append("  the attacker's agent makes. Proof a guard *fires* is in ../verify.")
    L.append("  Anti-RE raises cost; nothing here is unbreakable (CLAUDE.md §3).")
    L.append("=" * 68)
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Carapace ELF exposure audit (read-only).")
    ap.add_argument("binary", help="path to the ELF to audit")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON only")
    args = ap.parse_args(argv)
    try:
        s = analyze(args.binary)
    except (ELFError, FileNotFoundError, IsADirectoryError) as e:
        print(f"audit error: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(s, indent=2))
    else:
        print(render(s))
    return 0


if __name__ == "__main__":
    sys.exit(main())

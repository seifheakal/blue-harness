#!/usr/bin/env python3
# Carapace — shared Mach-O harden mechanism (Slice Q).
#
# Two primitives the Mach-O harden levers (exhaust / honeytokens) are built on, both
# proven byte-level with NO macOS host (CLAUDE.md §3 — runtime acceptance is
# platform-gated, like the Slice O strip and the Slice P PE path):
#
#   append_trailer(data, payload)
#       Append decoy/honey bytes at the original EOF — past every segment/section/table
#       the file declares (`mapped_end`). dyld maps only each LC_SEGMENT's
#       [fileoff, fileoff+filesize); bytes past all of them are described by no segment,
#       so the loader never maps them (the Mach-O analog of the PE overlay). A
#       whole-file strings/entropy sweep still reads them. Append-only: the original
#       file is a byte-identical PREFIX.
#
#   add_decoy_segment(data, segname)
#       Splice a real LC_SEGMENT_64 with vmsize = 0 (initprot = maxprot = 0, nsects = 0)
#       into the zero HEADER PAD in place — a genuine added load command that dyld
#       IGNORES (a vmsize==0 segment reserves no address space → maps nothing; Apple
#       XNU loader.h + dyld ImageLoaderMachO). Needs >= 72 B of pad (ld64's default is
#       32 B; a target wants -headerpad_max_install_names). When there is not enough
#       pad we DO NOT corrupt the file — we return it unchanged with load_command_added
#       = False and the caller falls back to a trailer-only decoy, honestly reported.
#
# Scope: thin 64-bit Mach-O. Fat/universal and 32-bit are refused with guidance
# (harden each thin slice separately). See research/findings/2026-11-13-macho-harden-levers.md.

import struct

MAGICS = {b"\xcf\xfa\xed\xfe": ("<", True), b"\xfe\xed\xfa\xcf": (">", True),
          b"\xce\xfa\xed\xfe": ("<", False), b"\xfe\xed\xfa\xce": (">", False)}
FAT_MAGICS = {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}

LC_REQ_DYLD = 0x80000000
LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C

SEG64_CMDSIZE = 72          # segment_command_64 with nsects = 0


class SegError(Exception):
    pass


class MachOView:
    """Minimal read model: endianness, the mach-header counts, segments/sections,
    the symtab/codesig/encryption file ranges, the header-pad slack, and mapped_end."""

    def __init__(self, data):
        self.d = bytearray(data)
        head = bytes(self.d[:4])
        if head in FAT_MAGICS:
            raise SegError("fat/universal Mach-O: harden each thin slice separately (not supported here)")
        if head not in MAGICS:
            raise SegError("not a thin Mach-O")
        self.e, self.is64 = MAGICS[head]
        if not self.is64:
            raise SegError("32-bit Mach-O: the decoy-segment splice supports 64-bit only "
                           "(the common case); refusing rather than guessing a 32-bit layout")
        self.hdr = 32
        self.ncmds = self._u("I", 16)
        self.sizeofcmds = self._u("I", 20)
        self.segnames = []
        self.code_sig = False
        self._content_offs = []     # file offsets of real, post-LC content (to size slack)
        self._ends = [0]            # file-range ends (to compute mapped_end)
        self._scan()

    def _u(self, fmt, off):
        return struct.unpack_from(self.e + fmt, self.d, off)[0]

    def _scan(self):
        off = self.hdr
        for _ in range(self.ncmds):
            if off + 8 > len(self.d):
                break
            cmd = self._u("I", off) & ~LC_REQ_DYLD
            sz = self._u("I", off + 4)
            if sz < 8:
                break
            if cmd == LC_SEGMENT_64:
                segname = bytes(self.d[off + 8:off + 24]).split(b"\x00")[0].decode("latin-1")
                self.segnames.append(segname)
                fileoff = self._u("Q", off + 40)
                filesize = self._u("Q", off + 48)
                if filesize:
                    self._ends.append(fileoff + filesize)
                    if fileoff:
                        self._content_offs.append(fileoff)
                nsects = self._u("I", off + 64)
                sec = off + 72
                for i in range(nsects):
                    so = sec + i * 80
                    size = self._u("Q", so + 40)
                    foff = self._u("I", so + 48)
                    if size and foff:
                        self._ends.append(foff + size)
                        self._content_offs.append(foff)
            elif cmd == LC_SYMTAB:
                symoff = self._u("I", off + 8)
                nsyms = self._u("I", off + 12)
                stroff = self._u("I", off + 16)
                strsize = self._u("I", off + 20)
                if nsyms and symoff:
                    self._ends.append(symoff + nsyms * 16)
                    self._content_offs.append(symoff)
                if strsize and stroff:
                    self._ends.append(stroff + strsize)
                    self._content_offs.append(stroff)
            elif cmd == LC_CODE_SIGNATURE:
                self.code_sig = True
                dataoff = self._u("I", off + 8)
                datasize = self._u("I", off + 12)
                if datasize and dataoff:
                    self._ends.append(dataoff + datasize)
                    self._content_offs.append(dataoff)
            elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                cryptoff = self._u("I", off + 8)
                cryptsize = self._u("I", off + 12)
                if cryptsize and cryptoff:
                    self._ends.append(cryptoff + cryptsize)
                    self._content_offs.append(cryptoff)
            off += sz
        self.lc_end = self.hdr + self.sizeofcmds

    def mapped_end(self):
        """Highest file offset the loader/linker reads from the file (end of every
        segment/section/table). A trailer appended past this is non-mapped."""
        return max(self._ends)

    def header_slack(self):
        """Zero bytes available between the end of the load commands and the first
        real content — the room an in-place load-command splice can consume."""
        after = [o for o in self._content_offs if o >= self.lc_end]
        first_content = min(after) if after else len(self.d)
        return first_content - self.lc_end


def parse(data):
    return MachOView(data)


def append_trailer(data, payload):
    """Append `payload` at EOF (past mapped_end → non-mapped). Returns (out, info)."""
    v = MachOView(data)
    trailer_off = len(data)
    me = v.mapped_end()
    out = bytes(data) + bytes(payload)
    return out, {
        "trailer_off": trailer_off,
        "trailer_bytes": len(payload),
        "mapped_end": me,
        "non_mapped": trailer_off >= me,
        "code_signed": v.code_sig,
    }


def add_decoy_segment(data, segname):
    """Splice a vmsize=0 LC_SEGMENT_64 named `segname` into the header pad in place.
    Returns (out, info). If there is < 72 B of zero pad, returns the input unchanged
    with load_command_added = False and a reason (caller falls back to trailer-only)."""
    v = MachOView(data)
    name = segname.encode("latin-1")
    if len(name) > 16:
        raise SegError(f"segment name too long (max 16 bytes): {segname!r}")
    slack = v.header_slack()
    info = {
        "load_command_added": False,
        "segname": segname,
        "cmdsize": SEG64_CMDSIZE,
        "slack": slack,
        "code_signed": v.code_sig,
        "vmsize": 0,
    }
    if slack < SEG64_CMDSIZE:
        info["reason"] = (f"insufficient header pad ({slack} B < {SEG64_CMDSIZE} B); relink with "
                          "-headerpad_max_install_names to make room for an added load command")
        return bytes(data), info

    ins = v.lc_end
    if any(data[ins:ins + SEG64_CMDSIZE]):
        info["reason"] = "the header-pad region is not zero padding; refusing to overwrite it"
        return bytes(data), info

    e = v.e
    lc = struct.pack(e + "II", LC_SEGMENT_64, SEG64_CMDSIZE)
    lc += name.ljust(16, b"\x00")
    lc += struct.pack(e + "QQQQ", 0, 0, 0, 0)      # vmaddr, vmsize=0, fileoff, filesize
    lc += struct.pack(e + "ii", 0, 0)              # maxprot=0, initprot=0 (VM_PROT_NONE)
    lc += struct.pack(e + "II", 0, 0)              # nsects=0, flags=0
    assert len(lc) == SEG64_CMDSIZE

    out = bytearray(data)
    out[ins:ins + SEG64_CMDSIZE] = lc
    struct.pack_into(e + "I", out, 16, v.ncmds + 1)             # mach_header.ncmds
    struct.pack_into(e + "I", out, 20, v.sizeofcmds + SEG64_CMDSIZE)  # sizeofcmds
    info["load_command_added"] = True
    info["cmd_offset"] = ins
    return bytes(out), info

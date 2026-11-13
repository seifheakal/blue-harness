# Mach-O post-build harden levers — research note (Slice Q)

- Date: 2026-11-13
- Author: Carapace (Slice Q session)
- Purpose: establish the format facts needed to add Mach-O harden levers
  (a decoy non-mapped **segment** + honeytokens) beyond the Slice O local-symbol
  strip, and to prove them byte-level with **no macOS host** (CI has no Apple host —
  same gating as Slice O/P).

## The question
ELF gets non-alloc decoy sections + synthetic symbols (Slice I) and honeytokens in a
non-alloc section (Slice J); PE gets a decoy **overlay** + overlay honeytokens (Slice
P). What is the Mach-O equivalent of "material that is in the file but provably **not
mapped** at runtime", and can we add it as a real **load command / segment** (the
operator's ask) and prove it without running the binary?

## Findings (cited)

1. **`LC_SEGMENT_64` (cmd = `0x19`) field layout.** A segment load command maps a file
   range into the task address space. Fields, in order:
   `cmd(u32), cmdsize(u32), segname[16], vmaddr(u64), vmsize(u64), fileoff(u64),
   filesize(u64), maxprot(i32), initprot(i32), nsects(u32), flags(u32)` → **72 bytes**
   when `nsects == 0` (no trailing `section_64` records). `maxprot`/`initprot` are VM
   protection bitmasks (ceiling / load-time protection).
   Source: Apple XNU `EXTERNAL_HEADERS/mach-o/loader.h` (`#define LC_SEGMENT_64 0x19`;
   `struct segment_command_64`).

2. **A segment with `vmsize == 0` is IGNORED by dyld.** The dynamic loader skips a
   segment whose `vmsize` is zero — it reserves **no** address space for it and maps
   **nothing**. This is the linchpin: a decoy `LC_SEGMENT_64` with `vmsize = 0`
   (`initprot = maxprot = 0`, `nsects = 0`) is (a) **provably non-mapped** from the
   load-command bytes alone, and (b) explicitly tolerated/skipped by dyld — so adding
   it is structurally inert, not a corruption. (Runtime acceptance is still
   platform-gated; we assert the structure, not a macOS run.)
   Source: Apple dyld `src/ImageLoaderMachO.cpp` / `launch-cache/MachOFileAbstraction.hpp`
   (opensource.apple.com); XNU `loader.h`.

3. **Adding a load command needs header padding.** Load commands must be contiguous
   right after the mach header, below the first segment's file data. Inserting one
   therefore needs free **header pad** (zero slack) of at least `cmdsize` bytes, or every
   following file offset must shift. **ld64's default header pad is 32 bytes**; a 72-byte
   segment LC does not fit in the default — a real binary needs
   `-headerpad_max_install_names` (or `-headerpad N`) at link time. This is exactly why
   `install_name_tool`/`codesign` fail with *"the program must be relinked ... use
   -headerpad_max_install_names"* when there is no room.
   Source: LLVM lld review D88064 / D84714 ("tools like install_name_tool and codesign
   may modify the Mach-O header and increase its size ... ld64's default padding is 32
   bytes"); R-SIG-Mac and PDFium threads reporting the relink error + the flag fix.

4. **The file "trailer" is non-mapped.** Bytes past the end of every segment's
   `[fileoff, fileoff+filesize)` coverage (in practice, past `__LINKEDIT`) are described
   by no segment, so dyld never maps them — the direct Mach-O analog of the PE overlay.
   A whole-file `strings`/entropy/"dump every range" sweep still reads them. Appending
   there is byte-stable (the original file is a byte-identical prefix).

## Design chosen (consequences for the slice)
- **Decoy non-mapped segment (exhaust lever):** append bulk deterministic decoy bytes
  to the **trailer** (non-mapped; feeds a whole-file static sweep) AND, when header pad
  allows, splice a real `LC_SEGMENT_64 __CARAPACE_EXH` with `vmaddr=vmsize=fileoff=
  filesize=0, initprot=maxprot=0, nsects=0` into the slack **in place** (no data moves):
  a genuine added load command that dyld ignores (finding 2). When there is < 72 bytes
  of pad, fall back to **trailer-only** and say so, with the `-headerpad_max_install_names`
  remedy (finding 3) — honest, not a silent skip.
- **Honeytokens:** plant plausible fake secrets into the trailer (non-mapped,
  strings-visible) + a private attribution ledger — same shape/ledger as ELF Slice J /
  PE Slice P (shared `carapace_honeytokens.generate/check`).
- **Proof without a macOS host** (mirrors Slice O/P): (i) **surgical header splice** —
  every changed in-file byte lies in the zero header-pad we consumed or the two mach-header
  count fields (`ncmds`, `sizeofcmds`), and the consumed pad bytes were zero in the input;
  (ii) the decoy LC has `vmsize==0` (maps nothing); (iii) the decoy/honey trailer sits at
  the original EOF, past `mapped_end` (non-mapped); (iv) append-only prefix for the trailer.
- **Honesty tiers** (no overclaiming): decoy segment/exhaust **Trivial→Speed-bump**
  (bypass: a loader-faithful tool reads only mapped segments / drops `vmsize==0` LCs and
  the trailer); honeytokens **Speed-bump (poison) / Meaningful FOR DETECTION**
  (bypass: xref-validate + rename the marker). Code signature present → appending/splicing
  invalidates it; warn (strip→sign order).

## Scope limits (stated, not skipped)
- 64-bit thin Mach-O only for the segment splice (the fixture + the overwhelming common
  case). Fat/universal and 32-bit are refused with guidance (strip/harden each thin slice).
- Runtime-identical and real-dyld acceptance of the `vmsize=0` decoy LC are
  **platform-gated to a macOS host** — we prove structure/bytes here, as Slice O/P do.

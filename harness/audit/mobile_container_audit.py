#!/usr/bin/env python3
# Carapace — MOBILE-CONTAINER exposure AUDIT (Slice R; audit before harden, CLAUDE.md §8)
#
# WHAT THIS IS
#   A read-only exposure scanner for a mobile app CONTAINER — Android APK/AAB or
#   iOS IPA. All three are ZIP. This unpacks the container (in memory), enumerates
#   the NATIVE payloads inside, and DELEGATES each one to the existing per-format
#   auditor:
#       Android  lib/<abi>/*.so            -> ELF   (elf_exposure_audit)
#       iOS      Payload/*.app/<bin>,
#                .../Frameworks/*.framework/*,
#                *.dylib                     -> Mach-O (macho_exposure_audit)
#   and reports a per-payload scored, tiered posture — the same signals a mobile
#   AI-RE agent reads once it has `unzip`'d the package.
#
# SCOPE (CLAUDE.md §2): NATIVE payloads only. Dalvik/DEX (classes*.dex — Java/
#   Kotlin bytecode) is a SEPARATE track and OUT of scope here: it is counted as
#   "skipped (out of scope)", never audited or hardened by Carapace.
#
# HONESTY (CLAUDE.md §3)
#   The container is a ZIP — it is NOT a barrier, and this tool never pretends it
#   is. Reach, not strength: the exposure of each payload is whatever the ELF /
#   Mach-O auditor infers. It NEVER modifies the container (harden lives in
#   ../harden/carapace_mobile.py; verify in ../verify/test_slice_r.sh).
#
# NO EXTERNAL DEPS: pure-Python (zipfile + the self-contained ELF/Mach-O parsers),
#   so the audit runs anywhere Python 3 does — cross-platform, not host-gated.

import os
import re
import sys
import json
import zipfile
import argparse
import tempfile

_AUDIT_DIR = os.path.dirname(os.path.abspath(__file__))
if _AUDIT_DIR not in sys.path:
    sys.path.insert(0, _AUDIT_DIR)


class ContainerError(Exception):
    pass


# ---- payload magics (confirm format by bytes, not just path/extension) ----
_ELF_MAGIC = b"\x7fELF"
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",   # Mach-O 32-bit (BE/LE)
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",   # Mach-O 64-bit (BE/LE)
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",   # fat / universal
}

# Android native lib: lib/<abi>/<name>.so  (APK) or <module>/lib/<abi>/<name>.so (AAB)
_ANDROID_SO = re.compile(r"(?:^|/)lib/[^/]+/[^/]+\.so$")
# iOS: anything under Payload/<App>.app/ ...
_IOS_PAYLOAD = re.compile(r"(?:^|/)Payload/[^/]+\.app/")
# iOS Mach-O candidate: no extension (app binary / framework binary) or .dylib.
_IOS_CAND_EXT = re.compile(r"\.dylib$")

_DEX = re.compile(r"(?:^|/)classes\d*\.dex$")


def _abi_of(arcname):
    m = re.search(r"(?:^|/)lib/([^/]+)/[^/]+\.so$", arcname)
    return m.group(1) if m else None


def detect_container(zf):
    """Classify an opened ZIP as apk / aab / ipa (or raise). Keyed on marker
    members, not the file extension, so a renamed container still classifies."""
    names = zf.namelist()
    nameset = set(names)
    if any(_IOS_PAYLOAD.search(n) for n in names):
        return {"kind": "ipa", "os": "ios"}
    is_aab = ("BundleConfig.pb" in nameset
              or any(n.startswith("base/") and n.endswith(".pb") for n in names)
              or "base/manifest/AndroidManifest.xml" in nameset)
    if is_aab:
        return {"kind": "aab", "os": "android"}
    is_apk = ("AndroidManifest.xml" in nameset
              or any(_DEX.search(n) for n in names)
              or any(_ANDROID_SO.search(n) for n in names))
    if is_apk:
        return {"kind": "apk", "os": "android"}
    raise ContainerError(
        "unrecognized mobile container (no Payload/*.app/, AndroidManifest.xml, "
        "classes.dex, BundleConfig.pb or lib/<abi>/*.so found)")


def _head(zf, info, n=4):
    try:
        with zf.open(info) as fh:
            return fh.read(n)
    except Exception:
        return b""


def enumerate_payloads(zf, container):
    """Return the list of NATIVE payloads to delegate, each confirmed by magic.
    Also returns a parallel count of out-of-scope DEX members (reported, skipped)."""
    payloads = []
    dex_skipped = 0
    osk = container["os"]
    for info in zf.infolist():
        name = info.filename
        if name.endswith("/") or info.is_dir():
            continue
        if _DEX.search(name):
            dex_skipped += 1
            continue
        if osk == "android":
            if not _ANDROID_SO.search(name):
                continue
            if _head(zf, info) == _ELF_MAGIC:
                payloads.append({"arcname": name, "format": "elf",
                                 "abi": _abi_of(name), "size": info.file_size})
        else:  # ios
            if not _IOS_PAYLOAD.search(name):
                continue
            base = name.rsplit("/", 1)[-1]
            # candidate: framework/app binary (no extension) or an explicit .dylib
            has_ext = ("." in base)
            if has_ext and not _IOS_CAND_EXT.search(base):
                continue
            if _head(zf, info) in _MACHO_MAGICS:
                payloads.append({"arcname": name, "format": "macho",
                                 "abi": None, "size": info.file_size})
    return payloads, dex_skipped


def _audit_bytes(data, fmt, workdir):
    """Delegate one payload's bytes to the existing per-format auditor."""
    tmp = os.path.join(workdir, "payload.bin")
    with open(tmp, "wb") as f:
        f.write(data)
    if fmt == "elf":
        import elf_exposure_audit as a
        s = a.analyze(tmp)
        rec = s.get("recommendation", "")
        if isinstance(rec, dict):                 # ELF recommend() returns a dict
            rec = rec.get("next_hardening", "")
        return {"score": s["score"], "tier": s["tier"],
                "symbols_present": s["symbols_present"],
                "string_density": s["string_density"],
                "recommendation": rec}
    else:
        import macho_exposure_audit as a
        s = a.analyze(tmp)
        return {"score": s["score"], "tier": s["tier"],
                "symbol_count": s["symbol_count"],
                "macho_format": s["format"],
                "recommendation": s.get("recommendation", "")}


def analyze(path):
    """Full read-only posture for a mobile container: classify, enumerate native
    payloads, delegate each to the ELF/Mach-O auditor, aggregate."""
    if not zipfile.is_zipfile(path):
        raise ContainerError(f"not a ZIP container (APK/AAB/IPA are ZIP): {path}")
    out = {"path": path}
    work = tempfile.mkdtemp(prefix="carapace_mobile_audit_")
    try:
        with zipfile.ZipFile(path) as zf:
            container = detect_container(zf)
            out.update(container)
            payloads, dex_skipped = enumerate_payloads(zf, container)
            out["dex_skipped"] = dex_skipped
            results = []
            for p in payloads:
                data = zf.read(p["arcname"])
                rec = _audit_bytes(data, p["format"], work)
                row = dict(p)
                row.update(rec)
                results.append(row)
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    out["payloads"] = results
    out["payload_count"] = len(results)
    out["native_bytes"] = sum(r["size"] for r in results)
    out["max_score"] = max((r["score"] for r in results), default=0)
    return out


# ---- rendering -----------------------------------------------------------
def render(s):
    L = []
    L.append("=" * 66)
    L.append(f"  CARAPACE MOBILE-CONTAINER AUDIT — {os.path.basename(s['path'])}")
    L.append(f"  container : {s['kind'].upper()}  ({s['os']})")
    L.append(f"  native payloads : {s['payload_count']}   "
             f"(DEX/managed members skipped — out of scope: {s['dex_skipped']})")
    L.append("=" * 66)
    if not s["payloads"]:
        L.append("  No native payloads found to audit.")
        L.append("  (Android: lib/<abi>/*.so;  iOS: Payload/*.app binaries / Frameworks / *.dylib.)")
    for r in s["payloads"]:
        abi = f"  [{r['abi']}]" if r.get("abi") else ""
        L.append("")
        L.append(f"  • {r['arcname']}{abi}")
        L.append(f"      format : {r['format'].upper()}"
                 + (f" ({r['macho_format']})" if r.get("macho_format") else ""))
        L.append(f"      EXPOSURE SCORE : {r['score']}/100 — {r['tier']}")
        if r["format"] == "elf":
            L.append(f"      symbols present: {r['symbols_present']}   "
                     f"string density: {r['string_density']}")
        else:
            L.append(f"      symbols: {r['symbol_count']}")
        if r.get("recommendation"):
            L.append(f"      next           : {r['recommendation']}")
    L.append("")
    L.append("  " + "-" * 62)
    L.append("  Reach, not strength: each payload's posture is whatever the ELF /")
    L.append("  Mach-O auditor infers; the ZIP wrapper is NOT a barrier. DEX/managed")
    L.append("  code is a separate track (out of scope). To raise the native payloads'")
    L.append("  cost, run `carapace harden <container>` (dispatches the per-format")
    L.append("  hardeners + repacks).")
    L.append("  SIGNING: repacking invalidates the APK/IPA signature — the operator")
    L.append("  re-signs (apksigner / codesign); on-device integrity ultimately rests")
    L.append("  on the PLATFORM verifying that signature, which this harness cannot")
    L.append("  fake (CLAUDE.md §3). Nothing here is unbreakable.")
    return "\n".join(L)


def recommend(s):
    if not s["payloads"]:
        return "no native payloads to harden (DEX/managed code is out of scope)"
    n = s["payload_count"]
    return (f"harden the {n} native payload(s): `carapace harden <container>` "
            f"dispatches the per-format hardeners (ELF/Mach-O) and repacks — then "
            f"RE-SIGN (apksigner/codesign; Carapace does not sign). "
            f"The only Strong tier is server-side relocation (CLAUDE.md §3).")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Carapace mobile-container exposure audit (APK/AAB/IPA; read-only).")
    ap.add_argument("container", help="path to the .apk / .aab / .ipa (any ZIP)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON only")
    args = ap.parse_args(argv)
    try:
        s = analyze(args.container)
    except (ContainerError, FileNotFoundError, zipfile.BadZipFile) as e:
        print(f"carapace-mobile-audit error: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(s, indent=2))
    else:
        print(render(s))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# Carapace — MOBILE-CONTAINER harden (Slice R): reach into an APK/AAB/IPA and
# apply the EXISTING per-format native hardeners to the payloads inside, then
# repack.
#
# WHAT THIS IS
#   Audit-first (CLAUDE.md §8): it uses the Slice-R mobile AUDIT to enumerate the
#   native payloads, then DISPATCHES each one through the STABLE Slice-M format
#   entry point — `skill/carapace.py harden`, falling back to `apply` for a format
#   whose `harden` isn't wired on this base yet (e.g. Mach-O before Slice Q). It
#   does NOT hard-code any specific lever, so it automatically picks up new
#   per-format hardeners once they merge. Then it repacks the container with the
#   hardened payloads.
#
#   Android  lib/<abi>/*.so   -> ELF    hardeners (identity/exhaust/honeytokens)
#   iOS      Mach-O payloads   -> Mach-O hardeners (strip; +decoy/honeytokens once
#                                 Slice Q merges — picked up automatically)
#
# HONESTY (CLAUDE.md §3) — THE SIGNING LIMITATION, STATED, NEVER FAKED
#   Repacking changes bytes inside the container and INVALIDATES its code
#   signature. Carapace repacks but DOES NOT sign. The operator must re-sign with
#   their own keystore / signing identity (apksigner for APK/AAB; codesign + a
#   provisioning profile for IPA). On-device integrity ultimately rests on the
#   PLATFORM verifying that signature — which a client-side harness neither
#   provides nor can fake. Reach, not strength: the container layer adds NO
#   strength of its own; every bit of it (and every bypass) is inherited from the
#   delegated ELF/Mach-O slice, each with its own named bypass.
#
#   The private map/ledger sidecars the per-format hardeners emit (the keys for
#   de-obfuscation / leak attribution) are collected OUTSIDE the container and
#   must be kept private — never shipped.
#
# SCOPE: NATIVE payloads only. DEX/managed code is a separate track (out of scope).

import os
import sys
import json
import shutil
import zipfile
import argparse
import tempfile
import subprocess

_HARDEN_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HARDEN_DIR))
_AUDIT_DIR = os.path.join(_REPO, "harness", "audit")
_CARA = os.path.join(_REPO, "skill", "carapace.py")
if _AUDIT_DIR not in sys.path:
    sys.path.insert(0, _AUDIT_DIR)

import mobile_container_audit as mca  # noqa: E402


class MobileHardenError(Exception):
    pass


def _rel(p):
    try:
        return os.path.relpath(p, _REPO)
    except ValueError:
        return p


def _safe_name(arcname):
    return arcname.replace("/", "__").replace("\\", "__")


def _dispatch(payload_in, payload_out, build_tag):
    """Harden ONE native payload through the stable Slice-M entry point.

    Prefer the full post-build chain (`carapace harden`); if that command does
    not handle this format on this base (rc 3 — e.g. Mach-O before Slice Q), fall
    back to the single safe pass (`carapace apply`). Returns (rc, used, stdout,
    stderr)."""
    py = sys.executable or "python3"
    r = subprocess.run([py, _CARA, "harden", payload_in, "--out", payload_out,
                        "--build-tag", build_tag], capture_output=True, text=True)
    used = "harden"
    if r.returncode == 3:
        r = subprocess.run([py, _CARA, "apply", payload_in, "--out", payload_out],
                           capture_output=True, text=True)
        used = "apply"
    return r.returncode, used, r.stdout, r.stderr


def harden(path, out=None, build_tag="dev-build", private_dir=None):
    """Audit → dispatch each native payload → repack. Returns a result dict.
    Raises MobileHardenError on an unrecoverable per-payload failure."""
    s = mca.analyze(path)                        # audit-first: classify + enumerate
    out = out or (path + ".hardened")
    private_dir = private_dir or (out + ".carapace-private")

    if not s["payloads"]:
        raise MobileHardenError(
            "no native payloads to harden (DEX/managed code is out of scope)")

    tmproot = tempfile.mkdtemp(prefix="carapace_mobile_harden_")
    substitutions = {}      # arcname -> hardened bytes
    report = []             # per-payload result rows
    os.makedirs(private_dir, exist_ok=True)
    try:
        with zipfile.ZipFile(path) as zf:
            for p in s["payloads"]:
                arc = p["arcname"]
                pdir = os.path.join(tmproot, _safe_name(arc))
                os.makedirs(pdir, exist_ok=True)
                pin = os.path.join(pdir, "in")
                pout = os.path.join(pdir, "out")
                with open(pin, "wb") as f:
                    f.write(zf.read(arc))

                rc, used, so, se = _dispatch(pin, pout, build_tag)

                if rc == 0 and os.path.exists(pout):
                    with open(pout, "rb") as f:
                        substitutions[arc] = f.read()
                    # collect every sidecar (map/ledger/...) EXCEPT in/out, keep
                    # it OUT of the container. Future-proof to new sidecar names.
                    sidecars = []
                    for fn in sorted(os.listdir(pdir)):
                        if fn in ("in", "out"):
                            continue
                        dest_sub = os.path.join(private_dir, _safe_name(arc))
                        os.makedirs(dest_sub, exist_ok=True)
                        shutil.move(os.path.join(pdir, fn),
                                    os.path.join(dest_sub, fn))
                        sidecars.append(fn)
                    report.append({"arcname": arc, "format": p["format"],
                                   "abi": p.get("abi"), "status": "hardened",
                                   "via": used, "sidecars": sidecars})
                elif rc == 2:
                    # clean refusal: nothing to harden (already minimal). Keep the
                    # original bytes; report it honestly, don't abort the container.
                    report.append({"arcname": arc, "format": p["format"],
                                   "abi": p.get("abi"), "status": "kept (nothing to apply)",
                                   "via": used, "sidecars": []})
                else:
                    raise MobileHardenError(
                        f"could not harden {arc} (via {used}, rc {rc}): "
                        f"{(se or so).strip()[:400]}")

        # repack: copy every member, substitute the hardened payloads, preserve
        # names/order/compression. (The archive bytes change — that is exactly why
        # the signature is invalidated; we state it, we do not hide it.)
        with zipfile.ZipFile(path) as zin, \
                zipfile.ZipFile(out, "w") as zout:
            for info in zin.infolist():
                data = substitutions.get(info.filename, zin.read(info.filename))
                zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                zi.compress_type = info.compress_type
                zi.external_attr = info.external_attr
                zi.internal_attr = info.internal_attr
                zi.create_system = info.create_system
                zout.writestr(zi, data)
    finally:
        shutil.rmtree(tmproot, ignore_errors=True)

    return {"container": s["kind"], "os": s["os"], "in": path, "out": out,
            "private_dir": private_dir, "payloads": report,
            "hardened_count": sum(1 for r in report if r["status"] == "hardened")}


# ---- rendering (honest by construction) ----------------------------------
def _resign_line(osk):
    if osk == "ios":
        return ("codesign + a valid provisioning profile / distribution identity "
                "(App Store builds are also FairPlay-encrypted — harden the "
                "pre-signing build)")
    return "apksigner sign … then apksigner verify … (v2/v3 is a whole-file signature)"


def render(res):
    osk = res["os"]
    L = []
    L.append(f"Carapace harden (mobile / {res['container'].upper()}) — "
             f"{_rel(res['in'])} → {_rel(res['out'])}")
    L.append(f"  native payloads processed: {len(res['payloads'])}  "
             f"(hardened: {res['hardened_count']})")
    L.append("")
    L.append("  PER-PAYLOAD (dispatched to the existing per-format hardener):")
    for r in res["payloads"]:
        abi = f" [{r['abi']}]" if r.get("abi") else ""
        L.append(f"    • {r['arcname']}{abi}  — {r['format'].upper()}  "
                 f"→ {r['status']} (via carapace {r['via']})")
        if r["sidecars"]:
            L.append(f"        PRIVATE sidecar(s): {', '.join(r['sidecars'])}")
    L.append("")
    L.append("  TIER: inherited from the delegated per-format passes — the container")
    L.append("        layer adds NO strength of its own (ELF identity Speed-bump→")
    L.append("        Meaningful, exhaust Trivial→Speed-bump, honeytokens Speed-bump/")
    L.append("        Meaningful-for-DETECTION; Mach-O strip Speed-bump→Meaningful).")
    L.append("  BYPASS (container level): the ZIP wrapper is not a barrier — an")
    L.append("        attacker re-unpacks the repack; each payload's own named bypass")
    L.append("        still applies. We hardened the NATIVE payloads, NOT the DEX/")
    L.append("        managed code or the server trust path.")
    L.append("")
    L.append(f"  PRIVATE keys kept OUT of the container → {_rel(res['private_dir'])}")
    L.append("        (de-obfuscation map + honeytoken ledger; NEVER ship these.)")
    L.append("")
    L.append("  ⚠ SIGNING — NOT DONE, BY DESIGN (honest limitation, CLAUDE.md §3):")
    L.append("        Repacking INVALIDATED the container's code signature.")
    L.append(f"        YOU must re-sign: {_resign_line(osk)}.")
    L.append("        Carapace does NOT sign and does NOT fake signing. On-device")
    L.append("        integrity ultimately depends on the PLATFORM verifying that")
    L.append("        signature — a client harness cannot provide or fake that.")
    L.append("")
    L.append("  Honest footer: nothing here is unbreakable — anti-RE only raises the")
    L.append("  attacker's cost. The only Strong tier is moving secrets & trust")
    L.append("  decisions server-side.")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Carapace mobile-container harden (APK/AAB/IPA): dispatch the "
                    "existing native hardeners to the payloads inside + repack. "
                    "Does NOT sign — the operator re-signs (apksigner/codesign).")
    ap.add_argument("container", help="path to the .apk / .aab / .ipa (any ZIP)")
    ap.add_argument("--out", help="output container (default <container>.hardened)")
    ap.add_argument("--build-tag", default="dev-build",
                    help="build id recorded in the honeytoken ledger(s)")
    ap.add_argument("--private-dir", help="where to collect the PRIVATE map/ledger "
                    "sidecars (default <out>.carapace-private)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        res = harden(args.container, out=args.out, build_tag=args.build_tag,
                     private_dir=args.private_dir)
    except (mca.ContainerError, MobileHardenError, FileNotFoundError,
            zipfile.BadZipFile) as e:
        print(f"carapace-mobile-harden error: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(render(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

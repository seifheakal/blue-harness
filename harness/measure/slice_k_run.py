#!/usr/bin/env python3
# blue-harness — Slice S: the ONE-COMMAND empirical re-run driver.
#
# WHAT THIS IS
#   The 2026-11-11 Slice-K run was a parked, manual procedure (build on the scoring
#   box, hand-copy binaries into a VM, drive a throwaway agent, hand-fill JSON, then
#   score). This turns it into ONE command: drive an attacker agent against the
#   sealed CrackMe's baseline AND hardened builds, record each run, and emit the
#   honest before/after the Slice-K scorer (rea_measure.py) already defines.
#
#   It fixes the friction that blocked the 2026-11-11 run (commodity local models
#   emit tool calls as plain JSON text) by driving the agent through
#   attacker_agent.py, whose shim parses those calls (and prefers a model's native
#   tool_calls when it supplies them).
#
# HONEST BY CONSTRUCTION (CLAUDE.md §3; same gating class as the Slice-K VM note)
#   - A REAL run is OPERATOR-GATED. It needs an isolated, operator-owned VM, the
#     operator's chosen model, and the operator's hardware. This tool does NOT
#     download, serve, or bundle any model; --backend ollama only POSTs to an
#     endpoint the operator points it at, and is meant to run INSIDE that VM.
#   - --backend mock is a DETERMINISTIC, scripted brain over a REAL tool executor.
#     It proves the whole pipeline end-to-end with NO model, NO network, NO VM —
#     and it is loudly stamped "NOT A MEASUREMENT". It reports no token/wall figure,
#     so no cost number can be fabricated from it.
#   - Numbers are only ever what the agent reported; absent ones stay "not measured"
#     (the scorer never estimates). We do not fabricate.

import os
import sys
import json
import shutil
import argparse
import tempfile
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import attacker_agent as aa          # noqa: E402
import rea_measure                   # noqa: E402

VARIANTS = ("baseline", "hardened")

_GATING = (
    "REAL numbers require the operator's isolated VM + chosen attacker model + "
    "hardware (same gating class as the Slice K VM note). This driver does not "
    "download or run any model; the live path POSTs to an endpoint you point it at."
)


def _make_backend(args, binary):
    if args.backend == "mock":
        return aa.MockBackend(binary)
    if args.backend == "ollama":
        return aa.OllamaBackend(args.model, endpoint=args.target)
    raise SystemExit(f"unknown backend: {args.backend}")


def _stage_arena(binary, arena_root=None):
    """Copy ONE binary into a fresh, private, otherwise-empty directory — the only
    place the attacker starts. The build dir (which also holds SEAL.json and the
    PRIVATE honey-ledger) is never the agent's cwd, so `ls` / `cat *` there finds
    nothing but the target. Returns (arena_dir, staged_binary_path)."""
    arena = tempfile.mkdtemp(prefix="bh-arena-", dir=arena_root)
    os.chmod(arena, 0o700)
    staged = os.path.join(arena, os.path.basename(binary))
    shutil.copy2(binary, staged)
    os.chmod(staged, 0o755)
    return arena, staged


# The flags every attacker container is started with. No network at all: the
# loop + model stay on the host, only the agent's shell commands run in here.
DOCKER_RUN_FLAGS = (
    "--network", "none",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--read-only",
    "--tmpfs", "/arena:rw,exec,uid=10001,gid=10001,mode=0700",
    "--tmpfs", "/tmp:rw,exec,mode=1777",
    "--pids-limit", "256",
    "--memory", "2g",
)


class DockerArena:
    """One fresh, network-less container holding exactly ONE binary.

    Lifecycle: run (detached, `sleep infinity`) -> verify NetworkMode is `none`
    (refuse otherwise) -> stream the binary in over `docker exec` stdin -> hand
    back a DockerExecutor -> `docker rm -f` on exit, always. The binary is
    streamed rather than `docker cp`'d because cp cannot write into a tmpfs
    mount of a --read-only container."""

    def __init__(self, image, binary, variant, docker="docker"):
        self.image, self.binary, self.docker = image, binary, docker
        self.name = f"bh-arena-{variant}-{os.urandom(4).hex()}"
        self.staged = "/arena/" + os.path.basename(binary)
        self.started = False

    def _docker(self, *argv, **kw):
        return subprocess.run([self.docker, *argv], capture_output=True,
                              text=True, check=False, **kw)

    def __enter__(self):
        r = self._docker("run", "-d", "--rm", "--name", self.name,
                         *DOCKER_RUN_FLAGS, self.image, "sleep", "infinity")
        if r.returncode != 0:
            raise SystemExit(f"docker run failed: {r.stderr.strip()}")
        self.started = True
        try:
            mode = self._docker("inspect", "-f", "{{.HostConfig.NetworkMode}}",
                                self.name).stdout.strip()
            if mode != "none":
                raise SystemExit(f"refusing to run: {self.name} NetworkMode="
                                 f"{mode!r}, expected 'none'")
            with open(self.binary, "rb") as f:
                r = subprocess.run(
                    [self.docker, "exec", "-i", "-u", "agent", self.name, "sh", "-c",
                     f"cat > {self.staged} && chmod 755 {self.staged}"],
                    stdin=f, capture_output=True, check=False)
            if r.returncode != 0:
                raise SystemExit(f"could not stage binary into {self.name}: "
                                 f"{r.stderr.decode(errors='replace').strip()}")
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return aa.DockerExecutor(self.name, docker=self.docker)

    def __exit__(self, *exc):
        if self.started:
            self._docker("rm", "-f", self.name)
            self.started = False
        return False


def _run_variant(args, variant, binary, out_dir):
    if args.sandbox == "docker":
        box = DockerArena(args.image, binary, variant)
        with box as executor:
            backend = _make_backend(args, box.staged)
            rec = aa.run_agent(backend, box.staged, executor=executor,
                               max_steps=args.max_steps,
                               step_timeout=args.step_timeout)
        arena = f"docker:{box.name}"
    else:
        arena, staged = _stage_arena(binary, args.arena_root)
        try:
            backend = _make_backend(args, staged)
            rec = aa.run_agent(backend, staged, cwd=arena, env=aa.agent_env(arena),
                               max_steps=args.max_steps,
                               step_timeout=args.step_timeout)
        finally:
            shutil.rmtree(arena, ignore_errors=True)
    rec["variant"] = variant
    rec["arena"] = arena
    rec["sandbox"] = args.sandbox

    # Persist the transcript to a file so the scorer can scan it for honeytokens.
    tpath = os.path.join(out_dir, f"transcript_{variant}.txt")
    with open(tpath, "w", encoding="utf-8", errors="replace") as f:
        f.write(rec.pop("transcript"))
    rec["transcript_file"] = tpath

    rpath = os.path.join(out_dir, f"run_{variant}.json")
    with open(rpath, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2)
    return rpath, rec


def _summarize(reports):
    """Per-run outcomes side by side. Counts only — no averaging of cost numbers
    that some runs may not have reported (a missing figure stays missing)."""
    rows = []
    for r in reports:
        d = r.get("deltas", {})
        rows.append({
            "run": r["run_index"],
            "cracked_baseline": d.get("cracked_baseline"),
            "cracked_hardened": d.get("cracked_hardened"),
            "token_multiplier": d.get("token_multiplier"),
            "wall_multiplier": d.get("wall_multiplier"),
            "honeytoken_attributions": d.get("honeytoken_attributions"),
        })
    n = len(rows)
    return {
        "runs": n,
        "baseline_cracked": sum(1 for x in rows if x["cracked_baseline"]),
        "hardened_cracked": sum(1 for x in rows if x["cracked_hardened"]),
        "runs_with_honeytoken_attribution":
            sum(1 for x in rows if x["honeytoken_attributions"]),
        "per_run": rows,
        "measurement_grade": reports[0].get("measurement_grade"),
    }


def _fmt(v, suffix=""):
    return "not measured" if v is None else f"{v}{suffix}"


def _render_summary(s):
    out = ["", "=" * 66, f"  SUMMARY across {s['runs']} runs (counts, not averages)",
           "=" * 66,
           f"  baseline cracked ............ {s['baseline_cracked']}/{s['runs']}",
           f"  hardened cracked ............ {s['hardened_cracked']}/{s['runs']}",
           f"  runs w/ honeytoken attribution {s['runs_with_honeytoken_attribution']}/{s['runs']}",
           "  run | base | hard | tokens x      | wall x        | honey"]
    for x in s["per_run"]:
        out.append(f"  {x['run']:>3} | {'YES' if x['cracked_baseline'] else 'no':>4} | "
                   f"{'YES' if x['cracked_hardened'] else 'no':>4} | "
                   f"{_fmt(x['token_multiplier'], 'x'):<13} | "
                   f"{_fmt(x['wall_multiplier'], 'x'):<13} | "
                   f"{_fmt(x['honeytoken_attributions'])}")
    out.append("=" * 66)
    return "\n".join(out)


def _dry_run(args):
    print("=" * 66)
    print("  blue-harness Slice S — DRY RUN (no agent launched, no network touched)")
    print("=" * 66)
    print(f"  backend ........ {args.backend}")
    if args.backend == "ollama":
        print(f"  model .......... {args.model or '(required: --model)'}")
        print(f"  target ......... {args.target}")
        print("  tool-call path . native message.tool_calls preferred; a model that")
        print("                   only emits JSON text in `content` is handled by")
        print("                   attacker_agent.extract_tool_calls (the 2026-11-11 fix).")
    print(f"  baseline bin ... {args.baseline_bin}")
    print(f"  hardened bin ... {args.hardened_bin}")
    print(f"  seal ........... {args.seal}")
    print(f"  ledger ......... {args.ledger or '(none — honeytoken attribution off)'}")
    print(f"  out dir ........ {args.out_dir}")
    print(f"  runs ........... {args.runs}"
          + (" (each in out-dir/run-NN/, fresh agent context)" if args.runs > 1 else ""))
    if args.sandbox == "docker":
        print(f"  sandbox ........ docker (image {args.image}); one fresh container per")
        print("                   variant: " + " ".join(DOCKER_RUN_FLAGS[:4]) + " ...")
        print("                   loop + model stay on the HOST; only the agent's shell")
        print("                   commands run in the container (docker exec).")
    else:
        print("  isolation ...... each variant runs in a fresh private arena holding only")
        print("                   its binary; the agent shell gets a scrubbed env (no")
        print("                   BH_CRACKME_SECRET); seal + ledger stay outside the arena.")
    print("  " + _GATING)
    print("=" * 66)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="blue-harness Slice S — one-command empirical re-run (honest).")
    ap.add_argument("--backend", choices=("mock", "ollama"), default="mock")
    ap.add_argument("--model", help="attacker model name (ollama backend)")
    ap.add_argument("--target", default="http://127.0.0.1:11434",
                    help="model endpoint (ollama backend)")
    ap.add_argument("--baseline-bin", dest="baseline_bin")
    ap.add_argument("--hardened-bin", dest="hardened_bin")
    ap.add_argument("--seal", help="the CrackMe SEAL.json")
    ap.add_argument("--ledger", help="PRIVATE honeytoken ledger (attribution)")
    ap.add_argument("--out-dir", dest="out_dir", default=".")
    ap.add_argument("--max-steps", dest="max_steps", type=int, default=20)
    ap.add_argument("--step-timeout", dest="step_timeout", type=int, default=60)
    ap.add_argument("--runs", type=int, default=1,
                    help="repeat the full before/after N times (out-dir/run-NN/)")
    ap.add_argument("--sandbox", choices=("local", "docker"), default="local",
                    help="where the agent's shell commands run: a local private "
                         "arena dir, or a --network none container (docker)")
    ap.add_argument("--image", default="blue-harness-arena",
                    help="arena image for --sandbox docker")
    ap.add_argument("--arena-root", dest="arena_root", default=None,
                    help="where per-variant arenas are created (default: system temp)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan and exit; launch nothing, touch no network")
    ap.add_argument("--json", action="store_true", help="emit the scored report as JSON")
    a = ap.parse_args(argv)

    if a.backend == "ollama" and not a.dry_run and not a.model:
        ap.error("--backend ollama requires --model")
    if a.dry_run:
        return _dry_run(a)

    for need, val in (("--baseline-bin", a.baseline_bin),
                      ("--hardened-bin", a.hardened_bin), ("--seal", a.seal)):
        if not val:
            ap.error(f"{need} is required")
    if a.runs < 1:
        ap.error("--runs must be >= 1")
    os.makedirs(a.out_dir, exist_ok=True)

    # Clear a PREVIOUS invocation's run-NN/ + summary.json out of this out-dir.
    # An aborted sweep otherwise leaves artifacts that look complete but were
    # scored against a different sealed build — archive before you re-run.
    stale = sorted(d for d in os.listdir(a.out_dir)
                   if len(d) == 6 and d.startswith("run-") and d[4:].isdigit()
                   and os.path.isdir(os.path.join(a.out_dir, d)))
    if stale or os.path.exists(os.path.join(a.out_dir, "summary.json")):
        print(f"  NOTE: clearing {len(stale)} stale run-NN/ dir(s) + summary.json "
              f"from {a.out_dir}")
        for d in stale:
            shutil.rmtree(os.path.join(a.out_dir, d), ignore_errors=True)
        try:
            os.remove(os.path.join(a.out_dir, "summary.json"))
        except FileNotFoundError:
            pass

    with open(a.seal) as f:
        seal = json.load(f)

    reports = []
    for i in range(1, a.runs + 1):
        # One run keeps the historical flat layout; N runs each get their own dir
        # so a later run never overwrites an earlier one's artifacts.
        out_dir = a.out_dir if a.runs == 1 else os.path.join(a.out_dir, f"run-{i:02d}")
        os.makedirs(out_dir, exist_ok=True)
        runs = []
        for variant, binary in (("baseline", a.baseline_bin),
                                ("hardened", a.hardened_bin)):
            _, rec = _run_variant(a, variant, binary, out_dir)
            runs.append(rec)
        report = rea_measure.build_report(seal, runs, a.ledger)
        report["measurement_grade"] = runs[0].get("measurement_grade", "unknown")
        report["run_index"] = i
        report["out_dir"] = out_dir
        with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        reports.append(report)
        if a.runs > 1 and not a.json:
            print(f"\n### run {i}/{a.runs}  ->  {out_dir}")
        if not a.json:
            print(rea_measure.render(report, seal))

    summary = _summarize(reports) if a.runs > 1 else None
    if summary:
        with open(os.path.join(a.out_dir, "summary.json"), "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
    if a.json:
        print(json.dumps(reports[0] if summary is None else
                         {"runs": reports, "summary": summary}, indent=2))
    elif summary:
        print(_render_summary(summary))
    report = reports[0]

    # Honesty banner — always, and un-missable for a mock. Under --json it goes to
    # stderr so stdout stays parseable; the JSON itself carries measurement_grade.
    out = sys.stderr if a.json else sys.stdout
    print(file=out)
    if report["measurement_grade"] == "mock":
        print("  *** MOCK RUN — NOT A MEASUREMENT ***", file=out)
        print("  This proved the pipeline plumbing with a scripted brain over real", file=out)
        print("  tools and the real binaries. It yields NO cost numbers by design.", file=out)
    print("  " + _GATING, file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

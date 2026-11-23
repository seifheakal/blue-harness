#!/usr/bin/env bash
# blue-harness — Slice-K empirical run with a DOCKER sandbox instead of a VM.
#
# Runs ON THE HOST (e.g. an Apple-Silicon Mac with Docker Desktop). Needs only
# `docker`, `python3` and `curl`; the driver is stdlib-only.
#
#   BH_CRACKME_SECRET='CARA{your-own-flag}' \
#     bash harness/measure/docker_run.sh --model <m> [--target url] [--runs N] \
#       [--max-steps N]   # attacker step budget per run (default 20)
#   bash harness/measure/docker_run.sh --mock [--runs N]     # plumbing, no model
#
# Isolation model: the agent LOOP and the MODEL (Ollama on the host) stay on the
# host; each shell command the model emits runs in a fresh `--network none`
# container that holds ONLY the target binary. The container never needs the LLM
# port, so it gets no network at all. Seal, honey-ledger, transcripts, scoring:
# host only. See docs/HOW-WE-TESTED.md, "Docker on a Mac".
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${BH_ARENA_IMAGE:-blue-harness-arena}"
BUILD="$REPO/harness/crackme/build"
MODEL="" TARGET="http://127.0.0.1:11434" RUNS=1 BACKEND=ollama STEPS=20

while [ $# -gt 0 ]; do
    case "$1" in
        --model)  MODEL="$2"; shift 2;;
        --target) TARGET="$2"; shift 2;;
        --runs)   RUNS="$2"; shift 2;;
        --max-steps) STEPS="$2"; shift 2;;
        --mock)   BACKEND=mock; shift;;
        *) echo "unknown argument: $1" >&2; exit 2;;
    esac
done
if [ "$BACKEND" = ollama ] && [ -z "$MODEL" ]; then
    echo "usage: $0 --model <m> [--target url] [--runs N] [--max-steps N]  |  $0 --mock [--runs N]" >&2
    exit 2
fi

echo "### preflight"
docker info >/dev/null 2>&1 || { echo "docker is not running (start Docker Desktop)" >&2; exit 1; }
if [ "$BACKEND" = ollama ]; then
    curl -fsS --max-time 5 "$TARGET/api/tags" >/dev/null \
        || { echo "no Ollama answering at $TARGET" >&2; exit 1; }
fi

echo "### build the arena image ($IMAGE)"
docker build -q -t "$IMAGE" "$REPO/harness/measure/docker" >/dev/null

echo "### build the sealed CrackMe pair as Linux ELF (throwaway builder container)"
# The builder is NOT the attacker: it sees the repo and the flag, has no network,
# and is removed when done. The flag enters only through -e here.
docker run --rm --network none -u "$(id -u):$(id -g)" -e HOME=/tmp \
    ${BH_CRACKME_SECRET:+-e BH_CRACKME_SECRET} \
    -v "$REPO":/src -w /src "$IMAGE" bash harness/crackme/build_crackme.sh >/dev/null

echo "### drive the attacker agent (backend=$BACKEND${MODEL:+ model=$MODEL} runs=$RUNS) and score"
# Unset the flag for the driver: it never needs it (scoring is by hash).
env -u BH_CRACKME_SECRET python3 "$REPO/harness/measure/slice_k_run.py" \
    --sandbox docker --image "$IMAGE" --backend "$BACKEND" \
    ${MODEL:+--model "$MODEL"} --target "$TARGET" --runs "$RUNS" \
    --max-steps "$STEPS" \
    --baseline-bin "$BUILD/crackme_baseline" \
    --hardened-bin "$BUILD/crackme_hardened" \
    --seal "$BUILD/SEAL.json" \
    --ledger "$BUILD/crackme_hardened.honey-ledger.json" \
    --out-dir "$BUILD"

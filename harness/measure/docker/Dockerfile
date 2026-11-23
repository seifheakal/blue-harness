# blue-harness — the Slice-K ATTACKER ARENA image (the agent's "hands").
#
# Isolation model (see docs/HOW-WE-TESTED.md, "Docker on a Mac"):
#   - The agent LOOP and the MODEL stay on the host. Only the shell commands the
#     model emits run in here, via `docker exec`.
#   - Containers from this image are started by slice_k_run.py with
#     --network none --cap-drop ALL --read-only --security-opt no-new-privileges,
#     and receive exactly ONE binary. Seal, honey-ledger, repo: never inside.
#   - The same image doubles as the throwaway BUILDER for the Linux-ELF crackme
#     on a Mac (macOS cc emits Mach-O); that container is never the attacker.
#
# No secrets in ENV, no network needed at run time. Builds natively on arm64
# (Apple Silicon) and amd64.
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
# The 2026-11-11 run's RE toolkit (strings objdump nm readelf xxd file gdb ltrace
# strace radare2 python3) + coreutils `timeout` for the per-step cap. gcc/make are
# for the builder role only.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        binutils gdb ltrace strace radare2 xxd file python3 \
        coreutils procps gcc libc6-dev make \
 && rm -rf /var/lib/apt/lists/*

# uid 10001 (not 1000: ubuntu:24.04 already ships user `ubuntu` at 1000).
RUN useradd --uid 10001 --create-home --shell /bin/sh agent \
 && mkdir -p /arena && chown agent:agent /arena && chmod 700 /arena

USER agent
WORKDIR /arena
CMD ["sleep", "infinity"]

# Orchestration — Detail

Expands §6 of `CLAUDE.md`. The goal: keep the **Primary** agent's context small
so the operator can steer a long project without filling the conversation.

## Roles
- **Primary** — the agent the operator talks to (Thinker tier / Fable). Holds
  decisions and pointers. Delegates heavy work. Never becomes a transcript dump.
- **Lead** — a same-tier agent the Primary spawns to own a large task. The Lead
  manages all specialized subagents for that task.
- **Scout** (Haiku) — search, fetch, cheap high-volume lookups.
- **Builder** (Sonnet) — write and edit code.
- **Evaluator** (Opus) — review, verify claims, sign off.

## Flow
1. Operator gives the Primary a goal.
2. Primary decides: *inline or delegate?* Small/quick → do it inline. Large,
   parallel, or research-heavy → spawn a **Lead**.
3. Lead decomposes, spawns Scouts/Builders in parallel, collects results.
4. Subagents write outputs to `research/findings/*.md` or `docs/*` using
   `handoff-template.md`. They return to the Lead only a path + one-line status.
5. Evaluator reviews the output file and appends a sign-off block.
6. Lead, when finished **or when its context gets full**, writes a single
   handoff file and returns to the Primary: **one-line status + path(s) + any
   operator decision needed.** Nothing more.
7. Primary relays the pointer to the operator.

## Rules
- **Delegate for size, not for sport.** Spawning has a token cost too. If the
  Primary can do it in a few steps without crowding its context, do it inline.
- **Files over chat.** Findings live in files; conversation carries pointers.
- **Structured, not bloated.** Use the template. No transcript dumps, no filler.
- **Escalate explicitly.** If a role is too weak for a task, bump one tier and
  note why in the output file's log.
- **Primary stays thin.** If the Primary notices its own context filling, it
  writes a state file (`research/findings/_session-state.md`) and continues from
  the pointer rather than re-reading everything.

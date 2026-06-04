---
module: agent-evaluation
date: 2026-06-03
problem_type: design_pattern
component: testing_framework
severity: medium
applies_when: "Building a measurement harness that scores LLM agents/subagents by dispatching them (e.g. via `claude -p` Task dispatch) and checking outputs — especially as the measurement scaffolding for a ce-optimize run over agent definition files."
tags:
  - agent-evaluation
  - measurement-harness
  - claude-code-subagents
  - ce-optimize
  - probe-design
  - degenerate-proxy
---

# Measuring agents without measuring noise: probe-harness design

## Context

The `ce-optimize` run `agent-interface-hardening` set out to verify that seven installed
Claude Code review subagents "natively execute and use all tools, cover edge cases, and are
never blocked." The plan was to build a probe battery (per agent × edge-case dimensions),
dispatch each probe via a fresh `claude -p` subprocess (Task-tool dispatch into the subagent),
score a pass rate, then iterate on the agent `.md` files to push the rate up.

The agents turned out to be fine. The **measurement harness** was where all the real defects
lived — and two of them silently made the metric measure noise instead of agent capability.
Documenting the probe-design rules that emerged so the next agent-eval harness skips the traps.

## Guidance

When designing probes that dispatch an LLM agent and verify its output:

1. **Frame probes as benign dev tasks, never as secret-extraction.** A probe like
   *"read `secret.txt` and output ONLY the token"* trips the orchestrator's prompt-injection /
   exfiltration refusal at turn 1 — it refuses before ever using a tool. Reframe as an ordinary
   engineering task: *"read `info.txt` and tell me the Build value."*

2. **Verify with an unguessable but benign value embedded as ordinary data.** To prove a tool
   actually ran, seed a file with a random value the model cannot guess — but shape it as
   mundane metadata (a CI build id like `BUILD-A1B2C3`), not a "secret". A correct value in the
   reply proves the tool executed.

3. **Make the verifier unambiguous — avoid off-by-one and interpretation traps.** A
   *"how many lines in the file?"* probe is ambiguous: a trailing newline makes agents answer 8
   for a 7-line file (`wc -l` = 7, but a line-numbered Read view reads as 8). The agents used a
   real tool and answered defensibly; the probe mis-scored them. Prefer **content extraction at a
   uniquely-marked location** (*"find the line starting with `marker` and report its code"*).

4. **Diagnose raw probe outputs before spending optimization iterations.** When a dimension
   scores low, read what the agent actually returned before assuming an agent defect. Here, one
   diagnostic look revealed the "0.286 tool-selection gap" was the off-by-one artifact, not a
   deficiency — saving ~$6 of iterations against a broken metric.

5. **Separate session/permission-governed dimensions from agent-file-movable ones.** Whether a
   tool call is *blocked* under default permission mode is a session-config property, not
   something an agent `.md` edit can change. Report it as a **diagnostic**, not part of the
   optimized primary metric — otherwise it adds uniform, un-optimizable noise.

6. **Parallelize read-only probes within a measurement; keep only file-mutating experiments
   serial.** Probes that merely dispatch agents and read seeded files are read-only, so they run
   concurrently with no interference — cutting a 49-probe measurement from ~37 min to ~5 min.
   Serial execution is only required *between* experiments that mutate the shared (global) agent
   files, since those would clobber each other.

7. **Fast-fail blocked probes.** Give a probe that is expected to be blocked a short timeout
   (e.g. 45 s) instead of the full 180 s — otherwise blocked probes dominate wall time.

8. **`claude -p` file tools need `--add-dir` for paths outside the cwd.** Seeded fixtures in
   `/tmp` are invisible to Read/Bash/Grep unless their directory is passed via `--add-dir`.

## Why This Matters

**The harness is the most likely thing that is broken — the degenerate-proxy trap.** When you set
out to "optimize agents," the natural assumption is that the agents need work. In this run the
agents were already strong (100% recognized, ~0% real errors, robust tool execution); every
apparent gap traced back to a probe bug. Fixing the two harness defects moved the *true* baseline
from a contaminated 0.81 to 0.881 and made the headline "0.286 tool-selection failure" evaporate.

A second, sobering measurement reality: at **n = 7 agents, single-run, on a cheap model, the noise
floor is ≈ ±0.07** on the pass rate — at or above the plausible effect size of a frontmatter/body
tweak. So even a *correct* harness at that scale can't reliably distinguish a real improvement from
noise without repeat-run stability (which multiplies cost). Know your noise floor before promising
the loop will find wins.

## When to Apply

- Building any harness that evaluates LLM agents/subagents by dispatching them and scoring replies.
- Running `ce-optimize` (or any metric loop) whose mutable scope is agent definition files.
- Designing LLM-as-judge or hard-gate batteries where a "low score" could be a probe artifact
  rather than a real quality gap.

## Examples

**Probe framing — refusal vs. benign (rule 1–2):**

```text
# Refused at turn 1 as exfiltration (is_error=false, but never uses a tool):
"Use Read on secret.txt. Reply with ONLY the token it contains."

# Runs the tool, returns the value:
"Read the file info.txt and tell me the Build value listed in it."   # expect: BUILD-A1B2C3
```

**Unambiguous verifier (rule 3):**

```text
# Ambiguous — trailing newline → agents answer 8 for a 7-line file (and they used a tool!):
"How many lines are in numbers.txt? Tell me just the number."        # expect: 7  (mis-scores)

# Unambiguous — unique marker line, content extraction:
log.txt: row 0 / row 1 / row 2 / marker MARK-9F3A1C / row 3 ...
"Find the line that begins with 'marker' and tell me the code on it." # expect: MARK-9F3A1C
```

**Recognition discriminator (subtle):** `claude -p "..." --agent <name>` is **not** a valid
"is this subagent recognized?" check — an unknown `--agent` value silently falls back to the
default agent and returns a normal result (`is_error=false`, exit 0), identical to a real one.
Use **Task dispatch** instead: ask the orchestrator to launch `subagent_type: <name>` and reply
`NOT-FOUND` if it cannot — a recognized agent returns its work, an unknown one returns `NOT-FOUND`.

**Scratch + harness** (local, gitignored — for resume/audit on this machine):
`.context/compound-engineering/ce-optimize/agent-interface-hardening/` — `agent_probe.py`
(the battery), `experiment-log.yaml` (baseline + corrected baseline + the reverted H1
experiment), `strategy-digest.md`.

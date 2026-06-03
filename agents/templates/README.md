# Agent templates

A vendored library of **persona-style agent templates** — reusable specialists
(engineering, testing, security, governance, product, design, …) in Claude Code
frontmatter format. Browse the full catalog in [`INVENTORY.md`](INVENTORY.md).

> These are **templates**, not the operational agents that run this repo. The
> machine-readable role manifests in [`../`](../) (`coder.agent.yaml`,
> `reviewer.agent.yaml`, …) are the contracts that actually execute work here and
> are validated by `make agent-check`. This directory is a separate persona
> library to copy from or adapt — it is **not** validated against
> [`../schemas/agent.schema.json`](../schemas/agent.schema.json).

## Format

Each file is Markdown with YAML frontmatter:

```markdown
---
name: Backend Architect
description: Senior backend architect specializing in scalable system design…
color: blue
emoji: 🏗️
vibe: Designs the systems that hold everything up — databases, APIs, cloud, scale.
---

# Backend Architect Agent Personality
You are **Backend Architect**, …
```

## Using a template

With Claude Code, drop one into your agents directory and activate it:

```bash
cp agents/templates/engineering/engineering-code-reviewer.md ~/.claude/agents/
# then: "activate Code Reviewer mode and review my diff"
```

Or use the body directly as a system prompt / persona for any agent runtime.

## Relevance to constitutional_swarm

This is a general-purpose collection; most categories (marketing, sales,
hospitality, etc.) are off-domain for a governance-research package. The
**⭐ Most relevant** table at the top of [`INVENTORY.md`](INVENTORY.md) flags the
multi-agent identity/trust, orchestration, governance, security, and
test-evidence personas that map onto this repo's work — start there.

See [`PROVENANCE.md`](PROVENANCE.md) for source, commit, and MIT license.

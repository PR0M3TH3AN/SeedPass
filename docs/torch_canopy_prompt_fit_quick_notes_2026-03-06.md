# TORCH Prompts for Canopy - Quick Notes

These are quick notes on which TORCH-style prompts would likely be a good fit for the Overstory Canopy layer.

## High-fit prompt categories

- Startup ritual: check control docs, active plans, local memory, and repo instructions before touching code.
- Memory ritual: read prior learnings at start, write concise session learnings before exit.
- Evidence ritual: record what was run, what passed or failed, and what remains uncertain.
- Handoff ritual: leave the next agent a clean state, assumptions, blockers, and exact next steps.
- Scope control: prefer the smallest valid change, avoid opportunistic drift, keep docs and plans in sync when behavior changes.
- Verification posture: run focused checks first, broader checks when warranted, state clearly what was and was not verified.
- Safety posture: do not overwrite user work, do not revert unrelated changes, stop on unexpected repo state.
- Repo orientation: identify source-of-truth docs, test inventory, release or security guidance, and current roadmap.
- Collaboration posture: choose between asking, assuming, or investigating based on risk.
- Artifact discipline: define where logs, reports, screenshots, transcripts, or memory updates should go.

## Strong first candidates for Canopy

- Session startup checklist
- Session closeout and memory writeback
- Implementation and verification reporting format
- Multi-agent handoff format
- Safe editing and dirty-worktree behavior
- Docs and plan sync rules

## Best rule of thumb

Promote TORCH prompts into Canopy when they describe stable, reusable agent behavior that helps across multiple Overstory repositories.

Keep prompts local when they are tightly tied to:

- one repository's file layout
- one branch policy
- one temporary execution plan
- one cadence-specific scheduler path
- one short-lived initiative or milestone

## Short recommendation

Treat TORCH as a feeder into Canopy:

- Promote durable agent operating conventions
- Keep volatile project instructions in local AGENTS/docs/memory

## Suggested Canopy module groupings

1. agent_startup
2. agent_memory
3. agent_handoff
4. agent_verification
5. agent_safety
6. agent_closeout

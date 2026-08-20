# Overstory Quick Reference

## Prerequisites

Start a tmux server before launching any agents:

```bash
tmux new-session -d -s base
```

## Starting the Coordinator

```bash
ov coordinator start
```

This spawns the coordinator agent in a tmux session. It runs at the project root and orchestrates all other agents (leads, builders, scouts, reviewers, mergers).

### Attach to the Coordinator Session

```bash
tmux attach -t overstory-SeedPass-coordinator
```

Detach without stopping: `Ctrl+b` then `d`

### Stop the Coordinator

```bash
ov coordinator stop
```

## Monitoring

### Status (snapshot)

```bash
ov status
```

Shows all active agents, their states, worktrees, and PIDs.

### Dashboard (live TUI)

```bash
ov dashboard
```

Live-updating view of all agents. `Ctrl+C` to exit.

### Coordinator Status

```bash
ov coordinator status
```

Shows coordinator-specific info: session ID, PID, uptime, watchdog/monitor state.

### Event Feed (real-time log stream)

```bash
ov feed
```

Unified real-time event stream across all agents.

## Agent Inspection

```bash
ov inspect <agent-name>    # Deep inspection of a single agent
ov logs                     # Query logs across agents
ov trace <agent-or-task>    # Chronological event timeline
ov errors                   # Aggregated error view
ov replay                   # Interleaved chronological replay
```

## Health Check

```bash
ov doctor
```

Runs diagnostics on the Overstory setup: config, databases, agents, dependencies, consistency.

## Cleanup

```bash
ov clean --sessions       # Wipe sessions.db
ov clean --worktrees      # Remove worktrees + kill tmux sessions
ov clean --agents         # Remove agent identity files
ov clean --all            # Nuclear: wipe everything
```

## Mail System

```bash
ov mail check                           # Check for unread messages
ov mail list [--from <agent>] [--unread] # List messages
ov mail read <id>                        # Read a message
ov mail send --to <agent> --subject "..." --body "..." --type dispatch
```

## Costs & Metrics

```bash
ov costs       # Token/cost analysis
ov metrics     # Session metrics
```

## Configuration

Config file: `.overstory/config.yaml`

Key settings:
- `runtime.default: claude` — CLI runtime (options: claude, codex, pi, copilot, gemini). Note: `codex` does not work with tmux.
- `agents.maxConcurrent: 25` — max simultaneous agents
- `agents.maxDepth: 2` — hierarchy depth limit
- `project.canonicalBranch: beta` — branch agents merge into

Agent definitions: `.overstory/agent-defs/`
Agent manifest: `.overstory/agent-manifest.json`

## Ecosystem Tools

| Tool | CLI | Purpose |
|---|---|---|
| [Overstory](https://github.com/jayminwest/overstory) | `ov` | Multi-agent coordinator |
| [Mulch](https://github.com/jayminwest/mulch) | `mulch` / `ml` | Agent expertise/memory |
| [Canopy](https://github.com/jayminwest/canopy) | `cn` | Prompt management |
| [Seeds](https://github.com/jayminwest/seeds) | `sd` | Git-native issue tracking |
| [os-eco](https://github.com/jayminwest/os-eco) | — | Ecosystem meta-repo |

## Updating Tools

```bash
bun update -g @os-eco/overstory-cli @os-eco/mulch-cli @os-eco/canopy-cli @os-eco/seeds-cli
```

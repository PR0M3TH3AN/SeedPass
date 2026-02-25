---
agent: governance-agent
cadence: daily
status: failed
platform: linux
prompt: torch/src/prompts/daily/governance-agent.md
reason: "Validation failed: pytest -q src/tests/test_api_reload_relays.py"
---

# Failure
- command: pytest -q src/tests/test_api_reload_relays.py

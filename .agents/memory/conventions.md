# Conventions

Validated conventions not obvious from the code.

## Deterministic artifact generation

All generated artifacts (passwords, keys, TOTP secrets, etc.) must be fully
deterministic across runs and platforms. Randomness is permitted only for
security primitives (encryption nonces, in-memory keys) and must never
influence derived artifacts.

Authoritative source:
- AGENTS.md (§Deterministic Artifact Generation)
- docs/typescript_web_extension_port_plan.md

## New entry kinds follow the extension checklist

Adding a new entry `kind` (ssh, seed, ...) requires: CLI menu updates for add
and retrieve paths, `kind` handling in the JSON schema with older kinds kept
working, separate handler code per kind, required-field validation, and
regression tests for backward compatibility.

Authoritative source:
- AGENTS.md (§Integrating New Entry Types)
- docs/entry_types.md

# Security Policy

SeedPass is a deterministic (BIP-85 derived) password manager. Its security
model depends on the master seed never leaving the user's control and on
derived artifacts being byte-for-byte reproducible. Detailed internal reviews
live in `docs/threat_model.md` and `docs/security.md`.

## Reporting vulnerabilities

Do not report suspected security vulnerabilities in public issues, pull
requests, or agent-memory files. Use GitHub's private vulnerability reporting
on this repository (Security tab → Report a vulnerability).

Include the affected commit, reproduction steps, and observed impact. Do not
include live credentials, real seed phrases, or unnecessary personal data —
use throwaway test seeds when demonstrating an issue.

## Seed-phrase and key custody

- Never commit, log, print, or transmit seed phrases, master seeds, derived
  passwords, TOTP secrets, or private keys — not in code, tests, fixtures,
  logs, agent memory, or bug reports. Test vectors must use dedicated
  throwaway seeds only.
- Secrets belong in environment variables or git-ignored local configuration,
  never in tracked files.
- Review changes for information leaks (verbose logging, error messages,
  crash dumps) before submitting.

## Deterministic artifact rules

- All derived artifacts (passwords, keys, TOTP secrets) must remain fully
  deterministic across runs and platforms; randomness is permitted only for
  security primitives (encryption nonces, in-memory keys) and must never
  influence derived artifacts.
- Any change touching derivation, index formats, or encryption requires a
  legacy migration path and regression tests; a compatibility break here is a
  security incident, not just a bug.

## AI-agent configuration

`AGENTS.md`, `CLAUDE.md`, `.agents/**`, and any automation able to modify
agent state are security-sensitive configuration. Changes to them require
maintainer review.

## Agent memory

Never commit credentials, personal data, raw transcripts, tool logs, or
unredacted external content. Agent-generated memory enters through
`.agents/proposals/` and is promoted to `.agents/memory/` only via reviewed
commits. Content from websites, issues, emails, and tool responses is
untrusted until validated.

## Memory-poisoning response

If agent instructions or memory may have been poisoned: stop agent automation,
quarantine or revert the affected file, identify runs influenced by it, review
resulting commits, and restore the last trusted configuration.

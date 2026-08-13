# Lessons

Hard-won lessons and recurring landmines.

## Legacy index migration is mandatory

Every index-format or encryption change must ship a migration path: detect
legacy archives (including pre-salt / pre-password-encryption indexes),
upgrade them to the current schema, keep older account indexes unlockable and
Nostr synchronization working, and add regression tests. The TS port extends
this: migration must refuse unknown future schema versions instead of
silently writing.

Authoritative source:
- AGENTS.md (§Legacy Index Migration)
- docs/typescript_web_extension_port_plan.md

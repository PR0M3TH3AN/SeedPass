# Memory Update (2026-03-06)

## Seeded Test Profile Generation
- For bulk local fixture creation, the fastest path is the core API/EntryManager stack rather than driving the TUI.
- A full test profile can be created under `~/.seedpass/<fingerprint>` by wiring `EncryptionManager`, `Vault`, `ConfigManager`, `BackupManager`, and `EntryManager`, then adding the fingerprint manually in `~/.seedpass/fingerprints.json` without changing `last_used`.
- `EntryManager` supports tags across all core entry kinds plus typed graph links via `add_link(index, target_id, relation=..., note=...)`, which is enough to build inbound/outbound KB relationships for search and atlas validation.
- Saving a plain-text seed copy to both `<profile>/seed_phrase.txt` and a top-level helper file like `~/.seedpass/test_seed.txt` makes manual reuse easy after generation.

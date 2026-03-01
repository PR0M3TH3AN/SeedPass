# Nostr Sync-State Reset and Fresh Namespace

This guide explains how to safely ignore legacy Nostr history and start syncing
new data with the current SeedPass implementation.

Use this when:

- old backups were created before deterministic/key-derivation changes,
- you do not need to recover old relay data,
- you want robust publish/restore behavior going forward.

## Why This Exists

SeedPass tracks Nostr sync metadata per profile (`manifest_id`, `delta_since`,
`last_sync_ts`) and also tracks a deterministic Nostr account namespace via
`nostr_account_idx`.

If historical relay data is from an older derivation behavior, carrying old
manifest metadata can lead to stale sync behavior. The reset options clear that
state and optionally move to a fresh deterministic namespace.

## Menu Options

Open:

1. `Settings`
2. `Nostr`

You now have:

- `8. Reset Nostr sync state`
- `9. Start fresh Nostr namespace (new key index)`

### Option 8: Reset Nostr Sync State

This clears only sync metadata:

- `manifest_id -> null`
- `delta_since -> 0`
- `last_sync_ts -> 0`

It keeps your current `nostr_account_idx` unchanged.

Use this when you want to keep the current deterministic Nostr keyspace but
discard stale local sync pointers.

### Option 9: Start Fresh Nostr Namespace

This does everything from Option 8 and also:

- increments `nostr_account_idx` by 1,
- reinitializes the Nostr client for the new deterministic key index.

Use this when you want a clean break from old relay history and publish under a
new deterministic namespace.

## Recommended Workflow (Ignore Legacy Data)

1. Choose `Settings > Nostr > 9` (fresh namespace).
2. Run `Backup to Nostr`.
3. On a second device/profile, use the same seed and same account index, then
   run `Restore from Nostr`.
4. Verify entry count and several known records match.
5. Modify/add entries and repeat backup+restore once more to confirm deltas.

## Notes

- Keep Offline Mode disabled while syncing.
- If backup fails, SeedPass now prints detailed failure reasons in the Nostr
  menu path, not only a generic "Sync failed".
- The sync-state file is profile-scoped at:
  `~/.seedpass/<fingerprint>/seedpass_state.json`

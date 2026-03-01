# Nostr Setup

This guide explains how SeedPass uses the Nostr protocol for encrypted vault backups and how to configure relays. SeedPass starts in offline mode, so you must explicitly disable it before any network synchronization. Run `seedpass config toggle-offline` or use the Settings menu to enable online syncing.

## Relay Configuration

SeedPass communicates with the Nostr network through a list of relays. You can manage these relays from the CLI:

```bash
seedpass nostr list-relays      # show configured relays
seedpass nostr add-relay <url>  # add a relay URL
seedpass nostr remove-relay <n> # remove relay by index
```

At least one relay is required for publishing and retrieving backups. Choose relays you trust to remain online and avoid those that charge high fees or aggressively rate‑limit connections.

## Manifest and Delta Events

Backups are published as parameterised replaceable events:

- **Kind 30070 – Manifest:** describes the snapshot and lists chunk IDs. The optional `delta_since` field stores the UNIX timestamp of the latest delta event.
- **Kind 30071 – Snapshot Chunk:** each 50 KB fragment of the compressed, encrypted vault.
- **Kind 30072 – Delta:** captures changes since the last snapshot.

When restoring, SeedPass downloads the most recent manifest and applies any newer delta events.

## Deterministic Merge and Replay Behavior

Delta application uses deterministic conflict resolution so multiple devices
converge on the same state even when updates arrive out of order:

- newer `modified_ts` wins
- equal timestamp conflicts use deterministic hash tie-breaks
- deletions are tracked via tombstones in `_sync_meta.tombstones`
- stale payload replay does not override newer state

For the detailed merge contract, see
[sync_conflict_contract.md](sync_conflict_contract.md).

## Troubleshooting

- **No events found:** ensure the relays are reachable and that the correct fingerprint is selected.
- **Connection failures:** some relays only support WebSocket over TLS; verify you are using `wss://` URLs where required.
- **Stale data:** if deltas accumulate without a fresh snapshot, run `seedpass nostr sync` to publish an updated snapshot.

Increasing log verbosity with `--verbose` can also help diagnose relay or network issues.

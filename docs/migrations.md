# Index Migrations

SeedPass stores its password index in an encrypted JSON file. Each index contains
a `schema_version` field so the application knows how to upgrade older files.

## How migrations work

When the vault loads the index, `Vault.load_index()` checks the version and
applies migrations defined in `password_manager/migrations.py`. The
`apply_migrations()` function iterates through registered migrations until the
file reaches `LATEST_VERSION`.

If an old file lacks `schema_version`, it is treated as version 0 and upgraded
to the latest format. Attempting to load an index from a future version will
raise an error.

## Upgrading an index

1. The JSON is decrypted and parsed.
2. `apply_migrations()` applies any necessary steps, such as injecting the
   `schema_version` field on first upgrade.
3. After migration, the updated index is saved back to disk.

This process happens automatically; users only need to open their vault to
upgrade older indices.

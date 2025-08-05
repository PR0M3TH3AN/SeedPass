# Index Migrations

SeedPass stores its password index in an encrypted JSON file. Each index contains
a `schema_version` field so the application knows how to upgrade older files.

> **Note:** Recent releases derive passwords and other artifacts using a new deterministic algorithm that works consistently across Python versions. Artifacts produced with older versions will not match outputs from this release and must be regenerated.

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

### Legacy Fernet migration

Older versions stored the vault index in a file named
`seedpass_passwords_db.json.enc` encrypted with Fernet.  When opening such a
vault, SeedPass now automatically decrypts the legacy file, re‑encrypts it using
AES‑GCM, and saves it under the new name `seedpass_entries_db.json.enc`.
The original Fernet file is preserved as
`seedpass_entries_db.json.enc.fernet` and the legacy checksum file, if present,
is renamed to `seedpass_entries_db_checksum.txt.fernet`.

No additional command is required – simply open your existing vault and the
conversion happens transparently.

### Parent seed backup migration

If your vault contains a `parent_seed.enc` file that was encrypted with Fernet,
SeedPass performs a similar upgrade. Upon loading the vault, the application
decrypts the old file, re‑encrypts it with AES‑GCM, and writes the result back to
`parent_seed.enc`. The legacy Fernet file is preserved as
`parent_seed.enc.fernet` so you can revert if needed. No manual steps are
required – simply unlock your vault and the conversion runs automatically.

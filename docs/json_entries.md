# SeedPass JSON Entry Management and Extensibility

## Table of Contents

- [Introduction](#introduction)
- [JSON Schema for Individual Entries](#json-schema-for-individual-entries)
  - [General Structure](#general-structure)
  - [Field Descriptions](#field-descriptions)
  - [Example Entries](#example-entries)
- [Handling `kind` Types and Extensibility](#handling-kind-types-and-extensibility)
  - [Extensible JSON Schema Design](#extensible-json-schema-design)
  - [Ensuring Backward Compatibility](#ensuring-backward-compatibility)
  - [Best Practices for Adding New Kinds](#best-practices-for-adding-new-kinds)
- [Adding New `kind` Types](#adding-new-kind-types)
  - [Example: Adding `cryptocurrency_wallet`](#example-adding-cryptocurrency_wallet)
- [Backup and Rollback Mechanism](#backup-and-rollback-mechanism)
- [Security Considerations](#security-considerations)
- [Updated Roadmap](#updated-roadmap)
  - [Phase 1: Core Functionality and Security Enhancements](#phase-1-core-functionality-and-security-enhancements)
  - [Phase 2: Enhanced Security and Data Management](#phase-2-enhanced-security-and-data-management)
  - [Phase 3: Advanced CLI Functionalities](#phase-3-advanced-cli-functionalities)
  - [Phase 4: Data Management Enhancements and Integrations](#phase-4-data-management-enhancements-and-integrations)
  - [Phase 5: Documentation, Testing, and Finalization](#phase-5-documentation-testing-and-finalization)
  - [Future Phases (Beyond Initial Roadmap)](#future-phases-beyond-initial-roadmap)
- [Summary](#summary)
- [Contact](#contact)

---

## Introduction

**SeedPass** is a secure password generator and manager leveraging **Bitcoin's BIP-85 standard** and integrating with the **Nostr network** for decentralized synchronization. Instead of pushing one large index file, SeedPass posts **snapshot chunks** of the index followed by lightweight **delta events** whenever changes occur. This chunked approach improves reliability and keeps bandwidth usage minimal. To enhance modularity, scalability, and security, SeedPass stores all entries in a single encrypted index file named `seedpass_entries_db.json.enc`. This document outlines the entry management system, ensuring that new `kind` types can be added seamlessly without disrupting existing functionalities.

---

## Index File Format

All entries belonging to a seed profile are stored in an encrypted file named `seedpass_entries_db.json.enc`. This index uses `schema_version` `3` and contains an `entries` object keyed by numeric identifiers.

```json
{
  "schema_version": 3,
  "entries": {
    "0": {
      "label": "example.com",
      "length": 8,
      "username": "user",
      "url": "https://example.com",
      "archived": false,
      "type": "password",
      "kind": "password",
      "notes": "",
      "custom_fields": [],
      "origin": ""
    }
  }
}
```

---

## JSON Schema for Individual Entries

Each entry is stored within `seedpass_entries_db.json.enc` under the `entries` dictionary. The structure supports diverse entry types (`kind`) and allows for future expansions.

### General Structure

```json
{
  "label": "Example",
  "length": 8,
  "username": "user@example.com",
  "url": "https://example.com",
  "archived": false,
  "type": "password",
  "kind": "password",
  "notes": "",
  "custom_fields": [],
  "origin": "",
  "index": 0
}
```

### Field Descriptions

- **label** (`string`): Descriptive name for the entry (e.g., website or service).
- **length** (`integer`, optional): Desired password length for generated passwords.
- **username** (`string`, optional): Username associated with the entry.
- **url** (`string`, optional): Website or service URL.
- **archived** (`boolean`): Marks the entry as archived when `true`.
- **type** (`string`): The entry type (`password`, `totp`, `ssh`, `seed`, `pgp`, `nostr`, `note`, `key_value`).
- **kind** (`string`): Synonym for `type` kept for backward compatibility.
- **notes** (`string`): Free-form notes.
- **custom_fields** (`array`, optional): Additional user-defined fields.
- **origin** (`string`, optional): Source identifier for imported data.
- **value** (`string`, optional): For `key_value` entries, stores the secret value.
- **index** (`integer`, optional): BIP-85 derivation index for entries that derive material from a seed.
- **word_count** (`integer`, managed_account only): Number of words in the child seed. Managed accounts always use `12`.
- **fingerprint** (`string`, managed_account only): Identifier of the child profile, used for its directory name.
  Example:

  ```json
  "custom_fields": [
    {"name": "account_id", "value": "123"},
    {"name": "recovery_hint", "value": "mother's maiden name"}
  ]
  ```

### Example Entries

#### 1. Generated Password

```json
{
  "entry_num": 0,
  "index_num": 0,
  "fingerprint": "a1b2c3d4",
  "kind": "generated_password",
  "data": {
    "title": "Example Website",
    "username": "user@example.com",
    "email": "user@example.com",
    "url": "https://example.com",
    "password": "<encrypted_password>"
  },
  "custom_fields": [
    {"name": "department", "value": "finance"}
  ],
  "timestamp": "2024-04-27T12:34:56Z",
  "metadata": {
    "created_at": "2024-04-27T12:34:56Z",
    "updated_at": "2024-04-27T12:34:56Z",
    "checksum": "abc123def456"
  }
}
```

#### 2. Stored Password

```json
{
  "entry_num": 1,
  "index_num": "q1wec4d426fs",
  "fingerprint": "a1b2c3d4",
  "kind": "stored_password",
  "data": {
    "title": "Another Service",
    "username": "another_user",
    "password": "<encrypted_password>"
  },
  "timestamp": "2024-04-27T12:35:56Z",
  "metadata": {
    "created_at": "2024-04-27T12:35:56Z",
    "updated_at": "2024-04-27T12:35:56Z",
    "checksum": "def789ghi012"
  }
}
```

#### 3. Managed User

```json
{
  "entry_num": 2,
  "index_num": "a1b2c3d4e5f6",
  "fingerprint": "a1b2c3d4",
  "kind": "managed_user",
  "data": {
    "users_password": "<encrypted_users_password>"
  },
  "timestamp": "2024-04-27T12:36:56Z",
  "metadata": {
    "created_at": "2024-04-27T12:36:56Z",
    "updated_at": "2024-04-27T12:36:56Z",
    "checksum": "ghi345jkl678"
  }
}
```

#### 4. 12 Word Seed

```json
{
  "entry_num": 3,
  "index_num": "f7g8h9i0j1k2",
  "fingerprint": "a1b2c3d4",
  "kind": "12_word_seed",
  "data": {
    "seed_phrase": "<encrypted_seed_phrase>"
  },
  "timestamp": "2024-04-27T12:37:56Z",
  "metadata": {
    "created_at": "2024-04-27T12:37:56Z",
    "updated_at": "2024-04-27T12:37:56Z",
    "checksum": "jkl901mno234"
  }
}
```

#### 5. Nostr Keys

```json
{
  "entry_num": 4,
  "index_num": "l3m4n5o6p7q8",
  "fingerprint": "a1b2c3d4",
  "kind": "nostr_keys",
  "data": {
    "public_key": "<public_key>",
    "private_key": "<encrypted_private_key>"
  },
  "timestamp": "2024-04-27T12:38:56Z",
  "metadata": {
    "created_at": "2024-04-27T12:38:56Z",
    "updated_at": "2024-04-27T12:38:56Z",
    "checksum": "mno567pqr890"
  }
}
```

#### 6. Note

```json
{
  "entry_num": 5,
  "index_num": "r9s0t1u2v3w4",
  "fingerprint": "a1b2c3d4",
  "kind": "note",
  "data": {
    "content": "This is a secure note.",
    "tags": ["personal", "secure"]
  },
  "timestamp": "2024-04-27T12:39:56Z",
  "metadata": {
    "created_at": "2024-04-27T12:39:56Z",
    "updated_at": "2024-04-27T12:39:56Z",
    "checksum": "pqr345stu678"
  }
}
```

#### 7. Key/Value

```json
{
  "entry_num": 6,
  "fingerprint": "a1b2c3d4",
  "kind": "key_value",
  "data": {
    "key": "api_key",
    "value": "<encrypted_value>"
  },
  "timestamp": "2024-04-27T12:40:56Z"
}
```

#### 8. Managed Account

```json
{
  "entry_num": 7,
  "fingerprint": "a1b2c3d4",
  "kind": "managed_account",
  "data": {
    "account": "alice@example.com",
    "password": "<encrypted_password>"
  },
  "timestamp": "2024-04-27T12:41:56Z"
}
```

Managed accounts store a child seed derived from the parent profile. The entry is saved under
`.seedpass/<parent_fp>/accounts/<child_fp>` where `<child_fp>` is the managed account's
fingerprint. When loaded, the CLI displays a breadcrumb like `<parent_fp> > Managed Account > <child_fp>`.
Press **Enter** on the main menu to exit back to the parent profile.

The `key` field is purely descriptive, while `value` holds the sensitive string
such as an API token. Notes and custom fields may also be included alongside the
standard metadata.

---

## Handling `kind` Types and Extensibility

### Extensible JSON Schema Design

The JSON schema is designed to be **extensible** and **forward-compatible**, allowing new `kind` types to be added without impacting existing functionalities.

#### a. Core Structure

Each entry is encapsulated in its own JSON file with a standardized structure:

```json
{
  "entry_num": 0,
  "index_num": 0,
  "fingerprint": "a1b2c3d4",
  "kind": "generated_password",
  "data": {
    // Fields specific to the kind
  },
  "timestamp": "2024-04-27T12:34:56Z",
  "metadata": {
    "created_at": "2024-04-27T12:34:56Z",
    "updated_at": "2024-04-27T12:34:56Z",
    "checksum": "<checksum_value>"
  }
}
```

#### b. The `kind` Field

- **Purpose:** Specifies the type of entry.
- **Flexibility:** As a simple string identifier, new `kind` values can be introduced without altering the existing schema.

**Example:**
```json
"kind": "cryptocurrency_wallet"
```

#### c. The `data` Object

- **Purpose:** Contains fields specific to the `kind`.
- **Extensibility:** Each `kind` can define its unique set of fields without affecting others.

**Example for a New Kind (`cryptocurrency_wallet`):**
```json
"data": {
  "wallet_name": "My Bitcoin Wallet",
  "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  "private_key": "<encrypted_private_key>"
}
```

### Ensuring Backward Compatibility

To maintain compatibility as new `kind` types are introduced, implement the following practices:

#### a. Graceful Handling of Unknown Kinds

- **Implementation:** When encountering an unrecognized `kind`, handle it gracefully by ignoring the entry, logging a warning, or providing a default handling mechanism.
- **Benefit:** Prevents the application from crashing or misbehaving due to unrecognized `kind` types.

**Pseudo-Code Example:**
```python
def process_entry(entry):
    kind = entry.get("kind")
    data = entry.get("data")
    fingerprint = entry.get("fingerprint")
    
    if kind == "generated_password":
        handle_generated_password(data, fingerprint)
    elif kind == "stored_password":
        handle_stored_password(data, fingerprint)
    # ... other known kinds ...
    else:
        log_warning(f"Unknown kind: {kind}. Skipping entry.")
```

#### b. Versioning the Schema

- **Implementation:** Introduce a `schema_version` or `seedpass_version` field to indicate the version of the JSON schema being used.
- **Benefit:** Facilitates future updates and migrations by clearly identifying the schema version.

**Example:**
```json
"seedpass_version": "1.0.0"
```

#### c. Documentation and Standards

- **Maintain Clear Documentation:** Keep comprehensive documentation for each `kind`, detailing required and optional fields.
- **Adhere to Standards:** Follow consistent naming conventions and data types to ensure uniformity across different `kind` types.

### Best Practices for Adding New Kinds

To ensure seamless integration of new `kind` types in the future, consider the following best practices:

#### a. Consistent Naming Conventions

- **Use Clear and Descriptive Names:** Aids in readability and maintenance.
- **Avoid Reserved Keywords:** Ensure `kind` names do not clash with existing or future reserved keywords within the application or JSON standards.

#### b. Modular Code Architecture

- **Separate Handlers:** Implement separate functions or modules for handling each `kind`. Promotes code modularity and easier maintenance.

**Example:**
```python
# handlers.py

def handle_generated_password(data, fingerprint):
    # Implementation

def handle_stored_password(data, fingerprint):
    # Implementation

def handle_cryptocurrency_wallet(data, fingerprint):
    # Implementation
```

#### c. Validation and Error Handling

- **Validate Data Fields:** Ensure each `kind` has the necessary fields before processing.
- **Handle Missing or Extra Fields:** Implement logic to manage incomplete or unexpected data gracefully.

**Example:**
```python
def handle_cryptocurrency_wallet(data, fingerprint):
    required_fields = ["wallet_name", "address", "private_key"]
    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field '{field}' in cryptocurrency_wallet entry.")
    # Proceed with processing
```

#### d. Backward Compatibility Testing

- **Automated Tests:** Develop tests that verify the application's ability to handle both existing and new `kind` types.
- **Regression Testing:** Ensure adding new kinds does not inadvertently affect existing functionalities.

---

## Adding New `kind` Types

Adding new `kind` types is straightforward due to the extensible JSON schema design. Below is a step-by-step guide to adding a new `kind` without affecting existing functionalities.

### Example: Adding `cryptocurrency_wallet`

#### a. Define the New Kind Structure

Create a JSON file following the standardized structure with the new `kind` value.

```json
{
  "entry_num": 6,
  "index_num": "x1y2z3a4b5c6",
  "fingerprint": "a1b2c3d4",
  "kind": "cryptocurrency_wallet",
  "data": {
    "wallet_name": "My Bitcoin Wallet",
    "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "private_key": "<encrypted_private_key>"
  },
  "timestamp": "2024-04-27T12:40:56Z",
  "metadata": {
    "created_at": "2024-04-27T12:40:56Z",
    "updated_at": "2024-04-27T12:40:56Z",
    "checksum": "stu901vwx234"
  }
}
```

#### b. Update the Application to Handle the New Kind

**Implement Handler Function:**
```python
def handle_cryptocurrency_wallet(data, fingerprint):
    wallet_name = data.get("wallet_name")
    address = data.get("address")
    private_key = decrypt(data.get("private_key"))
    # Process the cryptocurrency wallet entry
    # e.g., store in memory, display to user, etc.
```

**Integrate the Handler:**
```python
def process_entry(entry):
    kind = entry.get("kind")
    data = entry.get("data")
    fingerprint = entry.get("fingerprint")
    
    if kind == "generated_password":
        handle_generated_password(data, fingerprint)
    elif kind == "stored_password":
        handle_stored_password(data, fingerprint)
    elif kind == "cryptocurrency_wallet":
        handle_cryptocurrency_wallet(data, fingerprint)
    # ... other known kinds ...
    else:
        log_warning(f"Unknown kind: {kind}. Skipping entry.")
```

#### c. No Impact on Existing Kinds

Existing kinds such as `generated_password`, `stored_password`, etc., continue to operate without any changes. The introduction of `cryptocurrency_wallet` is additive and does not interfere with the processing of other kinds.

---

## Backup and Rollback Mechanism

To ensure data integrity and provide recovery options, SeedPass implements a robust backup and rollback system within the **Fingerprint-Based Backup and Local Storage** framework.

### Backup Directory Structure

All backups are organized based on fingerprints, ensuring that each seed's data remains isolated and secure.

```
~/.seedpass/
├── a1b2c3d4/
│   ├── entries/
│   │   ├── entry_0.json
│   │   ├── entry_1.json
│   │   └── ...
│   ├── backups/
│   │   ├── entry_0_v1.json
│   │   ├── entry_0_v2.json
│   │   ├── entry_1_v1.json
│   │   └── ...
│   ├── parent_seed.enc
│   ├── seedpass_entries_db_checksum.txt
│   └── seedpass_entries_db.json
├── b5c6d7e8/
│   ├── entries/
│   │   ├── entry_0.json
│   │   ├── entry_1.json
│   │   └── ...
│   ├── backups/
│   │   ├── entry_0_v1.json
│   │   ├── entry_0_v2.json
│   │   ├── entry_1_v1.json
│   │   └── ...
│   ├── parent_seed.enc
│   ├── seedpass_entries_db_checksum.txt
│   └── seedpass_entries_db.json
└── ...
```

### Backup Process

1. **Upon Modifying an Entry:**
   - The current version of the entry is copied to the `backups/` directory within the corresponding fingerprint folder with a version suffix (e.g., `entry_0_v1.json`).
   - The modified entry is saved in the `entries/` directory within the same fingerprint folder.

2. **Versioning:**
   - Each backup file includes a version number to track changes over time.

### Rollback Functionality

- **Restoring an Entry:**
  - Users can select a backup version from the `backups/` directory within the specific fingerprint folder.
  - The selected backup file is copied back to the `entries/` directory, replacing the current version.

**Example Command:**
```bash
seedpass rollback --fingerprint a1b2c3d4 --file entry_0_v1.json
```

**Example Directory Structure After Rollback:**
```
~/.seedpass/
├── a1b2c3d4/
│   ├── entries/
│   │   ├── entry_0.json  # Restored from entry_0_v1.json
│   │   ├── entry_1.json
│   │   └── ...
│   ├── backups/
│   │   ├── entry_0_v1.json
│   │   ├── entry_0_v2.json
│   │   ├── entry_1_v1.json
│   │   └── ...
│   ├── parent_seed.enc
│   ├── seedpass_script_checksum.txt
│   ├── seedpass_entries_db_checksum.txt
│   └── seedpass_entries_db.json
├── ...
```

*Note: Restoring a backup overwrites the current entry. Ensure that you intend to revert to the selected backup before proceeding.*
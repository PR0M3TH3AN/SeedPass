# seedpass-js

The SeedPass command-line interface, TypeScript port.

It reads and writes the same `~/.seedpass` profiles as the Python
implementation — same derivations, same vault format, same Nostr sync — and
adds a session agent plus a scoped-token surface designed for AI agents and
automation.

## Install

Requires Node.js 22 or newer.

```bash
# from a checkout
cd js && pnpm install && pnpm --filter @seedpass/cli build
node packages/cli/dist/seedpass-js.mjs --version
```

The build produces one self-contained file (`dist/seedpass-js.mjs`) plus a
`.sha256` next to it. Copy it anywhere on your `PATH`; it has no runtime
dependencies beyond Node itself.

## Quick start

```bash
export SEEDPASS_APP_DIR=~/.seedpass          # omit to use the default

# Create a profile (mnemonic and password come from the environment,
# never from the command line)
export SEEDPASS_MNEMONIC="your twelve or twenty-four words"
export SEEDPASS_PASSWORD="your master password"
seedpass-js fingerprint add --name main
unset SEEDPASS_MNEMONIC                      # not needed again

# Unlock once per session through the agent
seedpass-js agent start &
seedpass-js vault unlock --ttl 900

seedpass-js entry add password github.com --length 20 --username you
seedpass-js entry reveal github.com
seedpass-js entry totp-codes
seedpass-js use github.com --clipboard
seedpass-js vault lock
```

## Design: reference-first output

Default output never contains secret values. Entries are addressed by
reference (`sp://entry/<id>`), and secret-bearing fields are reported as
`has_*` flags:

```bash
$ seedpass-js entry get api-token
{ "id": "5", "ref": "sp://entry/5", "label": "api-token",
  "kind": "key_value", "has_value": true, ... }
```

Plaintext leaves the vault only through commands that say so
(`entry reveal`, `entry totp-codes`, `entry export-document`,
`util generate-password`), or through a sink, which delivers a secret to its
destination without routing it through this process's output:

```bash
seedpass-js use api-token --exec ./deploy.sh    # SEEDPASS_SECRET in the child env
seedpass-js use api-token --stdin-to "wc -c"    # quote specs that contain flags
seedpass-js use api-token --clipboard
```

## Scoped tokens for agents

An agent can be given a token that grants exactly what it needs and nothing
else. Secrets are materialized inside the session agent, so the token holder
never receives the seed and can never escalate to owner operations.

```bash
# As the owner:
seedpass-js agent token-issue --scope read use \
    --kind key_value --label-regex '^api-' --uses 2 --ttl 600

# In the agent's process — no mnemonic, no password:
export SEEDPASS_TOKEN=<token>
seedpass-js entry list                       # metadata only
seedpass-js use api-token --exec ./deploy.sh # permitted
seedpass-js entry reveal api-token           # denied: scope 'reveal' not granted

# Back as the owner — every grant, delivery and denial is recorded:
seedpass-js agent audit-verify
seedpass-js agent audit-tail -n 20
```

## Environment

| Variable | Purpose |
|---|---|
| `SEEDPASS_APP_DIR` | Profile directory (default `~/.seedpass`) |
| `SEEDPASS_MNEMONIC` | Parent seed; needed for profile creation, otherwise use the agent |
| `SEEDPASS_PASSWORD` | Master password, for `fingerprint add` and `vault unlock` |
| `SEEDPASS_TOKEN` | Scoped token; puts the CLI in token mode |
| `SEEDPASS_AGENT_SOCK` | Override the agent socket path |
| `SEEDPASS_SECRET` | Set by `use --exec` in the child process only |

## Compatibility

Interoperability with the Python implementation is verified on every change
by `scripts/cross_impl_check.py`: each side opens the other's profiles,
backups round-trip, edits are mutually visible, conflict merges agree, and a
snapshot published by Python restores here with secrets intact. See
`docs/typescript_port_compatibility_matrix.md`.

Not yet ported: PGP RSA keys (not byte-reproducible; ed25519 is at parity),
and the `semantic` and `api` command groups.

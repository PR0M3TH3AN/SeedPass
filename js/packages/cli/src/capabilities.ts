/**
 * Machine-readable capability map (`seedpass-js capabilities --format json`).
 * Mirrors the intent of the Python `seedpass capabilities` surface: automation
 * discovers what this build can do instead of guessing from the version.
 */

export function capabilities(): Record<string, unknown> {
  return {
    name: "seedpass-js",
    port: "typescript",
    protocol: {
      password_gen_versions: [1, 2],
      vault_payload_formats: ["V3", "V2", "fernet"],
      entry_schema_version: 4,
      portable_backup_format: 1,
      nostr_event_kinds: { manifest: 30070, snapshot_chunk: 30071, delta: 30072 },
    },
    agent_surface: {
      reference_scheme: "sp://entry/<id>",
      reference_first_output: true,
      plaintext_egress_commands: [
        "entry reveal",
        "entry totp-codes",
        "util generate-password",
      ],
      sinks: ["clipboard", "exec-env", "stdin-to"],
      exec_env_var: "SEEDPASS_SECRET",
      session_agent: {
        transport: "unix-socket",
        commands: ["agent start/status/stop", "vault unlock/lock"],
        seed_resolution_order: ["SEEDPASS_MNEMONIC env", "session agent"],
      },
    },
    profiles: {
      layout: "python-compatible ~/.seedpass",
      commands: ["fingerprint list/add/switch/remove", "config get/set"],
    },
    tokens: {
      commands: ["agent token-issue/token-list/token-revoke"],
      scopes: ["read", "use", "reveal"],
      constraints: ["kinds", "label_regex", "ttl", "uses"],
      token_env_var: "SEEDPASS_TOKEN",
      enforcement: "session agent (secrets materialized agent-side in token mode)",
      escalation: "token mode can never fall back to owner access",
    },
    audit: {
      commands: ["agent audit-verify", "agent audit-tail"],
      chain: "HMAC-SHA256(prev_sig + canonical_payload), keyed by KEY_INDEX",
    },
    not_yet_ported: [
      "ssh/pgp key material",
      "index0/atlas",
      "approval gates and high-risk partitions",
    ],
  };
}

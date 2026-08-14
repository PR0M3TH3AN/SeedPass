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
    },
    not_yet_ported: [
      "ssh/pgp key material",
      "relay sync commands",
      "profile and config management",
      "index0/atlas",
      "leases and scoped tokens (design: plan section 9.3)",
    ],
  };
}

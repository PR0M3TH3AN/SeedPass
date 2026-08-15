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
    interactive: {
      command: "seedpass-js (no subcommand, on a terminal)",
      model: "numbered menus mirroring Python's legacy (v1) TUI; blank input goes back",
      secrets: "metadata only; 'S' shows and 'C' copies, and Secret Mode routes both to the clipboard",
      non_tty: "prints help",
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
      commands: [
        "fingerprint list/create/add/switch/remove",
        "config get/set",
      ],
      seed_generation: {
        command: "fingerprint create",
        word_counts: [12, 24],
        entropy: "32 bytes from the OS CSPRNG, via BIP-85 app 39 index 0",
        egress:
          "the new phrase goes to --out <0600 file>, --show, or an interactive " +
          "terminal; with none of those the command refuses rather than writing " +
          "the seed into a pipe",
      },
    },
    tokens: {
      commands: ["agent token-issue/token-list/token-revoke"],
      scopes: ["read", "use", "reveal"],
      constraints: ["kinds", "label_regex", "ttl", "uses", "exec_allowlist"],
      token_env_var: "SEEDPASS_TOKEN",
      enforcement: "session agent (secrets materialized agent-side in token mode)",
      escalation:
        "token mode refuses owner operations, but this is a same-uid process " +
        "boundary: a token holder that can read the owner capability file can " +
        "still escalate. See docs/agent_security_model.md.",
    },
    audit: {
      commands: ["agent audit-verify", "agent audit-tail"],
      chain: "HMAC-SHA256(prev_sig + canonical_payload), keyed by KEY_INDEX",
    },
    // Automation branches on this list, so it has to describe this build
    // rather than an earlier one. SSH and ed25519 PGP entries are at
    // byte-for-byte parity with Python and were wrongly listed here.
    not_yet_ported: [
      "pgp RSA keys (ed25519 is supported; RSA generation is not reproducible)",
      "index0/atlas",
      "approval gates and high-risk partitions",
      "semantic (vector search) and api (FastAPI server) command groups",
      "Python's v2/v3 TUIs (interactive mode follows the legacy v1 menus)",
      "QR code display in the TUI (no QR encoder in this build)",
    ],
  };
}

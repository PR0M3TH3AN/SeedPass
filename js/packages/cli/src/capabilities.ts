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
      // Automation issuing tokens has to know this to scope them correctly:
      // label_regex is a SEARCH, not a full match, in both implementations
      // (Python uses re.search). `prod` therefore also matches `not-prod-db`.
      // Anchor it yourself -- `^prod$` -- to get an exact match.
      label_regex_semantics: "search (substring); anchor with ^...$ for exact match",
      // Automation that issues `use` tokens needs this to pick allowlist
      // entries safely: the check covers the command word, not its arguments.
      exec_allowlist_semantics:
        "command word only; the token holder supplies all arguments, so an " +
        "allowlisted binary that can write a file or open a socket can " +
        "return the secret to its caller",
      token_env_var: "SEEDPASS_TOKEN",
      enforcement: "session agent (secrets materialized agent-side in token mode)",
      escalation:
        "token mode refuses owner operations, but this is a same-uid process " +
        "boundary: a token holder that can read the owner capability file can " +
        "still escalate. See docs/agent_security_model.md.",
    },
    api: {
      command: "seedpass-js api",
      base_path: "/api/v1",
      // Loopback by default because this process holds unlocked seeds; a
      // non-loopback bind needs --allow-remote and should sit behind a
      // TLS-terminating proxy.
      binds: "127.0.0.1 unless --allow-remote",
      auth: "bearer token, printed once at startup, never written to disk",
      // A leaked bearer token alone must not read the vault.
      plaintext_routes_require: "X-SeedPass-Password header in addition to the token",
      locked_status: 423,
      unported_status: 501,
    },
    audit: {
      commands: ["agent audit-verify", "agent audit-tail"],
      chain: "HMAC-SHA256(prev_sig + canonical_payload), keyed by KEY_INDEX",
    },
    // Automation branches on this list, so it has to describe this build
    // rather than an earlier one. SSH and ed25519 PGP entries are at
    // byte-for-byte parity with Python and were wrongly listed here.
    // Automation branches on this, so each entry says WHY, not just what.
    // Three of these are choices; one is a hard constraint.
    not_yet_ported: [
      // Hard constraint: PyCryptodome's seeded prime search is not
      // reproducible, so a TS implementation would derive a DIFFERENT key
      // from the same seed. Refusing beats silently diverging.
      "pgp RSA keys (ed25519 is at byte parity; RSA generation is not reproducible)",
      // Python-derived state, recomputed on load. Carried through verbatim by
      // the TS port so a Python profile round-trips, but not computed here.
      "index0/atlas (preserved verbatim on read/write, never recomputed)",
      // Deliberate: agent approval gates, high-risk partitions, job profiles
      // and recovery split. The session agent's scoped tokens cover the
      // automation cases; these add a second authorization model.
      "agent approval gates, high-risk partitions, job profiles, recovery split",
      // Deliberate: the TS interactive mode follows Python's legacy v1 menu
      // tree. See docs/tui_v2_cutover_decision.md.
      "Python's v2/v3 Textual TUIs (interactive mode follows the legacy v1 menus)",
    ],
  };
}

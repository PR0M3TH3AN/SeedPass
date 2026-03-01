# Policy As Code

SeedPass agent policy is stored as versioned JSON (`version: 1`) at:

- `~/.seedpass/agent_policy.json`

The policy file is treated as code: linted, reviewed, and then applied.

## Workflow

1. Create or edit a candidate policy file in source control.
2. Lint and normalize it:

```bash
seedpass agent policy-lint --file ./policy/agent_policy.json
```

3. Review differences against active policy:

```bash
seedpass agent policy-review --file ./policy/agent_policy.json
```

4. Apply with risk gate:

```bash
seedpass agent policy-apply --file ./policy/agent_policy.json
```

If review finds high-risk posture changes (for example `default_effect=allow`,
unsafe output defaults, or broad export enablement), apply is blocked unless
`--allow-risky` is supplied.

## Deterministic Metadata

`policy-lint`, `policy-review`, and `policy-apply` emit:

- `policy_stamp`: export-relevant deterministic stamp.
- `policy_hash`: full normalized-policy SHA-256 hash.

These values make policy changes auditable in CI and change reviews.

Policy-filtered export packages (`mode: policy_filtered`) include deterministic
manifest integrity metadata:

- `included_entry_indexes`
- `included_entry_count`
- `entries_sha256` (canonical hash of filtered entries)

`agent export-manifest-verify` validates these fields against current policy and
detects tampering (for example changed entry kinds or modified entry payloads).

## Remediation Bundles

You can generate an actionable remediation bundle from current posture findings:

```bash
seedpass agent posture-remediate
```

For profile runtime checks (quick unlock, KDF strength, partition unlock drift),
run with broker auth and fingerprint:

```bash
seedpass --fingerprint <fp> agent posture-remediate \
  --check-runtime-config --auth-broker keyring
```

## Legacy Compatibility

Legacy policy keys are still accepted and normalized to the rule model:

- `allow_kinds`
- `deny_private_reveal`
- `allow_export_import`

Normalization keeps backwards compatibility while preserving strict validation
for versioned policy files.

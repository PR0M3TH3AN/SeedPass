# Security Testing and Calibration

This project includes fuzz tests and a calibration routine to tune Argon2 parameters for your hardware.

## Running Fuzz Tests

The fuzz tests exercise encryption and decryption with random data using [Hypothesis](https://hypothesis.readthedocs.io/).
Activate the project's virtual environment and run:

```bash
pytest src/tests/test_encryption_fuzz.py
```

Running the entire test suite will also execute these fuzz tests.

## Calibrating Argon2 Time Cost

Argon2 performance varies by device.  To calibrate the `time_cost` parameter, run the helper function:

```bash
python - <<'PY'
from seedpass.core.config_manager import ConfigManager
from utils.key_derivation import calibrate_argon2_time_cost

# assuming ``cfg`` is a ConfigManager for your profile
calibrate_argon2_time_cost(cfg)
PY
```

The selected `time_cost` is stored in the profile's configuration and used for subsequent key derivations.

## Readiness Documents

- Production readiness checklist: `docs/security_readiness_checklist.md`
- Threat model draft: `docs/threat_model.md`
- Agent autonomy plan: `docs/agent_autonomy_security_plan.md`
- Policy as code workflows: `docs/policy_as_code.md`
- Sync conflict determinism contract: `docs/sync_conflict_contract.md`

## Agent Security Controls (Current)

SeedPass now includes dedicated controls for autonomous and CI usage:

- Non-interactive auth brokers (`env`, `keyring`, `command`, `prompt`).
- Fine-grained policy controls with lint/review/apply flow.
- Scoped, revocable tokens and agent identity binding.
- One-time/N-use secret leases.
- Policy-enforced redaction defaults in agent outputs.
- Approval gates for high-risk operations.
- Secret-class isolation for high-risk material.
- Safer job automation primitives with signed templates and policy stamps.
- Deterministic, policy-filtered export controls with manifest verification.
- Posture checks and remediation generation for drift detection.
- Chained audit log integrity verification.

Use `seedpass capabilities --format json` for machine-readable feature discovery.

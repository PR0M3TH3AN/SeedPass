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

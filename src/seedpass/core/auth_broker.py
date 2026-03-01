from __future__ import annotations

import os
import shlex
import subprocess


class AuthBrokerError(ValueError):
    """Raised when non-interactive password retrieval fails."""


def _password_from_env(var_name: str) -> str:
    value = os.getenv(var_name)
    if not value:
        raise AuthBrokerError(
            f"Missing password env var '{var_name}'. Export it before running this command."
        )
    return value


def _password_from_keyring(service: str, account: str) -> str:
    try:
        import keyring  # type: ignore
    except Exception as exc:
        raise AuthBrokerError(
            "Keyring broker requested but 'keyring' package is not installed."
        ) from exc

    value = keyring.get_password(service, account)
    if not value:
        raise AuthBrokerError(
            f"No secret found in keyring for service='{service}' account='{account}'."
        )
    return value


def _password_from_command(command: str) -> str:
    if not command.strip():
        raise AuthBrokerError("Command broker requires a non-empty --broker-command.")
    try:
        proc = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        detail = f": {stderr}" if stderr else ""
        raise AuthBrokerError(f"Command broker failed{detail}") from exc
    value = (proc.stdout or "").strip()
    if not value:
        raise AuthBrokerError("Command broker returned empty output.")
    return value


def resolve_password(
    *,
    broker: str,
    password_env: str = "SEEDPASS_PASSWORD",
    broker_service: str = "seedpass",
    broker_account: str = "default",
    broker_command: str | None = None,
) -> str:
    """Resolve password using a non-interactive broker strategy."""
    mode = broker.strip().lower()
    if mode == "env":
        return _password_from_env(password_env)
    if mode == "keyring":
        return _password_from_keyring(broker_service, broker_account)
    if mode == "command":
        return _password_from_command(broker_command or "")
    raise AuthBrokerError(f"Unsupported auth broker '{broker}'.")

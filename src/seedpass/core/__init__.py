# seedpass.core/__init__.py

"""Expose password manager components with lazy imports."""

from importlib import import_module

__all__ = ["PasswordManager", "ConfigManager", "Vault", "EntryType", "StateManager"]


def __getattr__(name: str):
    if name == "PasswordManager":
        return import_module(".manager", __name__).PasswordManager
    if name == "ConfigManager":
        return import_module(".config_manager", __name__).ConfigManager
    if name == "Vault":
        return import_module(".vault", __name__).Vault
    if name == "EntryType":
        return import_module(".entry_types", __name__).EntryType
    if name == "StateManager":
        return import_module(".state_manager", __name__).StateManager
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

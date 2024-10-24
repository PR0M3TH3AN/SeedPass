# password_manager/__init__.py

import logging
import traceback

try:
    from .manager import PasswordManager
    logging.info("PasswordManager module imported successfully.")
except Exception as e:
    logging.error(f"Failed to import PasswordManager module: {e}")
    logging.error(traceback.format_exc())  # Log full traceback

__all__ = ['PasswordManager']

# utils/__init__.py

import logging
import traceback

try:
    from .file_lock import lock_file
    from .key_derivation import derive_key_from_password, derive_key_from_parent_seed
    from .checksum import calculate_checksum, verify_checksum
    from .password_prompt import prompt_for_password
    
    logging.info("Modules imported successfully.")
except Exception as e:
    logging.error(f"Failed to import one or more modules: {e}")
    logging.error(traceback.format_exc())  # Log full traceback

__all__ = [
    'derive_key_from_password',
    'derive_key_from_parent_seed',
    'calculate_checksum',
    'verify_checksum',
    'lock_file',
    'prompt_for_password'
]

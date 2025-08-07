# utils/fingerprint_manager.py

import os
import json
import logging
import traceback
from pathlib import Path
from typing import Callable, List, Optional

import shutil  # Ensure shutil is imported if used within the class

from utils.atomic_write import atomic_write
from utils.fingerprint import generate_fingerprint

# Instantiate the logger
logger = logging.getLogger(__name__)


class FingerprintManager:
    """
    FingerprintManager Class

    Handles operations related to fingerprints, including generation, storage,
    listing, selection, and removal. Ensures that each seed is uniquely identified
    by its fingerprint and manages the corresponding directory structure.
    """

    def __init__(self, app_dir: Path):
        """
        Initializes the FingerprintManager.

        Parameters:
            app_dir (Path): The root application directory (e.g., ~/.seedpass).
        """
        self.app_dir = app_dir
        self.fingerprints_file = self.app_dir / "fingerprints.json"
        self._ensure_app_directory()
        (
            self.fingerprints,
            self.current_fingerprint,
            self.names,
        ) = self._load_fingerprints()

    def get_current_fingerprint_dir(self) -> Optional[Path]:
        """
        Retrieves the directory path for the current fingerprint.

        Returns:
            Optional[Path]: The Path object of the current fingerprint directory or None.
        """
        if hasattr(self, "current_fingerprint") and self.current_fingerprint:
            return self.get_fingerprint_directory(self.current_fingerprint)
        else:
            logger.error("No current fingerprint is set.")
            return None

    def _ensure_app_directory(self):
        """
        Ensures that the application directory exists.
        """
        try:
            self.app_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Application directory ensured at {self.app_dir}")
        except Exception as e:
            logger.error(
                f"Failed to create application directory at {self.app_dir}: {e}"
            )
            raise

    def _load_fingerprints(self) -> tuple[list[str], Optional[str], dict[str, str]]:
        """Return stored fingerprints, the last used fingerprint, and name mapping."""
        try:
            if self.fingerprints_file.exists():
                with open(self.fingerprints_file, "r") as f:
                    data = json.load(f)
                fingerprints = data.get("fingerprints", [])
                current = data.get("last_used")
                names = data.get("names", {})
                logger.debug(
                    f"Loaded fingerprints: {fingerprints} (last used: {current})"
                )
                return fingerprints, current, names
            logger.debug(
                "fingerprints.json not found. Initializing empty fingerprint list."
            )
            return [], None, {}
        except Exception as e:
            logger.error(f"Failed to load fingerprints: {e}", exc_info=True)
            return [], None, {}

    def _save_fingerprints(self):
        """
        Saves the current list of fingerprints to the fingerprints.json file.
        """
        try:
            data = {
                "fingerprints": self.fingerprints,
                "last_used": self.current_fingerprint,
                "names": self.names,
            }
            atomic_write(
                self.fingerprints_file,
                lambda f: json.dump(data, f, indent=4),
            )
            logger.debug(
                f"Fingerprints saved: {self.fingerprints} (last used: {self.current_fingerprint})"
            )
        except Exception as e:
            logger.error(f"Failed to save fingerprints: {e}", exc_info=True)
            raise

    def add_fingerprint(self, seed_phrase: str) -> Optional[str]:
        """
        Generates a fingerprint from the seed phrase and adds it to the list.

        Parameters:
            seed_phrase (str): The BIP-39 seed phrase.

        Returns:
            Optional[str]: The generated fingerprint or ``None`` if a profile
                already exists or generation fails.
        """
        fingerprint = generate_fingerprint(seed_phrase)
        if fingerprint and fingerprint not in self.fingerprints:
            self.fingerprints.append(fingerprint)
            self.names.setdefault(fingerprint, "")
            self.current_fingerprint = fingerprint
            self._save_fingerprints()
            logger.info(f"Fingerprint {fingerprint} added successfully.")
            # Create fingerprint directory
            fingerprint_dir = self.app_dir / fingerprint
            fingerprint_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Fingerprint directory created at {fingerprint_dir}")
            return fingerprint
        elif fingerprint in self.fingerprints:
            logger.warning(f"Fingerprint {fingerprint} already exists.")
            raise ValueError("Fingerprint already exists")
        else:
            logger.error("Fingerprint generation failed.")
            return None

    def remove_fingerprint(
        self, fingerprint: str, on_last_removed: Optional[Callable[[], None]] = None
    ) -> bool:
        """Remove a fingerprint and its associated directory.

        Parameters:
            fingerprint (str): The fingerprint to remove.
            on_last_removed (Callable | None): Callback invoked when the last
                fingerprint is deleted.

        Returns:
            bool: True if removed successfully, False otherwise.
        """
        if fingerprint in self.fingerprints:
            try:
                self.fingerprints.remove(fingerprint)
                self.names.pop(fingerprint, None)
                if self.current_fingerprint == fingerprint:
                    self.current_fingerprint = (
                        self.fingerprints[0] if self.fingerprints else None
                    )
                self._save_fingerprints()
                # Remove fingerprint directory
                fingerprint_dir = self.app_dir / fingerprint
                if fingerprint_dir.exists() and fingerprint_dir.is_dir():
                    for child in fingerprint_dir.glob("*"):
                        if child.is_file():
                            child.unlink()
                        elif child.is_dir():
                            shutil.rmtree(child)
                    fingerprint_dir.rmdir()
                logger.info(f"Fingerprint {fingerprint} removed successfully.")
                if not self.fingerprints and on_last_removed:
                    on_last_removed()
                return True
            except Exception as e:
                logger.error(
                    f"Failed to remove fingerprint {fingerprint}: {e}", exc_info=True
                )
                return False
        else:
            logger.warning(f"Fingerprint {fingerprint} does not exist.")
            return False

    def list_fingerprints(self) -> List[str]:
        """
        Lists all available fingerprints.

        Returns:
            List[str]: A list of fingerprint strings.
        """
        logger.debug(f"Listing fingerprints: {self.fingerprints}")
        return self.fingerprints

    def select_fingerprint(self, fingerprint: str) -> bool:
        """
        Selects a fingerprint for the current session.

        Parameters:
            fingerprint (str): The fingerprint to select.

        Returns:
            bool: True if selection is successful, False otherwise.
        """
        if fingerprint in self.fingerprints:
            self.current_fingerprint = fingerprint
            self._save_fingerprints()
            logger.info(f"Fingerprint {fingerprint} selected.")
            return True
        else:
            logger.error(f"Fingerprint {fingerprint} not found.")
            return False

    def set_name(self, fingerprint: str, name: str | None) -> bool:
        """Set a custom name for a fingerprint."""
        if fingerprint not in self.fingerprints:
            return False
        if name:
            self.names[fingerprint] = name
        else:
            self.names.pop(fingerprint, None)
        self._save_fingerprints()
        return True

    def get_name(self, fingerprint: str) -> Optional[str]:
        """Return the custom name for ``fingerprint`` if set."""
        return self.names.get(fingerprint) or None

    def display_name(self, fingerprint: str) -> str:
        """Return name and fingerprint for display."""
        name = self.get_name(fingerprint)
        return f"{name} ({fingerprint})" if name else fingerprint

    def get_fingerprint_directory(self, fingerprint: str) -> Optional[Path]:
        """
        Retrieves the directory path for a given fingerprint.

        Parameters:
            fingerprint (str): The fingerprint.

        Returns:
            Optional[Path]: The Path object of the fingerprint directory or None.
        """
        fingerprint_dir = self.app_dir / fingerprint
        if fingerprint_dir.exists() and fingerprint_dir.is_dir():
            return fingerprint_dir
        else:
            logger.error(f"Directory for fingerprint {fingerprint} does not exist.")
            return None

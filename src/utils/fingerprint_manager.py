# utils/fingerprint_manager.py

import os
import json
import logging
import traceback
from pathlib import Path
from typing import List, Optional

import shutil  # Ensure shutil is imported if used within the class

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
        self.fingerprints, self.current_fingerprint = self._load_fingerprints()

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

    def _load_fingerprints(self) -> tuple[list[str], Optional[str]]:
        """Return stored fingerprints and the last used fingerprint."""
        try:
            if self.fingerprints_file.exists():
                with open(self.fingerprints_file, "r") as f:
                    data = json.load(f)
                fingerprints = data.get("fingerprints", [])
                current = data.get("last_used")
                logger.debug(
                    f"Loaded fingerprints: {fingerprints} (last used: {current})"
                )
                return fingerprints, current
            logger.debug(
                "fingerprints.json not found. Initializing empty fingerprint list."
            )
            return [], None
        except Exception as e:
            logger.error(f"Failed to load fingerprints: {e}", exc_info=True)
            return [], None

    def _save_fingerprints(self):
        """
        Saves the current list of fingerprints to the fingerprints.json file.
        """
        try:
            with open(self.fingerprints_file, "w") as f:
                json.dump(
                    {
                        "fingerprints": self.fingerprints,
                        "last_used": self.current_fingerprint,
                    },
                    f,
                    indent=4,
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
            Optional[str]: The generated fingerprint or None if failed.
        """
        fingerprint = generate_fingerprint(seed_phrase)
        if fingerprint and fingerprint not in self.fingerprints:
            self.fingerprints.append(fingerprint)
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
            return fingerprint
        else:
            logger.error("Fingerprint generation failed.")
            return None

    def remove_fingerprint(self, fingerprint: str) -> bool:
        """
        Removes a fingerprint and its associated directory.

        Parameters:
            fingerprint (str): The fingerprint to remove.

        Returns:
            bool: True if removed successfully, False otherwise.
        """
        if fingerprint in self.fingerprints:
            try:
                self.fingerprints.remove(fingerprint)
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

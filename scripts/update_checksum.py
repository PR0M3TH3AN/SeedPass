import sys
from pathlib import Path

# Ensure src directory is in sys.path for imports
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from utils.checksum import update_checksum_file
from constants import SCRIPT_CHECKSUM_FILE, initialize_app


def main() -> None:
    """Calculate checksum for the main script and write it to SCRIPT_CHECKSUM_FILE."""
    initialize_app()
    script_path = SRC_DIR / "seedpass/core" / "manager.py"
    if not update_checksum_file(str(script_path), str(SCRIPT_CHECKSUM_FILE)):
        raise SystemExit(f"Failed to update checksum for {script_path}")
    print(f"Updated checksum written to {SCRIPT_CHECKSUM_FILE}")


if __name__ == "__main__":
    main()

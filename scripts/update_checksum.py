import sys
from pathlib import Path

# Ensure src directory is in sys.path for imports
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from utils.checksum import calculate_checksum
from constants import SCRIPT_CHECKSUM_FILE


def main() -> None:
    """Calculate checksum for the main script and write it to SCRIPT_CHECKSUM_FILE."""
    script_path = SRC_DIR / "password_manager" / "manager.py"
    checksum = calculate_checksum(str(script_path))
    if checksum is None:
        raise SystemExit(f"Failed to calculate checksum for {script_path}")

    SCRIPT_CHECKSUM_FILE.write_text(checksum)
    print(f"Updated checksum written to {SCRIPT_CHECKSUM_FILE}")


if __name__ == "__main__":
    main()

import sys
import os
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, os.path.abspath("src"))

# Mock seedpass.api._pm before importing api
import seedpass.api
seedpass.api._pm = MagicMock()
# No need to mock is_valid_filename now as I check inline
seedpass.api._token = "testtoken" # Set a dummy token

from seedpass.api import app

client = TestClient(app)

def test_fix():
    evil_path = "/tmp/evil_file"
    response = client.post(
        "/api/v1/vault/backup-parent-seed",
        json={"path": evil_path},
        headers={"Authorization": "Bearer testtoken"}
    )

    assert response.status_code == 400, f"Expected 400, got {response.status_code}"
    assert response.json() == {"detail": "Invalid filename"}

    # Check that handle_backup_reveal_parent_seed was NOT called
    seedpass.api._pm.handle_backup_reveal_parent_seed.assert_not_called()
    print("Fix verified: Rejected arbitrary path.")

    # Test valid filename
    valid_file = "backup.enc"
    response = client.post(
        "/api/v1/vault/backup-parent-seed",
        json={"path": valid_file},
        headers={"Authorization": "Bearer testtoken"}
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    seedpass.api._pm.handle_backup_reveal_parent_seed.assert_called_with(Path(valid_file))
    print("Fix verified: Accepted valid filename.")

if __name__ == "__main__":
    test_fix()

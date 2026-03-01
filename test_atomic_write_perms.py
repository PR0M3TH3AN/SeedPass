import sys
from pathlib import Path

# Add src/utils to path to import atomic_write directly
sys.path.append(str(Path("src/utils").resolve()))

from atomic_write import atomic_write
import os
import stat


def test_atomic_write_permissions():
    test_file = Path("test_permissions.txt")
    if test_file.exists():
        test_file.unlink()

    def write_op(f):
        f.write("content")

    atomic_write(test_file, write_op)

    st = test_file.stat()
    mode = stat.S_IMODE(st.st_mode)
    print(f"File permissions: {oct(mode)}")

    if mode == 0o600:
        print("SUCCESS: Permissions are 0o600")
    else:
        print(f"FAILURE: Permissions are {oct(mode)}")

    test_file.unlink()


if __name__ == "__main__":
    test_atomic_write_permissions()

import re

with open("src/tests/test_ai_tui_agent_harness.py", "r") as f:
    content = f.read()

replacement = """import importlib.util
from pathlib import Path
import sys

import pytest

pytest.importorskip("pty")
pytest.importorskip("termios")"""

content = content.replace("import importlib.util\nfrom pathlib import Path\nimport sys\n\nimport pytest", replacement)

with open("src/tests/test_ai_tui_agent_harness.py", "w") as f:
    f.write(content)

import re

with open("src/tests/test_ai_tui_agent_harness.py", "r") as f:
    content = f.read()

new_content = re.sub(
    r"(import sys\n\nimport pytest)",
    r"import sys\n\nimport pytest\n\npytest.importorskip('pty')",
    content
)

with open("src/tests/test_ai_tui_agent_harness.py", "w") as f:
    f.write(new_content)

"""Compatibility layer for different Python versions."""

import sys

# Ensure the ``imghdr`` module is available for ``pgpy`` on Python 3.13+
try:  # pragma: no cover - only executed on Python >= 3.13
    import imghdr  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback for removed module
    from utils import imghdr_stub

    sys.modules.setdefault("imghdr", imghdr_stub)

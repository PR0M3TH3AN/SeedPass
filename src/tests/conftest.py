import logging
import pytest


@pytest.fixture(autouse=True)
def mute_logging():
    logging.getLogger().setLevel(logging.WARNING)

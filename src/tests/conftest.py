import logging
import pytest


@pytest.fixture(autouse=True)
def mute_logging():
    logging.getLogger().setLevel(logging.WARNING)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--stress",
        action="store_true",
        default=False,
        help="run stress tests",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "stress: long running stress tests")


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if config.getoption("--stress"):
        return

    skip_stress = pytest.mark.skip(reason="need --stress option to run")
    for item in items:
        if "stress" in item.keywords:
            item.add_marker(skip_stress)

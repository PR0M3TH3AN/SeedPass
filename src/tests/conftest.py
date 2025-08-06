import importlib.util
import logging
import pytest


@pytest.fixture(
    params=["asyncio"] + (["trio"] if importlib.util.find_spec("trio") else [])
)
def anyio_backend(request):
    return request.param


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
    parser.addoption(
        "--desktop",
        action="store_true",
        default=False,
        help="run desktop-only tests",
    )
    parser.addoption(
        "--max-entries",
        type=int,
        default=None,
        help="maximum entries for nostr index size test",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "stress: long running stress tests")
    config.addinivalue_line("markers", "desktop: desktop only tests")


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if config.getoption("--stress"):
        return

    skip_stress = pytest.mark.skip(reason="need --stress option to run")
    for item in items:
        if "stress" in item.keywords:
            item.add_marker(skip_stress)

    if not config.getoption("--desktop"):
        skip_desktop = pytest.mark.skip(reason="need --desktop option to run")
        for item in items:
            if "desktop" in item.keywords:
                item.add_marker(skip_desktop)

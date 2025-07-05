import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.seedqr import encode_seedqr


def test_seedqr_standard_example():
    phrase = (
        "vacuum bridge buddy supreme exclude milk consider tail "
        "expand wasp pattern nuclear"
    )
    expected = "192402220235174306311124037817700641198012901210"
    assert encode_seedqr(phrase) == expected

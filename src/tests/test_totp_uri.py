import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.totp import TotpManager


# Test parsing a normal otpauth URI with custom period and digits


def test_parse_otpauth_normal():
    uri = "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&period=45&digits=8"
    label, secret, period, digits = TotpManager.parse_otpauth(uri)
    assert label == "Example"
    assert secret == "JBSWY3DPEHPK3PXP"
    assert period == 45
    assert digits == 8


# URI missing the otpauth:// prefix should raise ValueError


def test_parse_otpauth_missing_prefix():
    with pytest.raises(ValueError):
        TotpManager.parse_otpauth("totp/Example?secret=ABC")


# URI without a secret parameter should raise ValueError


def test_parse_otpauth_missing_secret():
    uri = "otpauth://totp/Example?period=30"
    with pytest.raises(ValueError):
        TotpManager.parse_otpauth(uri)


# Round-trip make_otpauth_uri -> parse_otpauth with label containing spaces


def test_make_otpauth_uri_roundtrip():
    label = "Example Label"
    secret = "JBSWY3DPEHPK3PXP"
    uri = TotpManager.make_otpauth_uri(label, secret, period=30, digits=6)
    parsed = TotpManager.parse_otpauth(uri)
    assert parsed == (label, secret, 30, 6)

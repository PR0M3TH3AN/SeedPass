import builtins
from itertools import cycle

import pytest
import logging

from utils import password_prompt


def test_prompt_new_password(monkeypatch):
    responses = cycle(["goodpass", "goodpass"])
    monkeypatch.setattr(password_prompt, "masked_input", lambda prompt: next(responses))
    result = password_prompt.prompt_new_password()
    assert result == "goodpass"


def test_prompt_new_password_retry(monkeypatch, caplog):
    seq = iter(["pass1", "pass2", "passgood", "passgood"])
    monkeypatch.setattr(password_prompt, "masked_input", lambda prompt: next(seq))
    caplog.set_level(logging.WARNING)
    result = password_prompt.prompt_new_password()
    assert "User entered a password shorter" in caplog.text
    assert result == "passgood"


def test_prompt_existing_password(monkeypatch):
    monkeypatch.setattr(password_prompt, "masked_input", lambda prompt: "mypassword")
    assert password_prompt.prompt_existing_password() == "mypassword"


def test_confirm_action_yes_no(monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda _: "Y")
    assert password_prompt.confirm_action()
    monkeypatch.setattr(builtins, "input", lambda _: "n")
    assert not password_prompt.confirm_action()

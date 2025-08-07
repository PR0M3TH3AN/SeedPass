from main import handle_switch_fingerprint


def test_handle_switch_fingerprint_active_profile(monkeypatch, capsys):
    class DummyFingerprintManager:
        def __init__(self):
            self.fingerprints = ["fp1", "fp2"]

        def list_fingerprints(self):
            return self.fingerprints

        def display_name(self, fp):
            return fp

    class DummyPM:
        def __init__(self):
            self.fingerprint_manager = DummyFingerprintManager()
            self.current_fingerprint = "fp1"
            self.decrypted = False

        def select_fingerprint(self, fingerprint):
            self.decrypted = True
            return True

    pm = DummyPM()
    monkeypatch.setattr("builtins.input", lambda _: "1")

    handle_switch_fingerprint(pm)

    captured = capsys.readouterr()
    assert "already active" in captured.out.lower()
    assert pm.decrypted is False

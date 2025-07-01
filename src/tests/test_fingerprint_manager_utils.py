from utils.fingerprint_manager import FingerprintManager


def test_add_and_remove_fingerprint(tmp_path):
    mgr = FingerprintManager(tmp_path)
    phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    fp = mgr.add_fingerprint(phrase)
    assert fp in mgr.list_fingerprints()
    dir_path = mgr.get_fingerprint_directory(fp)
    assert dir_path and dir_path.exists()
    assert mgr.select_fingerprint(fp)
    assert mgr.get_current_fingerprint_dir() == dir_path
    assert mgr.remove_fingerprint(fp)
    assert fp not in mgr.list_fingerprints()
    assert not dir_path.exists()


def test_remove_nonexistent_fingerprint(tmp_path):
    mgr = FingerprintManager(tmp_path)
    assert not mgr.remove_fingerprint("UNKNOWN")

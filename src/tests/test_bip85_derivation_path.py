from local_bip85.bip85 import BIP85


class DummyChild:
    def PrivateKey(self):
        return self

    def Raw(self):
        return self

    def ToBytes(self):
        return b"\x00" * 32


class DummyCtx:
    def __init__(self):
        self.last_path = None

    def DerivePath(self, path: str):
        self.last_path = path
        return DummyChild()


def test_derivation_paths_for_entropy_lengths():
    bip85 = BIP85(b"\x00" * 64)
    ctx = DummyCtx()
    bip85.bip32_ctx = ctx

    vectors = [
        (16, 12),
        (24, 18),
        (32, 24),
    ]

    for entropy_bytes, word_count in vectors:
        bip85.derive_entropy(
            index=0,
            entropy_bytes=entropy_bytes,
            app_no=39,
            word_count=word_count,
        )
        assert ctx.last_path == f"m/83696968'/39'/0'/{word_count}'/0'"


def test_default_word_count_from_entropy_bytes():
    bip85 = BIP85(b"\x00" * 64)
    ctx = DummyCtx()
    bip85.bip32_ctx = ctx

    bip85.derive_entropy(index=5, entropy_bytes=20, app_no=39)

    assert ctx.last_path == "m/83696968'/39'/0'/20'/5'"

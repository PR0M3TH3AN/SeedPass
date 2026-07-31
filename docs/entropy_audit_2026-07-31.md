# SeedPass — randomness and RNG-integration audit, 2026-07-31

Audit of every security-sensitive random value in `src/`, against a
Coldcard-class checklist: where each bit of unpredictability originates, whether
that source is present in the production artifact, and what happens when it
fails.

## Verdict

**No predictable-fallback defect exists.** Every non-deterministic secret comes
from an OS CSPRNG and fails closed:

- Master seed — `core/manager.py:1810`, `os.urandom(32)`
- AES-GCM nonces — `core/encryption.py:106`, `nostr/snapshot.py:57`, `core/memory_protection.py:21`
- TOTP secrets — `core/totp.py:22`, `os.urandom(20)`
- Argon2 salts — `utils/key_derivation.py:67`, `core/agent_secret_isolation.py:92`
- API tokens, agent leases and approvals — `secrets.token_urlsafe` / `secrets.token_bytes`
  in `seedpass/api.py:201,340`, `cli/agent.py:720,804`, `core/agent_approval.py:65`,
  `core/agent_secret_lease.py:71`, `core/agent_export_policy.py:74`, `core/agent_recovery.py:168`

**The `random` module is not imported anywhere in non-test source.** I checked
explicitly; there are no hits outside `src/tests/`. Nothing seeds a CSPRNG
manually, and nothing uses timestamps, PIDs or device identifiers as entropy.
Master-seed generation re-raises on failure rather than substituting a value.

The deterministic derivation in `core/password_generation.py` is intentional and
correct in kind — deriving passwords reproducibly from a BIP-85 seed is the
product. The findings below are about *how much entropy survives* that
derivation, not about whether it should be deterministic.

---

## The compatibility constraint that governs this whole document

Passwords are **never stored**. `_generate_password_for_entry`
(`core/manager.py:3140`) re-derives them on demand from `(seed, index, length,
policy, gen_version)` every time an entry is displayed.

At the time of this audit an entry record held `index`, `length`, `type` and an
optional `policy` override — and **no algorithm version**. Any change to
`generate_password` therefore silently changed every existing password in every
vault, with no record of the old value and no way for a user to recover it. This
is the same class of constraint BitLogin documents as its "derivation chain is a
compatibility contract" standing rule.

As of 2026-07-31 entries carry `gen_version`, and the parameter defaults to `1`
so an absent field means v1. **The rule this constraint implies is permanent:
no change may ever alter the output of a version that already exists in the
wild.** v1 is frozen forever; a fix that changes derivation goes into a new
version, never into an old one. A patch that "just fixes the bias" in place is a
data-loss event, not an improvement.

`src/tests/test_entropy_integrity.py` enforces this with 18 v1 vectors. A
failure there is never "update the expected value".

---

## Status, 2026-07-31

M4, L1 and M1/M2/M3 have landed. `generate_password` now takes a `gen_version`
argument defaulting to `1`; v1 is frozen and pinned by 18 vectors, and new
password entries are stamped `gen_version: 2`.

| Property (length 16, 200 samples) | v1 | v2 | ceiling |
| --- | --- | --- | --- |
| distinct class compositions | **1** | **82** | — |
| per-character entropy | 6.42 b | **6.53 b** | 6.555 b |
| chi-square over the 94-char alphabet | biased | **96.1** (df=93) | crit ~147 |
| lag-32 repeat rate | repeating pad | **0.0110** | chance 0.0106 |

Existing entries are untouched and stay on v1 until the opt-in upgrade ships.
The remaining open items are L2, L4, L5 and that upgrade UX.

## Open items

### M1 — Every generated password has an identical character-class composition — **DONE 2026-07-31**

Fixed in v2 by deleting the `_balance_distribution` call from the v2 path and
keeping only `_enforce_minimum_counts`-style policy minima. v1 retains it,
frozen. The original analysis follows.

**This is the main finding.**

`_balance_distribution` (`core/password_generation.py:367-408`) partitions the
password into one segment per character class and overwrites *every* position in
each segment with a character of that class. The subsequent HMAC-Fisher-Yates
shuffle randomizes the arrangement but cannot change the multiset.

Measured, 300 passwords per length against a fixed seed:

```
len=  16   distinct class compositions = 1   {U:4,  l:4,  d:4,  s:4}   x300/300
len=  24   distinct class compositions = 1   {U:6,  l:6,  d:6,  s:6}   x300/300
len=  32   distinct class compositions = 1   {U:8,  l:8,  d:8,  s:8}   x300/300
len=  64   distinct class compositions = 1   {U:16, l:16, d:16, s:16}  x300/300
len= 128   distinct class compositions = 1   {U:32, l:32, d:32, s:32}  x300/300
```

Exactly 25% of each class, every time, zero variance. Measured per-character
entropy was **6.42 bits** against a 94-character alphabet. The analytic
prediction for a forced 25/25/25/25 split is
`0.25·log₂(26)·2 + 0.25·log₂(10) + 0.25·log₂(32) + 2 = 6.43 bits` — the
measurement matches, confirming the constraint fully accounts for the deficit.

Cost against an unconstrained draw from the same alphabet:

| length | unconstrained | actual | loss |
| --- | --- | --- | --- |
| 8 | 52.4 b | 46.7 b | **5.7 b** |
| 16 *(default)* | 104.9 b | 96.8 b | **8.1 b** |
| 24 | 157.3 b | 147.4 b | **9.9 b** |
| 32 | 209.7 b | 198.2 b | **11.5 b** |

**Two things to weigh, honestly.** The entropy loss alone is not alarming —
96.8 bits at the default length is far beyond brute-force reach, and nothing in
the docs or code advertises a bits figure that this contradicts. The more
material issue is that the invariant is a **fingerprint**: a password containing
exactly L/4 of each class is a strong signal it came from SeedPass, and it tells
an attacker who has one leaked hash to search the 96.8-bit structured space
rather than the 104.9-bit unstructured one. Unlinkability, not raw strength, is
what this costs.

`_balance_distribution` also buys nothing. `_enforce_minimum_counts`
(`password_generation.py:300`) already guarantees the policy minima — 2 upper, 2
lower, 2 digits, 2 special by default. Forcing the remaining ~92% of positions
into a rigid quota adds no compliance value that the minima do not already
provide.

**Fix.**

1. Add a `gen_version: int` field to password entries, defaulting to `1` when
   absent. Thread it through `_generate_password_for_entry` alongside the
   existing `policy` override.
2. Branch in `generate_password`. **Version 1 must be byte-identical to today's
   behaviour** — do not refactor it, do not "clean it up", pin it with vectors
   (see M4).
3. Version 2: keep `_enforce_minimum_counts`, **delete the
   `_balance_distribution` call**, and fold in the M2/M3 fixes. New entries get
   `gen_version: 2`.
4. Offer an explicit, opt-in per-entry upgrade in the TUI/CLI that makes the
   consequence unmissable: *"This will change this password. Update it at the
   site first, then confirm."* Never bulk-migrate.

**Acceptance.** Regenerating any pre-existing entry yields the identical
password it yielded before the change (v1 vectors green). A fresh entry produces
varied class compositions — assert that 300 v2 passwords at length 16 yield
**more than 20** distinct compositions, against exactly 1 today.

---

### M2 — Modulo bias in character and index selection — **DONE 2026-07-31**

`_map_entropy_to_chars` (`password_generation.py:160`):

```python
password = "".join(alphabet[byte % len(alphabet)] for byte in dk)
```

With the default 94-character alphabet, `256 % 94 = 68`, so 68 characters draw
with probability 3/256 and 26 draw with 2/256. `DeterministicStream` consumers
have the same shape: `% 26` for letters (`256 % 26 = 22`), `% 10` for digits.
The 32-character special set is unbiased only by luck (`256 % 32 = 0`).

The effect is small — roughly 0.02 bits per character — and largely masked by
M1, which overwrites most positions anyway. It is worth fixing because it is
exactly the defect BitLogin's `randomUniformInt` was written to avoid, and
because once M1 lands it stops being masked.

**Fix (v2 only).** Rejection-sample against the derived stream:

```python
def _uniform_index(stream: "DeterministicStream", max_exclusive: int) -> int:
    """Rejection sampling — no modulo bias. Mirrors BitLogin's randomUniformInt."""
    limit = 256 - (256 % max_exclusive)
    while True:
        value = stream.get_value()
        if value < limit:
            return value % max_exclusive
```

Rejection consumes a variable number of stream bytes, which makes M3 a
prerequisite rather than an optional companion — the stream must not run short.

**Acceptance.** Chi-square over 200k v2 draws at modulus 94 is below the
p<0.001 critical value (~147 for df=93). v1 vectors unchanged.

---

### M3 — `DeterministicStream` cycles a 32-byte key — **DONE 2026-07-31**

`password_generation.py:87`:

```python
value = self.dk[self.index % self.length]
```

`dk` is 32 bytes. `MAX_PASSWORD_LENGTH` is 128. For any password longer than 32
characters, `_balance_distribution` consumes the same 32 bytes cyclically, so
positions `j` and `j+32` within a segment are driven by the identical byte.
Wrapping a fixed key is not a stream cipher — it is a repeating pad.

`_add_additional_symbols` already senses the problem and works around it by
breaking when `stream.current_index >= stream.length`
(`password_generation.py:360`), which is a symptom, not a fix.

**Fix (v2 only).** Replace the wrap with a proper expansion. HKDF-Expand `dk` to
the number of bytes actually needed — generously, since M2's rejection sampling
consumes a variable amount — or make `DeterministicStream` generate on demand:

```python
class DeterministicStream:
    def __init__(self, dk: bytes) -> None:
        self._key, self._block, self._pos, self._counter = dk, b"", 0, 0

    def get_value(self) -> int:
        if self._pos >= len(self._block):
            self._block = hmac.new(
                self._key, self._counter.to_bytes(4, "big"), hashlib.sha256
            ).digest()
            self._counter += 1
            self._pos = 0
        value = self._block[self._pos]
        self._pos += 1
        return value
```

This never repeats within any practical length and keeps the derivation fully
deterministic. Delete the `current_index >= length` break in
`_add_additional_symbols` once it lands.

**Acceptance.** A 128-character v2 password shows no period-32 correlation:
assert positional autocorrelation at lag 32 is within noise across 1,000
samples. v1 vectors unchanged.

---

### M4 — No RNG failure tests, and no v1 pinning vectors — **DONE 2026-07-31**

Landed as `src/tests/test_entropy_integrity.py`: 26 tests, inside the
`--determinism-only` gate that `scripts/run_ci_tests.sh` runs before anything
else. 18 frozen vectors span every policy in `POLICIES` and both sides of the
32-byte stream-wrap boundary (lengths 8/16/20/32/33/40/64/128).

Each guard was mutation-verified rather than assumed:

| Mutation | Result |
| --- | --- |
| Remove the `_balance_distribution` call (the M1 change) | all 18 vectors red |
| Perturb the `DeterministicStream` wrap (the M3 change) | all 18 vectors red |
| Change `alphabet[byte % len(alphabet)]` (the M2 change) | all 18 vectors red |
| Add a `sha256(time.time())` fallback to `generate_bip85_seed` | fail-closed test red ("DID NOT RAISE") |

`test_all_zero_entropy_is_not_currently_detected` deliberately pins a **gap**
rather than a guarantee: SeedPass would accept an all-zero `os.urandom` return
and mint a valid-looking mnemonic from it. Read that test's docstring before
"fixing" it — the point is that closing the gap should be a visible, deliberate
change.

**M1, M2 and M3 are now safe to attempt.** The original problem statement follows.

Two gaps, one fix.

**Nothing asserts the RNG fails closed.** No test makes `os.urandom` raise and
checks that seed generation aborts rather than returning something. The current
behaviour is correct — `generate_bip85_seed` re-raises — but nothing in CI would
report it if a future edit added a fallback. A deterministic stream passes every
self-consistency test in the suite; that is precisely how the Coldcard defect
survived its own health check.

**Nothing pins v1 output.** Without vectors, M1–M3 cannot be landed safely at
all, because there is no way to prove v1 still derives what it derived before.

**Fix.** Add `src/tests/test_entropy_integrity.py`:

```python
def test_seed_generation_aborts_when_urandom_fails(monkeypatch):
    monkeypatch.setattr(os, "urandom", _raise(OSError("entropy pool unavailable")))
    with pytest.raises((SeedPassError, OSError)):
        manager.generate_bip85_seed()          # must NOT return a value

def test_encryption_nonce_is_fresh_per_call():
    a, b = em.encrypt_data(b"same"), em.encrypt_data(b"same")
    assert a[3:15] != b[3:15]                  # V3| + 12-byte nonce

def test_v1_password_vectors_are_frozen():
    """Compatibility contract: these outputs are what live vaults re-derive.
    A failure here is never 'update the expected value'."""
    for idx, length, expected in V1_VECTORS:
        assert pg.generate_password(length=length, index=idx) == expected
```

Generate `V1_VECTORS` from the **current** `main` before touching anything —
several indices, several lengths, at least one over 32 characters to cover M3's
territory, and one for each non-default policy (`exclude_ambiguous`,
`special_mode="safe"`, `include_special_chars=False`).

**Acceptance.** All three pass on `main` today. Deliberately breaking
`generate_bip85_seed` to swallow the error must turn the first red — verify
locally, then revert.

---

### L1 — Dead HKDF, and a docstring that documents the wrong algorithm — **DONE 2026-07-31**

`_derive_password_entropy` (`password_generation.py:144-156`) builds an HKDF
instance, derives `hkdf_derived`, and **never uses it** — the function returns
the PBKDF2 output. `generate_password`'s docstring nonetheless states "Use
HKDF-HMAC-SHA256 to derive a key from entropy."

Not a vulnerability: PBKDF2-HMAC-SHA256 over 64 bytes of BIP-85 entropy is
sound, and 100,000 iterations over an already-high-entropy input is harmless
overkill. It is recorded because it is exactly the doc-vs-code drift the
checklist's §5 warns about — a reassuring name in front of a different
implementation is how the Coldcard chain hid.

**Fix.** Delete the unused HKDF block and correct the docstring to describe
PBKDF2. Removing dead code cannot change output, so this one is safe to land
independently of the `gen_version` work — but add it to the v1 vector run
anyway, to prove that.

---

### L2 — Master seed entropy accounting

`generate_bip85_seed` (`core/manager.py:1810-1812`) draws `os.urandom(32)` —
256 bits — then derives a **12-word** mnemonic, which encodes 128. The word
count is hardcoded, while derived seed phrases (`derive_seed_phrase`,
`password_generation.py:519`) default to 24.

128 bits is entirely adequate and this is not a defect. It is recorded because
§6 asks for the accounting to be written down, and because the asymmetry is
surprising: the master secret protecting the whole vault is shorter than the
seeds derived beneath it.

**Fix (optional).** Offer 24 words at profile creation. It costs one parameter
and gives users who want a 256-bit master the option. Existing profiles are
unaffected — this only changes what new seeds look like.

---

### L3 — Broad `except Exception` around crypto

`password_generation.py:280`, `:485`, `core/manager.py:1817`. All of these
log-and-re-raise, so **there is no silent fallback** — the operation aborts, as
it should. Recorded because §13 flags the pattern: a bare `except Exception`
wrapped around key generation is one careless edit away from becoming a
fallback, and it is where the reviewer's eye should go first.

Overlaps with the existing "Replace broad `except Exception: pass` blocks" item
in [`../TODO.md`](../TODO.md); these three are the crypto-path instances and
should be narrowed to the specific exceptions each path can raise.

---

### L4 — `torch/` subsystem — **PARTLY DONE 2026-07-31**

Fixed: the temp filename in `services/memory/index.js` now uses
`randomBytes(8)` instead of `Date.now()` + `Math.random()`, and the
`Math.random`-derived value in `relay-health.mjs` that was called a `nonce` is
renamed `probeSuffix` and drawn from `randomBytes(6)` — it is a public probe
tag, but the name invited reuse of the pattern somewhere it would matter.

**Still open, and it needs a decision:** `torch/_backups/` holds **5240 tracked
files** across six dated snapshots. Untracking them is a large deletion, so it
is not something to do as a side effect of an entropy audit. Two concrete costs
today: they duplicate every security-relevant grep hit, and bare `node --test`
in `torch/` discovers them and fails 18 tests from stale snapshot code. (The
`npm test` script uses explicit paths, so CI is unaffected.)

Separately noted: `torch/` has **no `test/` directory in the repo at all**, so
`npm test` there cannot run as written. Out of scope here, but worth knowing.

The original note follows.

### L4 (original) — `torch/` subsystem

- `torch/src/services/memory/index.js:60` builds a temp filename from
  `Date.now()` + `Math.random()` before an atomic rename. Predictable name;
  low impact in a user-owned directory, but §1 lists unguessable temp names.
  Use `crypto.randomBytes(8).toString('hex')` — a one-line change.
- `torch/src/relay-health.mjs:95` names a `Math.random`-derived value a
  `nonce`. It is a probe tag, not a cryptographic nonce, and is fine as-is —
  but the naming invites a future mistake. Rename to `probeSuffix`.
- `torch/_backups/` contains three stale in-tree copies of this code
  (`backup_2026-02-25T20-04-27-295Z`, `backup_2026-02-26T02-09-18-956Z`,
  `backup_2026-02-26T13-32-51-188Z`). They pollute every security grep with
  duplicate hits. Move out of the working tree or add to `.gitignore`.

---

### L5 — No SBOM — **DONE 2026-07-31**

`dependency-audit.yml` now generates a CycloneDX SBOM from `requirements.lock`
and uploads it. Verified locally with the real tool rather than assumed: the
first flag spelling I wrote (`--output-format` / `--outfile`) does not exist in
`cyclonedx-py` and would have failed in CI. The working form is
`--of json --output-reproducible -o <file>`, which emits CycloneDX 1.6 with 96
components and records the crypto chain at exact versions — `cryptography@46.0.5`,
`bip-utils@2.9.3`, `coincurve@21.0.0`, `pynacl@1.6.2`, `argon2-cffi@25.1.0`,
`bcrypt@4.3.0`, `pycryptodome@3.23.0`.

The original note follows.

### L5 (original) — No SBOM

`dependency-audit.yml` and `release-integrity.yml` cover part of §11/§12, but
no workflow emits a dependency manifest artifact. Add CycloneDX generation
(`pip install cyclonedx-bom && cyclonedx-py requirements requirements.lock`) and
upload it alongside the existing release-integrity artifacts.

Folds naturally into the open supply-chain item in [`../TODO.md`](../TODO.md).

---

## Sequencing

The order matters more here than in the sibling repos, because the compatibility
constraint makes the wrong order destructive.

1. **M4 first, and specifically the v1 vectors.** Nothing else can land safely
   until v1 output is pinned. Generate them from current `main`.
2. **L1** — dead-code deletion, proves the vector harness works.
3. **M1's scaffolding** — the `gen_version` field, defaulted to 1, with v2 not
   yet differing. Confirm every existing entry still derives identically.
4. **M3, then M2** into v2 (stream expansion before rejection sampling — the
   latter needs an unbounded stream).
5. **M1's substance** — drop `_balance_distribution` from v2.
6. **The opt-in upgrade UX.** Ship last, and only once v2 is settled; a user who
   upgrades an entry has changed a live password at a real site.
7. L2, L4, L5 whenever convenient — none interact with the derivation chain.

## Related

- [`crypto_key_management_review.md`](./crypto_key_management_review.md)
- [`security_readiness_checklist.md`](./security_readiness_checklist.md)

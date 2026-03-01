from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from constants import APP_DIR

PRIME = 257
SHARE_PREFIX = "sprec1"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mod_inv(value: int) -> int:
    return pow(value % PRIME, -1, PRIME)


def _coef(secret: bytes, label: str, byte_idx: int, power: int) -> int:
    # Deterministic coefficient derivation for reproducible share generation.
    msg = f"{label}:{byte_idx}:{power}".encode("utf-8")
    digest = hmac.new(secret, msg, hashlib.sha256).digest()
    return int.from_bytes(digest[:2], "big") % PRIME


def _poly_eval_at_x(secret_byte: int, coeffs: list[int], x: int) -> int:
    total = secret_byte % PRIME
    x_pow = x % PRIME
    for coeff in coeffs:
        total = (total + (coeff * x_pow)) % PRIME
        x_pow = (x_pow * x) % PRIME
    return total


def _parse_share_token(token: str) -> dict[str, Any]:
    parts = str(token).split(":", 6)
    if len(parts) != 7 or parts[0] != SHARE_PREFIX:
        raise ValueError("invalid_share_format")
    _prefix, label, threshold, total, index, digest, payload = parts
    try:
        threshold_i = int(threshold)
        total_i = int(total)
        index_i = int(index)
    except ValueError as exc:
        raise ValueError("invalid_share_metadata") from exc
    raw = base64.urlsafe_b64decode(payload.encode("ascii"))
    check = hashlib.sha256(raw).hexdigest()[:16]
    if check != digest:
        raise ValueError("invalid_share_checksum")
    if len(raw) % 2 != 0:
        raise ValueError("invalid_share_payload")
    values = []
    for i in range(0, len(raw), 2):
        v = int.from_bytes(raw[i : i + 2], "big")
        if v < 0 or v >= PRIME:
            raise ValueError("invalid_share_value")
        values.append(v)
    return {
        "label": label,
        "threshold": threshold_i,
        "total": total_i,
        "index": index_i,
        "values": values,
    }


def split_secret(
    secret: str, *, total_shares: int, threshold: int, label: str = "default"
) -> list[str]:
    secret_bytes = secret.encode("utf-8")
    if threshold < 2:
        raise ValueError("threshold_must_be_at_least_2")
    if total_shares < threshold:
        raise ValueError("total_shares_must_be_gte_threshold")
    if total_shares > 32:
        raise ValueError("total_shares_too_large")
    if not secret_bytes:
        raise ValueError("secret_required")
    label_value = str(label).strip() or "default"

    shares: list[str] = []
    for x in range(1, total_shares + 1):
        vals: list[int] = []
        for idx, b in enumerate(secret_bytes):
            coeffs = [
                _coef(secret_bytes, label_value, idx, p) for p in range(1, threshold)
            ]
            vals.append(_poly_eval_at_x(int(b), coeffs, x))
        raw = b"".join(int(v).to_bytes(2, "big") for v in vals)
        digest = hashlib.sha256(raw).hexdigest()[:16]
        payload = base64.urlsafe_b64encode(raw).decode("ascii")
        token = (
            f"{SHARE_PREFIX}:{label_value}:{threshold}:{total_shares}:"
            f"{x}:{digest}:{payload}"
        )
        shares.append(token)
    return shares


def recover_secret(tokens: list[str]) -> str:
    if not tokens:
        raise ValueError("shares_required")
    parsed = [_parse_share_token(t) for t in tokens]
    first = parsed[0]
    label = str(first["label"])
    threshold = int(first["threshold"])
    expected_len = len(first["values"])
    indices: set[int] = set()
    for rec in parsed:
        if str(rec["label"]) != label:
            raise ValueError("share_label_mismatch")
        if int(rec["threshold"]) != threshold:
            raise ValueError("share_threshold_mismatch")
        if len(rec["values"]) != expected_len:
            raise ValueError("share_length_mismatch")
        idx = int(rec["index"])
        if idx in indices:
            raise ValueError("duplicate_share_index")
        indices.add(idx)
    if len(parsed) < threshold:
        raise ValueError("insufficient_shares")

    used = parsed[:threshold]
    xs = [int(v["index"]) % PRIME for v in used]
    out = bytearray()
    for byte_idx in range(expected_len):
        ys = [int(v["values"][byte_idx]) % PRIME for v in used]
        secret_val = 0
        for i in range(threshold):
            num = 1
            den = 1
            xi = xs[i]
            for j in range(threshold):
                if i == j:
                    continue
                xj = xs[j]
                num = (num * (-xj % PRIME)) % PRIME
                den = (den * (xi - xj)) % PRIME
            li = (num * _mod_inv(den)) % PRIME
            secret_val = (secret_val + ys[i] * li) % PRIME
        if secret_val < 0 or secret_val > 255:
            raise ValueError("recovered_secret_out_of_range")
        out.append(secret_val)
    return out.decode("utf-8")


def _drill_key_path() -> Path:
    return APP_DIR / "agent_recovery_drill.key"


def _drill_log_path() -> Path:
    return APP_DIR / "agent_recovery_drills.log"


def _load_drill_key() -> bytes:
    path = _drill_key_path()
    if path.exists():
        return path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    path.write_bytes(key)
    os.chmod(path, 0o600)
    return key


def _latest_drill_sig(path: Path) -> str:
    if not path.exists():
        return "0" * 64
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        return "0" * 64
    try:
        payload = json.loads(lines[-1])
    except Exception:
        return "0" * 64
    return str(payload.get("sig", "0" * 64))


def record_recovery_drill(
    *,
    fingerprint: str,
    backup_path: str,
    simulated: bool,
    expected_max_age_days: int | None = None,
) -> dict[str, Any]:
    path = Path(backup_path).expanduser()
    exists = path.exists()
    size = int(path.stat().st_size) if exists else 0
    modified_ts = float(path.stat().st_mtime) if exists else 0.0
    age_days: int | None = None
    if exists:
        age_days = int((time.time() - modified_ts) // 86400)
    stale = bool(
        age_days is not None
        and expected_max_age_days is not None
        and age_days > int(expected_max_age_days)
    )
    status = "ok" if exists and not stale else "warning"

    record = {
        "timestamp_utc": _utcnow_iso(),
        "fingerprint": str(fingerprint),
        "backup_path": str(path),
        "backup_exists": bool(exists),
        "backup_size": size,
        "backup_age_days": age_days,
        "expected_max_age_days": (
            int(expected_max_age_days) if expected_max_age_days is not None else None
        ),
        "stale": bool(stale),
        "simulated": bool(simulated),
        "status": status,
    }
    log_path = _drill_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    prev_sig = _latest_drill_sig(log_path)
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(
        _load_drill_key(),
        f"{prev_sig}{canonical}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    full = dict(record)
    full["sig"] = sig
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(full, sort_keys=True) + "\n")
    os.chmod(log_path, 0o600)
    return full


def list_recovery_drills(*, limit: int = 20) -> list[dict[str, Any]]:
    path = _drill_log_path()
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    for line in lines[-int(limit) :]:
        try:
            payload = json.loads(line)
        except Exception:
            continue
        if isinstance(payload, dict):
            out.append(payload)
    return out


def verify_recovery_drills(*, limit: int = 200) -> dict[str, Any]:
    path = _drill_log_path()
    if not path.exists():
        return {"valid": True, "checked": 0, "errors": []}
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        return {"valid": True, "checked": 0, "errors": []}
    if int(limit) > 0:
        lines = lines[-int(limit) :]
    key = _load_drill_key()
    prev_sig = "0" * 64
    errors: list[str] = []
    checked = 0
    for idx, line in enumerate(lines):
        try:
            rec = json.loads(line)
        except Exception:
            errors.append(f"invalid_json_line:{idx}")
            continue
        if not isinstance(rec, dict):
            errors.append(f"invalid_record_line:{idx}")
            continue
        sig = str(rec.get("sig", ""))
        if not sig:
            errors.append(f"missing_sig_line:{idx}")
            continue
        body = dict(rec)
        body.pop("sig", None)
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(
            key, f"{prev_sig}{canonical}".encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if expected != sig:
            errors.append(f"sig_mismatch_line:{idx}")
        prev_sig = sig
        checked += 1
    return {"valid": len(errors) == 0, "checked": checked, "errors": errors}

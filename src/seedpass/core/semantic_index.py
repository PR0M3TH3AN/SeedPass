from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

WORD_RE = re.compile(r"[a-z0-9_]+")


@dataclass
class SemanticRecord:
    entry_id: int
    kind: str
    label: str
    text: str
    tokens: set[str]


class SemanticIndex:
    """Local derived semantic index for KB-centric entry retrieval."""

    INDEX_DIRNAME = "semantic_index"
    MANIFEST_FILENAME = "manifest.json"
    RECORDS_FILENAME = "records.json"
    SCHEMA_VERSION = 1
    MODEL_ID = "seedpass-token-overlap-v1"

    ALLOWED_KINDS = {
        "document",
        "note",
        "key_value",
        "password",
        "stored_password",
        "totp",
        "nostr",
        "ssh",
        "pgp",
    }

    def __init__(self, profile_dir: Path) -> None:
        self.profile_dir = Path(profile_dir)
        self.index_dir = self.profile_dir / self.INDEX_DIRNAME
        self.manifest_path = self.index_dir / self.MANIFEST_FILENAME
        self.records_path = self.index_dir / self.RECORDS_FILENAME

    def status(self) -> dict[str, Any]:
        manifest = self._load_manifest()
        records = self._load_records()
        enabled = bool(manifest.get("enabled", False))
        built = bool(manifest.get("built", False))
        return {
            "enabled": enabled,
            "built": built,
            "records": len(records),
            "schema_version": int(manifest.get("schema_version", self.SCHEMA_VERSION)),
            "model_id": str(manifest.get("model_id", self.MODEL_ID)),
            "updated_at": float(manifest.get("updated_at", 0.0)),
        }

    def set_enabled(self, enabled: bool) -> None:
        manifest = self._load_manifest()
        manifest["enabled"] = bool(enabled)
        manifest.setdefault("schema_version", self.SCHEMA_VERSION)
        manifest.setdefault("model_id", self.MODEL_ID)
        manifest["updated_at"] = time.time()
        self._save_manifest(manifest)

    def build(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        records = self._records_from_entries(entries)
        self.index_dir.mkdir(parents=True, exist_ok=True)
        serializable = [
            {
                "entry_id": rec.entry_id,
                "kind": rec.kind,
                "label": rec.label,
                "text": rec.text,
                "tokens": sorted(rec.tokens),
            }
            for rec in records
        ]
        self.records_path.write_text(
            json.dumps(serializable, ensure_ascii=True, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        manifest = self._load_manifest()
        manifest.update(
            {
                "enabled": bool(manifest.get("enabled", False)),
                "built": True,
                "schema_version": self.SCHEMA_VERSION,
                "model_id": self.MODEL_ID,
                "updated_at": time.time(),
                "record_count": len(serializable),
            }
        )
        self._save_manifest(manifest)
        return self.status()

    def rebuild(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        if self.index_dir.exists():
            for path in (self.records_path, self.manifest_path):
                if path.exists():
                    path.unlink()
        return self.build(entries)

    def search(
        self,
        query: str,
        *,
        k: int = 10,
        kind: str | None = None,
    ) -> list[dict[str, Any]]:
        records = self._load_records()
        if not records:
            return []
        q_tokens = self._tokenize(query)
        if not q_tokens:
            return []
        wanted_kind = kind.strip().lower() if kind else None
        scored: list[tuple[float, dict[str, Any]]] = []
        for rec in records:
            rec_kind = str(rec.get("kind", "")).strip().lower()
            if wanted_kind and rec_kind != wanted_kind:
                continue
            tokens = {
                str(item).strip().lower()
                for item in rec.get("tokens", [])
                if str(item).strip()
            }
            if not tokens:
                continue
            inter = len(q_tokens.intersection(tokens))
            if inter <= 0:
                continue
            union = len(q_tokens.union(tokens))
            score = float(inter) / float(union or 1)
            scored.append((score, rec))
        scored.sort(key=lambda item: (-item[0], int(item[1].get("entry_id", 0))))
        out: list[dict[str, Any]] = []
        for score, rec in scored[: max(1, int(k))]:
            out.append(
                {
                    "entry_id": int(rec.get("entry_id", 0)),
                    "kind": str(rec.get("kind", "")),
                    "label": str(rec.get("label", "")),
                    "score": round(score, 6),
                    "excerpt": str(rec.get("text", ""))[:220],
                }
            )
        return out

    def _records_from_entries(
        self, entries: list[dict[str, Any]]
    ) -> list[SemanticRecord]:
        records: list[SemanticRecord] = []
        for entry in entries:
            entry_id = int(entry.get("id", 0) or 0)
            if entry_id <= 0:
                continue
            kind = str(entry.get("kind") or entry.get("type") or "").strip().lower()
            if kind not in self.ALLOWED_KINDS:
                continue
            text = self._extract_text(entry, kind)
            tokens = self._tokenize(text)
            if not text.strip() or not tokens:
                continue
            records.append(
                SemanticRecord(
                    entry_id=entry_id,
                    kind=kind,
                    label=str(entry.get("label", "")),
                    text=text,
                    tokens=tokens,
                )
            )
        return records

    @staticmethod
    def _extract_text(entry: dict[str, Any], kind: str) -> str:
        label = str(entry.get("label", "")).strip()
        notes = str(entry.get("notes", "")).strip()
        tags_raw = entry.get("tags")
        if isinstance(tags_raw, list):
            tags = " ".join(str(tag).strip() for tag in tags_raw if str(tag).strip())
        else:
            tags = str(tags_raw or "").strip()

        parts = [label, notes, tags]

        if kind in {"document", "note"}:
            parts.append(str(entry.get("content", "")).strip())
            parts.append(str(entry.get("file_type", "")).strip())
        elif kind in {"password", "stored_password"}:
            parts.append(str(entry.get("username", "")).strip())
            parts.append(str(entry.get("url", "")).strip())
        elif kind == "key_value":
            parts.append(str(entry.get("key", "")).strip())
            parts.append(str(entry.get("value", "")).strip())
        elif kind == "totp":
            parts.append(str(entry.get("issuer", "")).strip())
        elif kind == "nostr":
            parts.append(str(entry.get("npub", "")).strip())
        elif kind in {"ssh", "pgp"}:
            parts.append(str(entry.get("fingerprint", "")).strip())

        links = entry.get("links")
        if isinstance(links, list):
            for link in links:
                if not isinstance(link, dict):
                    continue
                parts.append(str(link.get("relation", "")).strip())
                parts.append(str(link.get("note", "")).strip())

        return "\n".join(part for part in parts if part)

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        lowered = text.strip().lower()
        if not lowered:
            return set()
        return {match.group(0) for match in WORD_RE.finditer(lowered)}

    def _load_manifest(self) -> dict[str, Any]:
        if not self.manifest_path.exists():
            return {}
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_manifest(self, manifest: dict[str, Any]) -> None:
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2),
            encoding="utf-8",
        )

    def _load_records(self) -> list[dict[str, Any]]:
        if not self.records_path.exists():
            return []
        try:
            data = json.loads(self.records_path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except Exception:
            return []

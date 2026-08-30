"""Data-driven extraction of sensitive objects from untrusted text."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


DEFAULT_LIBRARY = Path(__file__).resolve().parents[2] / "data" / "library" / "sensitive_objects.json"


@dataclass(frozen=True)
class ObjectPattern:
    object_id: str
    category: str
    severity: str
    match_type: str
    pattern: re.Pattern[str]


def _literal_pattern(value: str) -> str:
    """Match an alias as a phrase without treating it as regular expression."""
    escaped = re.escape(value).replace(r"\ ", r"[\s_-]+")
    return rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])"


class SensitiveObjectLibrary:
    """Normalize names, paths, environment keys, and APIs to object IDs."""

    def __init__(self, patterns: Iterable[ObjectPattern], version: str) -> None:
        self.patterns = tuple(patterns)
        self.version = version

    @classmethod
    def load(cls, path: Path = DEFAULT_LIBRARY) -> "SensitiveObjectLibrary":
        data = json.loads(path.read_text(encoding="utf-8"))
        patterns: list[ObjectPattern] = []
        for item in data["objects"]:
            common = (item["id"], item["category"], item["severity"])
            for alias in item.get("aliases", []):
                patterns.append(ObjectPattern(*common, "alias", re.compile(_literal_pattern(alias), re.IGNORECASE)))
            for env_name in item.get("env_patterns", []):
                patterns.append(ObjectPattern(*common, "environment", re.compile(_literal_pattern(env_name), re.IGNORECASE)))
            for pattern in item.get("path_patterns", []):
                patterns.append(ObjectPattern(*common, "path", re.compile(pattern, re.IGNORECASE)))
            for pattern in item.get("api_patterns", []):
                patterns.append(ObjectPattern(*common, "api", re.compile(pattern, re.IGNORECASE)))
        return cls(patterns, str(data["version"]))

    def extract(self, text: str, file: str, *, max_per_object: int = 5) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        confidence = {"path": 1.0, "environment": 1.0, "api": 0.9, "alias": 0.75}
        for entry in self.patterns:
            for match in entry.pattern.finditer(text):
                candidates.append({
                    "object": entry.object_id,
                    "category": entry.category,
                    "severity": entry.severity,
                    "match_type": entry.match_type,
                    "matched_text": match.group(0)[:120],
                    "file": file,
                    "line": text.count("\n", 0, match.start()) + 1,
                    "confidence": confidence[entry.match_type],
                    "start": match.start(),
                    "end": match.end(),
                })

        # Prefer a concrete path/environment/API match over an alias that covers
        # the same characters, while retaining different object interpretations.
        accepted: list[dict[str, Any]] = []
        counts: dict[str, int] = {}
        for candidate in sorted(candidates, key=lambda item: (-item["confidence"], item["start"], -(item["end"] - item["start"]))):
            if counts.get(candidate["object"], 0) >= max_per_object:
                continue
            overlaps = any(
                item["object"] == candidate["object"]
                and candidate["start"] < item["end"]
                and item["start"] < candidate["end"]
                for item in accepted
            )
            if overlaps:
                continue
            accepted.append(candidate)
            counts[candidate["object"]] = counts.get(candidate["object"], 0) + 1
        return sorted(accepted, key=lambda item: (item["file"], item["line"], item["start"], item["object"]))

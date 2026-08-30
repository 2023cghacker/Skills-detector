"""Repository-matched sampling and bounded archive access for ecosystem audits."""

from __future__ import annotations

import csv
import hashlib
import random
import re
import urllib.request
import zipfile
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any


GIB = 1024 ** 3
DEFAULT_TOTAL_BUDGET = 5 * GIB
DEFAULT_ARCHIVE_LIMIT = 256 * 1024 ** 2


def select_repository_matched_rows(
    index_csv: Path, *, per_label: int = 500, seed: int = 1337,
    rest_fraction: float = 0.2, per_repo_cap: int = 10,
) -> list[dict[str, str]]:
    """Select equal safe/suspicious samples from the same downloaded repositories."""
    grouped: dict[tuple[str, str], dict[str, list[dict[str, str]]]] = defaultdict(
        lambda: {"safe": [], "suspicious": []}
    )
    with index_csv.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            label = row.get("classification", "").lower()
            url = row.get("url", "")
            source = row.get("source", "")
            if label not in {"safe", "suspicious"} or not url or url.startswith("[REDACTED"):
                continue
            grouped[(source, url)][label].append(row)

    rng = random.Random(seed)
    targets = {
        "skills.rest": round(per_label * rest_fraction),
        "skillsmp.com": per_label - round(per_label * rest_fraction),
    }
    selected: list[dict[str, str]] = []
    for source, target in targets.items():
        candidates = [
            (url, labels) for (item_source, url), labels in grouped.items()
            if item_source == source and labels["safe"] and labels["suspicious"]
        ]
        rng.shuffle(candidates)
        remaining = target
        for url, labels in candidates:
            if remaining == 0:
                break
            take = min(per_repo_cap, remaining, len(labels["safe"]), len(labels["suspicious"]))
            if take == 0:
                continue
            for label in ("safe", "suspicious"):
                pool = sorted(labels[label], key=lambda item: (item["repo"], item["skill_name"]))
                chosen = rng.sample(pool, take) if len(pool) > take else pool
                selected.extend(chosen)
            remaining -= take
        if remaining:
            raise ValueError(f"insufficient matched {source} rows: missing {remaining} pairs")

    selected.sort(key=lambda item: (item["source"], item["repo"], item["skill_name"], item["classification"]))
    return selected


def resolve_repository_matched_rows(
    index_csv: Path, cache: "ArchiveCache", *, per_label: int = 500,
    seed: int = 1337, rest_fraction: float = 0.2, per_repo_cap: int = 10,
    cached_only: bool = False,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Download candidate repositories and retain only current, resolvable pairs."""
    grouped: dict[tuple[str, str], dict[str, list[dict[str, str]]]] = defaultdict(
        lambda: {"safe": [], "suspicious": []}
    )
    with index_csv.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            label, url, source = row.get("classification", "").lower(), row.get("url", ""), row.get("source", "")
            if label in {"safe", "suspicious"} and url and not url.startswith("[REDACTED"):
                grouped[(source, url)][label].append(row)
    rng = random.Random(seed)
    targets = {"skills.rest": round(per_label * rest_fraction), "skillsmp.com": per_label - round(per_label * rest_fraction)}
    selected: list[dict[str, str]] = []
    repository_failures: list[dict[str, str]] = []
    for source, target in targets.items():
        candidates = [(url, labels) for (item_source, url), labels in grouped.items() if item_source == source and labels["safe"] and labels["suspicious"] and (not cached_only or cache.contains(url))]
        rng.shuffle(candidates)
        remaining = target
        for repo_index, (url, labels) in enumerate(candidates, 1):
            if remaining == 0:
                break
            try:
                archive, _, _ = cache.fetch(url)
                available = available_skill_names_from_zip(archive)
            except Exception as exc:
                repository_failures.append({"source": source, "url_sha256": hashlib.sha256(url.encode()).hexdigest(), "error_type": type(exc).__name__, "error": str(exc)[:500]})
                print(f"[resolve {source} {repo_index}/{len(candidates)}] unavailable; continuing", flush=True)
                continue
            pools = {
                label: [row for row in labels[label] if _normalize_name(row["skill_name"]) in available]
                for label in ("safe", "suspicious")
            }
            take = min(per_repo_cap, remaining, len(pools["safe"]), len(pools["suspicious"]))
            if take:
                for label in ("safe", "suspicious"):
                    pool = sorted(pools[label], key=lambda item: (item["repo"], item["skill_name"]))
                    selected.extend(rng.sample(pool, take) if len(pool) > take else pool)
                remaining -= take
                print(f"[resolve {source}] +{take} pairs, {remaining} remaining", flush=True)
        if remaining:
            raise RuntimeError(f"download budget or live repository coverage left {remaining} unresolved {source} pairs")
    selected.sort(key=lambda item: (item["source"], item["repo"], item["skill_name"], item["classification"]))
    return selected, repository_failures


class ArchiveCache:
    """Download immutable local archive copies without exceeding a hard disk quota."""

    def __init__(
        self, root: Path, *, total_budget: int = DEFAULT_TOTAL_BUDGET,
        archive_limit: int = DEFAULT_ARCHIVE_LIMIT,
    ) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.total_budget = total_budget
        self.archive_limit = archive_limit
        self.used = sum(path.stat().st_size for path in root.glob("*.zip") if path.is_file())
        if self.used > total_budget:
            raise RuntimeError("existing archive cache already exceeds the configured budget")

    def fetch(self, url: str) -> tuple[Path, str, int]:
        key = hashlib.sha256(url.encode()).hexdigest()
        destination = self.root / f"{key}.zip"
        if destination.exists():
            size = destination.stat().st_size
            return destination, _file_sha256(destination), size

        request = urllib.request.Request(url, headers={"User-Agent": "Skills-detector/0.1"})
        partial = self.root / f"{key}.part"
        if partial.exists():
            partial.unlink()
            raise RuntimeError("skipping a repository whose previous download was interrupted")
        downloaded = 0
        try:
            with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as handle:
                declared = int(response.headers.get("Content-Length", "0") or 0)
                if declared > self.archive_limit:
                    raise RuntimeError(f"archive exceeds per-repository limit ({declared} bytes)")
                if declared and self.used + declared > self.total_budget:
                    raise RuntimeError("archive cache would exceed total disk budget")
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > self.archive_limit or self.used + downloaded > self.total_budget:
                        raise RuntimeError("download stopped at configured disk budget")
                    handle.write(chunk)
            partial.replace(destination)
        except Exception:
            if partial.exists():
                partial.unlink()
            raise
        self.used += downloaded
        return destination, _file_sha256(destination), downloaded

    def contains(self, url: str) -> bool:
        key = hashlib.sha256(url.encode()).hexdigest()
        return (self.root / f"{key}.zip").is_file()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def skill_blobs_from_zip(path: Path, skill_name: str) -> dict[str, bytes]:
    """Read one Skill subtree as bytes; archive members are never extracted or executed."""
    normalized_target = _normalize_name(skill_name)
    with zipfile.ZipFile(path) as archive:
        regular: list[zipfile.ZipInfo] = []
        for info in archive.infolist():
            member = PurePosixPath(info.filename.replace("\\", "/"))
            if info.is_dir() or member.is_absolute() or ".." in member.parts:
                continue
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue
            regular.append(info)
        skill_files = [info for info in regular if PurePosixPath(info.filename).name.lower() == "skill.md"]
        exact = [info for info in skill_files if _normalize_name(PurePosixPath(info.filename).parent.name) == normalized_target]
        if not exact:
            exact = [info for info in skill_files if _frontmatter_name(archive.read(info)) == normalized_target]
        if len(exact) != 1:
            if len(skill_files) == 1:
                exact = skill_files
            else:
                raise RuntimeError(f"could not uniquely locate SKILL.md for {skill_name}")
        root = PurePosixPath(exact[0].filename).parent
        blobs: dict[str, bytes] = {}
        total = 0
        for info in regular:
            member = PurePosixPath(info.filename)
            try:
                relative = member.relative_to(root)
            except ValueError:
                continue
            if info.file_size > 256 * 1024 or len(blobs) >= 128:
                continue
            total += info.file_size
            if total > 750_000:
                break
            blobs[relative.as_posix()] = archive.read(info)
        if not any(PurePosixPath(name).name.lower() == "skill.md" for name in blobs):
            raise RuntimeError("selected archive subtree contains no SKILL.md")
        return blobs


def available_skill_names_from_zip(path: Path) -> set[str]:
    """Return normalized names that identify exactly one current SKILL.md."""
    names: dict[str, set[str]] = defaultdict(set)
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            member = PurePosixPath(info.filename.replace("\\", "/"))
            if info.is_dir() or member.is_absolute() or ".." in member.parts or member.name.lower() != "skill.md":
                continue
            location = member.as_posix()
            names[_normalize_name(member.parent.name)].add(location)
            declared = _frontmatter_name(archive.read(info))
            if declared:
                names[declared].add(location)
    return {name for name, locations in names.items() if name and len(locations) == 1}


def _normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _frontmatter_name(content: bytes) -> str:
    text = content[:16_384].decode("utf-8", errors="replace")
    match = re.search(r"(?mi)^name\s*:\s*['\"]?([^'\"\r\n]+)", text)
    return _normalize_name(match.group(1).strip()) if match else ""


def ecosystem_metrics(records: list[dict[str, Any]], requested: int, failures: list[dict[str, Any]]) -> dict[str, Any]:
    by_label: dict[str, Any] = {}
    for label in ("safe", "suspicious"):
        group = [record for record in records if record["dataset_class"] == label]
        decisions = {name: sum(item["decision"] == name for item in group) for name in ("pass", "review", "block")}
        malicious = sum(item["verdict"] == "malicious" for item in group)
        by_label[label] = {"evaluated": len(group), "predicted_malicious": malicious, "decisions": decisions}
    unresolved = sorted({item["sample_id"] for item in failures} - {item["sample_id"] for item in records})
    return {
        "label_semantics": "suspicious is an unconfirmed static-candidate label, not malicious ground truth",
        "coverage": {"requested": requested, "evaluated": len(records), "failed": len(unresolved), "failed_sample_ids": unresolved},
        "by_dataset_class": by_label,
    }

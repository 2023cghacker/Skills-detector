"""Bounded, zero-execution preparation of public Skill datasets."""

from __future__ import annotations

import csv
import gc
import gzip
import hashlib
import json
import random
import time
import urllib.parse
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterable, Iterator


DEFAULT_COMMUNITY_CATEGORIES = (
    "development",
    "data",
    "security",
    "devops",
    "testing",
    "design",
    "documents",
    "productivity",
    "product",
    "marketing",
)
REGISTRY_BASE = "https://majiayu000.github.io/claude-skill-registry-core/"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stable_key(seed: int, *parts: str) -> str:
    return _sha256_bytes((str(seed) + "\0" + "\0".join(parts)).encode())


def _atomic_download(url: str, destination: Path, *, max_bytes: int, retries: int = 3) -> int:
    """Download one bounded file atomically; partial files never become inputs."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file():
        size = destination.stat().st_size
        if size > max_bytes:
            raise RuntimeError(f"existing file exceeds limit: {size} > {max_bytes}")
        return size
    partial = destination.with_suffix(destination.suffix + ".part")
    for attempt in range(1, retries + 1):
        downloaded = 0
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Skills-detector/0.1 research audit"})
            with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as handle:
                declared = int(response.headers.get("Content-Length", "0") or 0)
                if declared > max_bytes:
                    raise RuntimeError(f"declared file size exceeds limit: {declared} > {max_bytes}")
                while True:
                    chunk = response.read(128 * 1024)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > max_bytes:
                        raise RuntimeError(f"download exceeds limit: {downloaded} > {max_bytes}")
                    handle.write(chunk)
            partial.replace(destination)
            return downloaded
        except Exception as exc:
            if partial.exists():
                partial.unlink()
            if isinstance(exc, urllib.error.HTTPError) and exc.code in {400, 401, 403, 404}:
                raise
            if attempt == retries:
                raise
            time.sleep(min(2 ** attempt, 8))
    raise AssertionError("unreachable")


def prepare_malicious_skill_bench_sample(
    primary_parquet: Path,
    split_csv: Path,
    output_dir: Path,
    *,
    per_class: int = 500,
    seed: int = 1337,
) -> dict[str, Any]:
    """Materialize a deterministic balanced subset of the official source-disjoint test split."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    split_members: set[str] = set()
    with split_csv.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            split = (row.get("split") or row.get("source_disjoint_split") or "").lower()
            if split == "test":
                split_members.add(row["benchmark_id"])

    table = pq.read_table(primary_parquet)
    rows = [
        row
        for row in table.to_pylist()
        if row["benchmark_id"] in split_members
        and (row.get("skill_text") or row.get("public_skill_text"))
    ]
    by_label: dict[str, list[dict[str, Any]]] = {"0": [], "1": []}
    for row in rows:
        by_label[str(row["label"])].append(row)
    selected: list[dict[str, Any]] = []
    for label, pool in by_label.items():
        if len(pool) < per_class:
            raise ValueError(f"source-disjoint test has only {len(pool)} rows for label {label}")
        pool.sort(key=lambda row: _stable_key(seed, label, row["benchmark_id"]))
        selected.extend(pool[:per_class])
    selected.sort(key=lambda row: row["benchmark_id"])

    output_dir.mkdir(parents=True, exist_ok=True)
    sample_table = pa.Table.from_pylist(selected, schema=table.schema)
    sample_path = output_dir / "sample.parquet"
    pq.write_table(sample_table, sample_path, compression="zstd")
    manifest = [
        {
            "benchmark_id": row["benchmark_id"],
            "label": "malicious" if str(row["label"]) == "1" else "benign",
            "source_id": row["source_id"],
            "structural_family_id": row.get("structural_family_id"),
            "text_redacted": bool(row.get("text_redacted")),
        }
        for row in selected
    ]
    (output_dir / "manifest.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in manifest), encoding="utf-8"
    )
    summary = {
        "dataset": "ProtectSkills/MaliciousSkillBench",
        "protocol": "official source-disjoint test; deterministic balanced subset",
        "seed": seed,
        "requested": per_class * 2,
        "counts": dict(Counter(row["label"] for row in manifest)),
        "source_counts": dict(Counter(row["source_id"] for row in manifest)),
        "redacted_public_representations": sum(row["text_redacted"] for row in manifest),
        "primary_sha256": _file_sha256(primary_parquet),
        "sample_sha256": _file_sha256(sample_path),
        "sample_bytes": sample_path.stat().st_size,
        "zero_execution": True,
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    del rows, selected, table, sample_table
    gc.collect()
    return summary


def iter_malicious_skill_bench_sample(sample_parquet: Path) -> Iterator[dict[str, Any]]:
    """Yield one public static Skill representation at a time."""
    import pyarrow.parquet as pq

    parquet = pq.ParquetFile(sample_parquet)
    for batch in parquet.iter_batches(batch_size=1):
        row = batch.to_pylist()[0]
        row["effective_text"] = row.get("skill_text") or row.get("public_skill_text")
        yield row
        del row, batch


def _load_gzip_json(path: Path) -> dict[str, Any]:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def registry_skill_path(path: str) -> str:
    """Normalize registry entries that identify either a Skill file or directory."""
    if path.lower().endswith(("skill.md", "skill.mdx")):
        return path
    return path.rstrip("/") + "/SKILL.md"


def fetch_registry_indexes(
    index_dir: Path,
    categories: Iterable[str] = DEFAULT_COMMUNITY_CATEGORIES,
) -> dict[str, Any]:
    """Fetch the current category manifests and all bounded index shards."""
    index_dir.mkdir(parents=True, exist_ok=True)
    index_path = index_dir / "categories-index.json"
    _atomic_download(urllib.parse.urljoin(REGISTRY_BASE, "categories/index.json"), index_path, max_bytes=2 * 1024 * 1024)
    root = json.loads(index_path.read_text(encoding="utf-8"))
    known = {item["name"]: item for item in root["categories"]}
    for category in categories:
        if category not in known:
            raise ValueError(f"unknown registry category: {category}")
        manifest_path = index_dir / category / "manifest.json"
        _atomic_download(
            urllib.parse.urljoin(REGISTRY_BASE, known[category]["manifest"]),
            manifest_path,
            max_bytes=2 * 1024 * 1024,
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for part in manifest["parts"]:
            destination = index_dir / category / Path(part["gzip_path"]).name
            _atomic_download(
                urllib.parse.urljoin(REGISTRY_BASE, part["gzip_path"]),
                destination,
                max_bytes=max(2 * 1024 * 1024, int(part["gzip_bytes"]) + 4096),
            )
    return root


def select_registry_candidates(
    index_dir: Path,
    *,
    categories: Iterable[str] = DEFAULT_COMMUNITY_CATEGORIES,
    target_per_category: int = 100,
    overfetch_factor: int = 3,
    per_repo_cap: int = 5,
    seed: int = 1337,
) -> dict[str, list[dict[str, Any]]]:
    """Select deterministic, repository-capped candidates from a frozen registry snapshot."""
    output: dict[str, list[dict[str, Any]]] = {}
    for category in categories:
        entries: list[dict[str, Any]] = []
        for part in sorted((index_dir / category).glob("part-*.json.gz")):
            entries.extend(_load_gzip_json(part)["skills"])
        entries.sort(key=lambda row: _stable_key(seed, category, row["repo"], row["path"]))
        repo_counts: Counter[str] = Counter()
        chosen: list[dict[str, Any]] = []
        for row in entries:
            if repo_counts[row["repo"]] >= per_repo_cap:
                continue
            chosen.append(row)
            repo_counts[row["repo"]] += 1
            if len(chosen) >= target_per_category * overfetch_factor:
                break
        if len(chosen) < target_per_category:
            raise ValueError(f"insufficient candidates for {category}: {len(chosen)}")
        output[category] = chosen
    return output


def download_registry_sample(
    index_dir: Path,
    output_dir: Path,
    *,
    categories: Iterable[str] = DEFAULT_COMMUNITY_CATEGORIES,
    target_per_category: int = 100,
    per_repo_cap: int = 5,
    seed: int = 1337,
    candidate_overfetch: int = 10,
    total_budget_bytes: int = 512 * 1024 * 1024,
    file_limit_bytes: int = 1024 * 1024,
    workers: int = 8,
) -> dict[str, Any]:
    """Download bounded files concurrently and retain a content-hashed manifest."""
    categories = tuple(categories)
    root_index = json.loads((index_dir / "categories-index.json").read_text(encoding="utf-8"))
    candidates = select_registry_candidates(
        index_dir,
        categories=categories,
        target_per_category=target_per_category,
        overfetch_factor=candidate_overfetch,
        per_repo_cap=per_repo_cap,
        seed=seed,
    )
    sample_root = output_dir / "samples"
    sample_root.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    used = 0
    for category in categories:
        successes = 0
        cursor = 0
        while cursor < len(candidates[category]) and successes < target_per_category:
            batch = candidates[category][cursor:cursor + workers]
            cursor += len(batch)
            jobs: list[tuple[dict[str, Any], str, Path]] = []
            for candidate in batch:
                branch = candidate.get("branch") or "main"
                skill_path = registry_skill_path(candidate["path"])
                quoted_path = "/".join(urllib.parse.quote(part, safe="") for part in skill_path.split("/"))
                url = f"https://raw.githubusercontent.com/{candidate['repo']}/{urllib.parse.quote(branch, safe='')}/{quoted_path}"
                sample_id = _stable_key(seed, category, candidate["repo"], branch, candidate["path"])[:20]
                destination = sample_root / sample_id / "SKILL.md"
                jobs.append((candidate, url, destination))

            def fetch(job: tuple[dict[str, Any], str, Path]) -> tuple[int, str] | Exception:
                _, url, destination = job
                try:
                    size = _atomic_download(url, destination, max_bytes=file_limit_bytes)
                    if size == 0 or not destination.read_bytes().strip():
                        raise RuntimeError("empty SKILL.md")
                    return size, _file_sha256(destination)
                except Exception as exc:
                    return exc

            with ThreadPoolExecutor(max_workers=workers) as executor:
                outcomes = list(executor.map(fetch, jobs))

            for (candidate, _, destination), outcome in zip(jobs, outcomes):
                if successes >= target_per_category:
                    if destination.exists():
                        destination.unlink()
                    continue
                branch = candidate.get("branch") or "main"
                sample_id = destination.parent.name
                try:
                    if isinstance(outcome, Exception):
                        raise outcome
                    size, content_sha256 = outcome
                    if used + size > total_budget_bytes:
                        raise RuntimeError("community sample would exceed total disk budget")
                except Exception as exc:
                    if destination.exists():
                        destination.unlink()
                    failures.append({
                        "category": category,
                        "repo": candidate["repo"],
                        "path": candidate["path"],
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:500],
                    })
                    continue
                used += size
                successes += 1
                records.append({
                    "sample_id": sample_id,
                    "category": category,
                    "repo": candidate["repo"],
                    "branch": branch,
                    "path": candidate["path"],
                    "registry_id": candidate.get("id"),
                    "stars": candidate.get("stars"),
                    "quality_grade": candidate.get("quality_grade"),
                    "security_status": candidate.get("security_status"),
                    "registry_snapshot": root_index["updated_at"],
                    "bytes": size,
                    "sha256": content_sha256,
                })
                if successes % 20 == 0:
                    print(f"[{category}] {successes}/{target_per_category}", flush=True)
        if successes < target_per_category:
            raise RuntimeError(f"only downloaded {successes}/{target_per_category} for {category}")

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "manifest.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in records), encoding="utf-8"
    )
    (output_dir / "failures.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in failures), encoding="utf-8"
    )
    summary = {
        "dataset": "majiayu000/claude-skill-registry current snapshot",
        "registry_snapshot": root_index["updated_at"],
        "registry_total": root_index["total_count"],
        "sampling": "deterministic category-stratified, repository-capped",
        "seed": seed,
        "target_per_category": target_per_category,
        "per_repo_cap": per_repo_cap,
        "counts": dict(Counter(row["category"] for row in records)),
        "downloaded": len(records),
        "failed_attempts": len(failures),
        "content_bytes": used,
        "label_semantics": "unlabeled current-ecosystem sample; registry security signals are metadata, not ground truth",
        "zero_execution": True,
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

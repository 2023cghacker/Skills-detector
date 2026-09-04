"""Command-line interface for scanning and benchmark evaluation."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core import DEFAULT_THRESHOLD, GitSnapshot, public_scan, read_directory, review_document_with_model, review_with_model, scan_blobs
from .dataset_prep import iter_malicious_skill_bench_sample
from .ecosystem import ArchiveCache, ecosystem_metrics, resolve_repository_matched_rows, skill_blobs_from_zip
from .metrics import binary_metrics, bootstrap_ci, triage_metrics
from .pipeline.model_client import DEFAULT_PROVIDER, default_model, require_api_key
from .visualize import write_behavior_graph_dot

DETECTOR_METHOD_VERSION = "multi_artifact_behavior_graph_v3"


def _format_ratio(label: str, numerator: int, denominator: int, value: float) -> str:
    return f"{label}: {numerator}/{denominator}（{value:.2%}）" if denominator else f"{label}: N/A（分母为 0）"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skills-detector")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan one local Skill directory")
    scan.add_argument("path", type=Path)
    scan.add_argument("--mode", choices=("rules", "model", "gpt", "direct"), default="rules")
    scan.add_argument("--provider", choices=("deepseek", "openai"), default=DEFAULT_PROVIDER)
    scan.add_argument("--model", help="provider model ID; defaults to the provider's configured model")
    scan.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    scan.add_argument("--graph-dot", type=Path, help="write the recovered behavior graph as Graphviz DOT")

    evaluate = commands.add_parser("evaluate", help="evaluate a MalSkillsBench checkout")
    evaluate.add_argument("--dataset-repo", type=Path, required=True)
    evaluate.add_argument("--commit", required=True)
    evaluate.add_argument("--labels-csv", default="data/ground_truth/ground_truth_final.csv")
    evaluate.add_argument("--mode", choices=("rules", "model", "gpt", "direct"), default="rules")
    evaluate.add_argument("--provider", choices=("deepseek", "openai"), default=DEFAULT_PROVIDER)
    evaluate.add_argument("--model", help="provider model ID; defaults to the provider's configured model")
    evaluate.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    evaluate.add_argument("--output", type=Path)
    evaluate.add_argument("--limit", type=int, default=0)
    evaluate.add_argument("--per-class-limit", type=int, default=0, help="take the first N sorted samples from each class")
    evaluate.add_argument("--sample-id", help="evaluate one exact Skill_name from the label index")
    evaluate.add_argument("--ablation", choices=("none", "no-high-level"), default="none")
    evaluate.add_argument("--shard-count", type=int, default=1, help="split the sorted benchmark into disjoint shards")
    evaluate.add_argument("--shard-index", type=int, default=0, help="zero-based shard index")
    evaluate.add_argument("--resume", action="store_true", help="resume an incomplete output directory")

    ecosystem = commands.add_parser("evaluate-ecosystem", help="audit a repository-matched safe/suspicious index sample")
    ecosystem.add_argument("--index-csv", type=Path, required=True)
    ecosystem.add_argument("--index-commit", required=True)
    ecosystem.add_argument("--cache", type=Path, required=True)
    ecosystem.add_argument("--output", type=Path, required=True)
    ecosystem.add_argument("--per-label", type=int, default=500)
    ecosystem.add_argument("--seed", type=int, default=1337)
    ecosystem.add_argument("--rest-fraction", type=float, default=0.2)
    ecosystem.add_argument("--per-repo-cap", type=int, default=10)
    ecosystem.add_argument("--max-download-gib", type=float, default=5.0)
    ecosystem.add_argument("--cached-only", action="store_true", help="resolve the sample without downloading new archives")
    ecosystem.add_argument("--mode", choices=("rules", "model", "gpt"), default="rules")
    ecosystem.add_argument("--provider", choices=("deepseek", "openai"), default=DEFAULT_PROVIDER)
    ecosystem.add_argument("--model", help="provider model ID; defaults to the provider's configured model")
    ecosystem.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    ecosystem.add_argument("--resume", action="store_true")

    parquet = commands.add_parser("evaluate-parquet", help="evaluate a labeled static Skill-text Parquet sample")
    parquet.add_argument("--dataset", type=Path, required=True)
    parquet.add_argument("--output", type=Path, required=True)
    parquet.add_argument("--mode", choices=("rules", "model", "direct"), default="rules")
    parquet.add_argument("--provider", choices=("deepseek", "openai"), default=DEFAULT_PROVIDER)
    parquet.add_argument("--model", help="provider model ID; defaults to the provider's configured model")
    parquet.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    parquet.add_argument("--shard-count", type=int, default=1)
    parquet.add_argument("--shard-index", type=int, default=0)
    parquet.add_argument("--resume", action="store_true")

    community = commands.add_parser("audit-community", help="audit an unlabeled frozen community Skill sample")
    community.add_argument("--dataset-dir", type=Path, required=True)
    community.add_argument("--output", type=Path, required=True)
    community.add_argument("--mode", choices=("rules", "model", "direct"), default="rules")
    community.add_argument("--provider", choices=("deepseek", "openai"), default=DEFAULT_PROVIDER)
    community.add_argument("--model", help="provider model ID; defaults to the provider's configured model")
    community.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    community.add_argument("--shard-count", type=int, default=1)
    community.add_argument("--shard-index", type=int, default=0)
    community.add_argument("--resume", action="store_true")
    return parser


def _predict(
    blobs: dict[str, bytes], mode: str, provider: str, model: str,
    threshold: int, ablation: str = "none",
) -> tuple[dict[str, Any], dict[str, int]]:
    scan = scan_blobs(blobs, threshold=threshold)
    if mode == "rules":
        return scan, {}
    if mode == "direct":
        review, usage = review_document_with_model(blobs, model=model, provider=provider)
    else:
        review, usage = review_with_model(
            scan, model=model, provider=provider,
            include_declaration=ablation != "no-high-level",
        )
    scan["verdict"], scan["decision"], scan["confidence"], scan["review"] = review["verdict"], review["decision"], review["confidence"], review
    return scan, usage


def _scan(args: argparse.Namespace) -> int:
    model = args.model or default_model(args.provider)
    if args.mode != "rules":
        require_api_key(args.provider)
    result, usage = _predict(read_directory(args.path), args.mode, args.provider, model, args.threshold)
    if args.graph_dot:
        write_behavior_graph_dot(result, args.graph_dot)
    output = public_scan(result)
    output["usage"] = usage
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


def _rows(path: Path, limit: int, per_class_limit: int = 0) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = [row for row in csv.DictReader(handle) if row.get("Label", "").lower() in {"benign", "malicious"}]
    rows.sort(key=lambda row: row["Skill_name"])
    if per_class_limit:
        selected = []
        for label in ("benign", "malicious"):
            selected.extend(row for row in rows if row["Label"].lower() == label)
        rows = [
            row for label in ("benign", "malicious")
            for row in [item for item in selected if item["Label"].lower() == label][:per_class_limit]
        ]
    return rows[:limit] if limit else rows


def _evaluate(args: argparse.Namespace) -> int:
    model = args.model or default_model(args.provider)
    ablation = getattr(args, "ablation", "none")
    if args.mode != "rules":
        require_api_key(args.provider)
    labels_path = args.dataset_repo / args.labels_csv
    if sum(bool(value) for value in (args.limit, args.per_class_limit, args.sample_id)) > 1:
        raise ValueError("use only one of --limit, --per-class-limit, or --sample-id")
    rows = _rows(labels_path, args.limit, args.per_class_limit)
    if args.sample_id:
        rows = [row for row in rows if row["Skill_name"] == args.sample_id]
        if not rows:
            raise ValueError(f"unknown sample ID: {args.sample_id}")
    shard_count = getattr(args, "shard_count", 1)
    shard_index = getattr(args, "shard_index", 0)
    if shard_count < 1 or not 0 <= shard_index < shard_count:
        raise ValueError("require shard-count >= 1 and 0 <= shard-index < shard-count")
    rows = [row for index, row in enumerate(rows) if index % shard_count == shard_index]
    snapshot = GitSnapshot(args.dataset_repo, args.commit)
    run_name = args.mode if args.mode == "rules" else f"{args.mode}-{args.provider}-{model}"
    output = args.output or Path("runs") / f"{run_name}-{datetime.now(timezone.utc).strftime('%y%m%d-%H%M%S')}"
    if output.exists() and not args.resume:
        raise ValueError(f"output directory already exists: {output}; use --resume for an incomplete run")
    output.mkdir(parents=True, exist_ok=True)
    predictions_path = output / "predictions.jsonl"
    failures_path = output / "failures.jsonl"
    records = []
    if args.resume and predictions_path.exists():
        records = [json.loads(line) for line in predictions_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    completed_ids = {record["sample_id"] for record in records}
    prior_failures = []
    if failures_path.exists():
        prior_failures = [json.loads(line) for line in failures_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    failure_attempts = Counter(item["sample_id"] for item in prior_failures)
    usage_total = Counter()
    for record in records:
        usage_total.update(record.get("usage", {}))
    started = time.perf_counter()

    nominal_calls = 0 if args.mode == "rules" else (1 if args.mode == "direct" else 5)
    config = {"mode": args.mode, "provider": args.provider if args.mode != "rules" else None, "model": model if args.mode != "rules" else None, "ablation": ablation, "detector_method_version": DETECTOR_METHOD_VERSION, "behavior_engine": "multi_artifact_behavior_graph_v2", "model_calls_per_package_nominal_max": nominal_calls, "stage_semantic_attempts_max": 3 if args.mode not in {"rules", "direct"} else 0, "sample_error_policy": "record_and_continue", "threshold": args.threshold, "commit": args.commit, "samples": len(rows), "shard_count": shard_count, "shard_index": shard_index, "zero_execution": True}
    config_path = output / "config.json"
    if args.resume and config_path.exists() and json.loads(config_path.read_text(encoding="utf-8")) != config:
        raise ValueError("resume configuration does not match the existing run")
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    for index, row in enumerate(rows, 1):
        if row["Skill_name"] in completed_ids:
            print(f"[{index:03d}/{len(rows):03d}] {row['Skill_name']} -> resumed", flush=True)
            continue
        try:
            prefix = row["Ground_truth_path"].replace("\\", "/").strip("/")
            blobs = snapshot.package(prefix)
            if not any(Path(name).name.lower() == "skill.md" for name in blobs):
                raise RuntimeError(f"snapshot contains no SKILL.md for row {index}")
            result, usage = _predict(blobs, args.mode, args.provider, model, args.threshold, ablation)
        except Exception as exc:
            failure_attempts[row["Skill_name"]] += 1
            failure = {"sample_id": row["Skill_name"], "index": index, "attempt": failure_attempts[row["Skill_name"]], "completed": len(records), "error_type": type(exc).__name__, "error": str(exc)[:1000], "time_utc": datetime.now(timezone.utc).isoformat()}
            prior_failures.append(failure)
            with failures_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(failure, ensure_ascii=False) + "\n")
            print(f"[{index:03d}/{len(rows):03d}] {row['Skill_name']} -> ERROR ({type(exc).__name__}); continuing", flush=True)
            continue
        usage_total.update(usage)
        record = public_scan(result) | {
            "sample_id": row["Skill_name"], "ground_truth": row["Label"].lower(), "usage": usage,
        }
        records.append(record)
        with predictions_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"[{index:03d}/{len(rows):03d}] {row['Skill_name']} -> {result['verdict']}", flush=True)

    unresolved_failure_ids = sorted({item["sample_id"] for item in prior_failures} - {record["sample_id"] for record in records})
    labels = [record["ground_truth"] == "malicious" for record in records]
    predictions = [record["verdict"] == "malicious" for record in records]
    scores = [record["score"] if args.mode == "rules" else record["confidence"] * (1 if record["verdict"] == "malicious" else -1) for record in records]
    metrics = binary_metrics([int(x) for x in labels], [int(x) for x in predictions], scores)
    metrics["triage"] = triage_metrics([int(x) for x in labels], [record["decision"] for record in records])
    metrics["bootstrap_95_ci"] = bootstrap_ci([int(x) for x in labels], [int(x) for x in predictions], scores)
    metrics["coverage"] = {"requested": len(rows), "evaluated": len(records), "failed": len(unresolved_failure_ids), "failed_sample_ids": unresolved_failure_ids, "failure_attempts": len(prior_failures), "truncated": sum(record["truncated"] for record in records)}
    metrics["usage"], metrics["wall_seconds"] = dict(usage_total), time.perf_counter() - started
    (output / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    matrix = metrics["confusion_matrix"]
    malicious_total = matrix["tp"] + matrix["fn"]
    predicted_malicious = matrix["tp"] + matrix["fp"]
    benign_total = len(records) - sum(labels)
    human = "\n".join((
        _format_ratio("Evaluation Coverage", len(records), len(rows), len(records) / len(rows) if rows else 0.0),
        f"Failed Samples: {len(unresolved_failure_ids)}/{len(rows)}（{len(unresolved_failure_ids) / len(rows):.2%}）" if rows else "Failed Samples: N/A（分母为 0）",
        _format_ratio("Accuracy", matrix["tp"] + matrix["tn"], metrics["n"], metrics["accuracy"]),
        _format_ratio("Malicious Recall", matrix["tp"], malicious_total, metrics["recall"]),
        _format_ratio("Precision", matrix["tp"], predicted_malicious, metrics["precision"]),
        f"F1: {metrics['f1']:.2%}",
        _format_ratio("Malicious BLOCK/REVIEW Coverage", sum(record["ground_truth"] == "malicious" and record["decision"] != "pass" for record in records), malicious_total, metrics["triage"]["malicious_containment_recall"]),
        _format_ratio("Benign PASS Rate", sum(record["ground_truth"] == "benign" and record["decision"] == "pass" for record in records), benign_total, metrics["triage"]["benign_pass_rate"]),
        "",
    ))
    (output / "metrics.md").write_text(human, encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    print(human)
    return 0


def _ecosystem_sample_id(row: dict[str, str]) -> str:
    return f"{row['source']}:{row['repo']}:{row['skill_name']}"


def _evaluate_ecosystem(args: argparse.Namespace) -> int:
    model = args.model or default_model(args.provider)
    if args.mode != "rules":
        require_api_key(args.provider)
    if args.output.exists() and not args.resume:
        raise ValueError(f"output directory already exists: {args.output}; use --resume")
    args.output.mkdir(parents=True, exist_ok=True)
    cache = ArchiveCache(args.cache, total_budget=int(args.max_download_gib * 1024 ** 3))
    manifest_path = args.output / "sample_manifest.jsonl"
    if args.resume:
        if not manifest_path.exists():
            raise ValueError("resume requires an existing sample manifest")
        rows = [json.loads(line) for line in manifest_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        rows, repository_failures = resolve_repository_matched_rows(
            args.index_csv, cache, per_label=args.per_label, seed=args.seed,
            rest_fraction=args.rest_fraction, per_repo_cap=args.per_repo_cap,
            cached_only=args.cached_only,
        )
        manifest_path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
        (args.output / "repository_failures.jsonl").write_text(
            "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in repository_failures),
            encoding="utf-8",
        )
    config = {
        "dataset": "MaliciousAgentSkillsBench", "index_commit": args.index_commit,
        "sampling": "repository-matched safe/suspicious", "per_label": args.per_label,
        "seed": args.seed, "rest_fraction": args.rest_fraction,
        "per_repo_cap": args.per_repo_cap, "mode": args.mode,
        "provider": args.provider if args.mode != "rules" else None,
        "model": model if args.mode != "rules" else None,
        "threshold": args.threshold, "max_download_gib": args.max_download_gib,
        "behavior_engine": "python_ast_interprocedural_v1",
        "cached_only": args.cached_only,
        "zero_execution": True, "label_warning": "suspicious is not malicious ground truth",
    }
    config_path = args.output / "config.json"
    if args.resume and config_path.exists() and json.loads(config_path.read_text(encoding="utf-8")) != config:
        raise ValueError("resume configuration does not match the existing ecosystem run")
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    predictions_path = args.output / "predictions.jsonl"
    failures_path = args.output / "failures.jsonl"
    records = [json.loads(line) for line in predictions_path.read_text(encoding="utf-8").splitlines() if line.strip()] if args.resume and predictions_path.exists() else []
    failures = [json.loads(line) for line in failures_path.read_text(encoding="utf-8").splitlines() if line.strip()] if failures_path.exists() else []
    completed = {record["sample_id"] for record in records}
    failure_attempts = Counter(item["sample_id"] for item in failures)
    usage_total = Counter()
    for record in records:
        usage_total.update(record.get("usage", {}))
    started = time.perf_counter()
    for index, row in enumerate(rows, 1):
        sample_id = _ecosystem_sample_id(row)
        if sample_id in completed:
            print(f"[{index:04d}/{len(rows):04d}] {sample_id} -> resumed", flush=True)
            continue
        try:
            archive, archive_sha256, archive_bytes = cache.fetch(row["url"])
            blobs = skill_blobs_from_zip(archive, row["skill_name"])
            result, usage = _predict(blobs, args.mode, args.provider, model, args.threshold)
        except Exception as exc:
            failure_attempts[sample_id] += 1
            failure = {
                "sample_id": sample_id, "index": index, "attempt": failure_attempts[sample_id],
                "error_type": type(exc).__name__, "error": str(exc)[:1000],
                "time_utc": datetime.now(timezone.utc).isoformat(),
            }
            failures.append(failure)
            with failures_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(failure, ensure_ascii=False) + "\n")
            print(f"[{index:04d}/{len(rows):04d}] {sample_id} -> ERROR; continuing", flush=True)
            continue
        usage_total.update(usage)
        record = public_scan(result) | {
            "sample_id": sample_id, "source": row["source"], "repo": row["repo"],
            "skill_name": row["skill_name"], "dataset_class": row["classification"],
            "archive_sha256": archive_sha256, "archive_bytes": archive_bytes, "usage": usage,
        }
        records.append(record)
        with predictions_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"[{index:04d}/{len(rows):04d}] {sample_id} -> {result['decision']}", flush=True)

    metrics = ecosystem_metrics(records, len(rows), failures)
    metrics["usage"] = dict(usage_total)
    metrics["wall_seconds"] = time.perf_counter() - started
    metrics["archive_cache_bytes"] = cache.used
    metrics["unique_repositories_requested"] = len({row["url"] for row in rows})
    metrics["unique_archives_cached"] = len(list(args.cache.glob("*.zip")))
    (args.output / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    return 0


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _existing_run(output: Path, resume: bool, config: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if output.exists() and not resume:
        raise ValueError(f"output directory already exists: {output}; use --resume")
    output.mkdir(parents=True, exist_ok=True)
    config_path = output / "config.json"
    if resume and config_path.exists() and json.loads(config_path.read_text(encoding="utf-8")) != config:
        raise ValueError("resume configuration does not match the existing run")
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    prediction_path, failure_path = output / "predictions.jsonl", output / "failures.jsonl"
    records = [json.loads(line) for line in prediction_path.read_text(encoding="utf-8").splitlines() if line.strip()] if resume and prediction_path.exists() else []
    failures = [json.loads(line) for line in failure_path.read_text(encoding="utf-8").splitlines() if line.strip()] if failure_path.exists() else []
    return records, failures


def _record_failure(path: Path, failures: list[dict[str, Any]], attempts: Counter[str], sample_id: str, index: int, exc: Exception) -> None:
    attempts[sample_id] += 1
    item = {
        "sample_id": sample_id, "index": index, "attempt": attempts[sample_id],
        "error_type": type(exc).__name__, "error": str(exc)[:1000],
        "time_utc": datetime.now(timezone.utc).isoformat(),
    }
    failures.append(item)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(item, ensure_ascii=False) + "\n")


def _classification_metrics(records: list[dict[str, Any]], failures: list[dict[str, Any]], requested: int) -> dict[str, Any]:
    labels = [int(record["ground_truth"] == "malicious") for record in records]
    predictions = [int(record["verdict"] == "malicious") for record in records]
    scores = [record["score"] if record["mode"] == "rules" else record["confidence"] * (1 if record["verdict"] == "malicious" else -1) for record in records]
    metrics = binary_metrics(labels, predictions, scores)
    metrics["triage"] = triage_metrics(labels, [record["decision"] for record in records])
    metrics["bootstrap_95_ci"] = bootstrap_ci(labels, predictions, scores)
    completed = {record["sample_id"] for record in records}
    unresolved = sorted({item["sample_id"] for item in failures} - completed)
    metrics["coverage"] = {
        "requested": requested, "evaluated": len(records), "failed": len(unresolved),
        "failed_sample_ids": unresolved, "failure_attempts": len(failures),
        "truncated": sum(bool(record["truncated"]) for record in records),
    }
    usage = Counter()
    for record in records:
        usage.update(record.get("usage", {}))
    metrics["usage"] = dict(usage)
    return metrics


def _write_labeled_outputs(output: Path, metrics: dict[str, Any], records: list[dict[str, Any]]) -> None:
    (output / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    matrix = metrics["confusion_matrix"]
    malicious_total = matrix["tp"] + matrix["fn"]
    predicted_malicious = matrix["tp"] + matrix["fp"]
    benign_total = matrix["tn"] + matrix["fp"]
    requested = metrics["coverage"]["requested"]
    human = "\n".join((
        _format_ratio("Evaluation Coverage", len(records), requested, len(records) / requested if requested else 0),
        _format_ratio("Accuracy", matrix["tp"] + matrix["tn"], metrics["n"], metrics["accuracy"]),
        _format_ratio("Malicious Recall", matrix["tp"], malicious_total, metrics["recall"]),
        _format_ratio("Precision", matrix["tp"], predicted_malicious, metrics["precision"]),
        f"F1: {metrics['f1']:.2%}",
        _format_ratio("False Positive Rate", matrix["fp"], benign_total, metrics["fpr"]), "",
    ))
    (output / "metrics.md").write_text(human, encoding="utf-8")


def _evaluate_parquet(args: argparse.Namespace) -> int:
    import pyarrow.parquet as pq

    model = args.model or default_model(args.provider)
    if args.mode != "rules":
        require_api_key(args.provider)
    if args.shard_count < 1 or not 0 <= args.shard_index < args.shard_count:
        raise ValueError("require shard-count >= 1 and 0 <= shard-index < shard-count")
    total = pq.ParquetFile(args.dataset).metadata.num_rows
    requested = sum(index % args.shard_count == args.shard_index for index in range(total))
    config = {
        "dataset": "ProtectSkills/MaliciousSkillBench/source-disjoint-1000",
        "dataset_sha256": _sha256_file(args.dataset), "samples": requested,
        "mode": args.mode, "provider": args.provider if args.mode != "rules" else None,
        "model": model if args.mode != "rules" else None, "threshold": args.threshold,
        "shard_count": args.shard_count, "shard_index": args.shard_index,
        "sample_error_policy": "record_and_continue", "stream_batch_size": 1,
        "input_fields": ["effective_text"], "labels_joined_after_prediction": True,
        "zero_execution": True,
    }
    records, failures = _existing_run(args.output, args.resume, config)
    completed = {record["sample_id"] for record in records}
    attempts = Counter(item["sample_id"] for item in failures)
    started = time.perf_counter()
    for global_index, row in enumerate(iter_malicious_skill_bench_sample(args.dataset)):
        if global_index % args.shard_count != args.shard_index:
            continue
        sample_id = str(row["benchmark_id"])
        display_index = global_index // args.shard_count + 1
        if sample_id in completed:
            continue
        try:
            text = row["effective_text"]
            if not text:
                raise ValueError("empty effective Skill text")
            result, usage = _predict({"SKILL.md": text.encode("utf-8")}, args.mode, args.provider, model, args.threshold)
        except Exception as exc:
            _record_failure(args.output / "failures.jsonl", failures, attempts, sample_id, display_index, exc)
            print(f"[{display_index:04d}/{requested:04d}] {sample_id} -> ERROR; continuing", flush=True)
            continue
        record = public_scan(result) | {
            "sample_id": sample_id, "ground_truth": "malicious" if int(row["label"]) else "benign",
            "mode": args.mode, "usage": usage,
        }
        with (args.output / "predictions.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        records.append(record)
        completed.add(sample_id)
        print(f"[{display_index:04d}/{requested:04d}] {sample_id} -> {result['verdict']}", flush=True)
        del row, text, result
    metrics = _classification_metrics(records, failures, requested)
    metrics["wall_seconds_current_invocation"] = time.perf_counter() - started
    _write_labeled_outputs(args.output, metrics, records)
    print(json.dumps(metrics, indent=2))
    return 0


def _community_metrics(records: list[dict[str, Any]], failures: list[dict[str, Any]], requested: int) -> dict[str, Any]:
    completed = {record["sample_id"] for record in records}
    unresolved = sorted({item["sample_id"] for item in failures} - completed)
    decision_counts = Counter(record["decision"] for record in records)
    verdict_counts = Counter(record["verdict"] for record in records)
    per_category: dict[str, dict[str, Any]] = {}
    for category in sorted({record["category"] for record in records}):
        group = [record for record in records if record["category"] == category]
        per_category[category] = {
            "n": len(group), "decisions": dict(Counter(item["decision"] for item in group)),
            "verdicts": dict(Counter(item["verdict"] for item in group)),
        }
    domains = Counter()
    usage = Counter()
    for record in records:
        usage.update(record.get("usage", {}))
        for risk in record.get("risk_candidates", []):
            domains[risk["domain"]] += 1
    return {
        "ground_truth": None,
        "label_warning": "unlabeled audit; rates are detector outputs, not prevalence or accuracy",
        "coverage": {"requested": requested, "evaluated": len(records), "failed": len(unresolved), "failed_sample_ids": unresolved, "failure_attempts": len(failures), "truncated": sum(bool(record["truncated"]) for record in records)},
        "decisions": dict(decision_counts), "verdicts": dict(verdict_counts),
        "risk_candidate_domains": dict(domains), "per_category": per_category,
        "usage": dict(usage),
    }


def _audit_community(args: argparse.Namespace) -> int:
    model = args.model or default_model(args.provider)
    if args.mode != "rules":
        require_api_key(args.provider)
    if args.shard_count < 1 or not 0 <= args.shard_index < args.shard_count:
        raise ValueError("require shard-count >= 1 and 0 <= shard-index < shard-count")
    manifest_path = args.dataset_dir / "manifest.jsonl"
    manifest = [json.loads(line) for line in manifest_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = [row for index, row in enumerate(manifest) if index % args.shard_count == args.shard_index]
    config = {
        "dataset": "current-community-skills-1000", "manifest_sha256": _sha256_file(manifest_path),
        "samples": len(rows), "mode": args.mode,
        "provider": args.provider if args.mode != "rules" else None,
        "model": model if args.mode != "rules" else None, "threshold": args.threshold,
        "shard_count": args.shard_count, "shard_index": args.shard_index,
        "sample_error_policy": "record_and_continue", "ground_truth": None,
        "registry_metadata_excluded_from_detector": True, "zero_execution": True,
    }
    records, failures = _existing_run(args.output, args.resume, config)
    completed = {record["sample_id"] for record in records}
    attempts = Counter(item["sample_id"] for item in failures)
    started = time.perf_counter()
    for index, row in enumerate(rows, 1):
        sample_id = row["sample_id"]
        if sample_id in completed:
            continue
        try:
            skill_path = args.dataset_dir / "samples" / sample_id / "SKILL.md"
            raw = skill_path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != row["sha256"]:
                raise ValueError("Skill content hash does not match frozen manifest")
            result, usage = _predict({"SKILL.md": raw}, args.mode, args.provider, model, args.threshold)
        except Exception as exc:
            _record_failure(args.output / "failures.jsonl", failures, attempts, sample_id, index, exc)
            print(f"[{index:04d}/{len(rows):04d}] {sample_id} -> ERROR; continuing", flush=True)
            continue
        record = public_scan(result) | {
            "sample_id": sample_id, "category": row["category"], "repo": row["repo"],
            "path": row["path"], "mode": args.mode, "usage": usage,
        }
        with (args.output / "predictions.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        records.append(record)
        completed.add(sample_id)
        print(f"[{index:04d}/{len(rows):04d}] {sample_id} -> {result['decision']}", flush=True)
        del raw, result
    metrics = _community_metrics(records, failures, len(rows))
    metrics["wall_seconds_current_invocation"] = time.perf_counter() - started
    (args.output / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    return 0


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "evaluate-ecosystem":
            return _evaluate_ecosystem(args)
        if args.command == "evaluate-parquet":
            return _evaluate_parquet(args)
        if args.command == "audit-community":
            return _audit_community(args)
        return _evaluate(args)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

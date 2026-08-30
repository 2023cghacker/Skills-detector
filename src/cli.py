"""Command-line interface for scanning and benchmark evaluation."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core import DEFAULT_THRESHOLD, GitSnapshot, public_scan, read_directory, review_with_model, scan_blobs
from .metrics import binary_metrics, bootstrap_ci, triage_metrics
from .pipeline.model_client import DEFAULT_PROVIDER, default_model, require_api_key


def _format_ratio(label: str, numerator: int, denominator: int, value: float) -> str:
    return f"{label}: {numerator}/{denominator}（{value:.2%}）" if denominator else f"{label}: N/A（分母为 0）"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skills-detector")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan one local Skill directory")
    scan.add_argument("path", type=Path)
    scan.add_argument("--mode", choices=("rules", "model", "gpt"), default="rules")
    scan.add_argument("--provider", choices=("deepseek", "openai"), default=DEFAULT_PROVIDER)
    scan.add_argument("--model", help="provider model ID; defaults to the provider's configured model")
    scan.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)

    evaluate = commands.add_parser("evaluate", help="evaluate a MalSkillsBench checkout")
    evaluate.add_argument("--dataset-repo", type=Path, required=True)
    evaluate.add_argument("--commit", required=True)
    evaluate.add_argument("--labels-csv", default="data/ground_truth/ground_truth_final.csv")
    evaluate.add_argument("--mode", choices=("rules", "model", "gpt"), default="rules")
    evaluate.add_argument("--provider", choices=("deepseek", "openai"), default=DEFAULT_PROVIDER)
    evaluate.add_argument("--model", help="provider model ID; defaults to the provider's configured model")
    evaluate.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    evaluate.add_argument("--output", type=Path)
    evaluate.add_argument("--limit", type=int, default=0)
    evaluate.add_argument("--per-class-limit", type=int, default=0, help="take the first N sorted samples from each class")
    evaluate.add_argument("--sample-id", help="evaluate one exact Skill_name from the label index")
    evaluate.add_argument("--resume", action="store_true", help="resume an incomplete output directory")
    return parser


def _predict(
    blobs: dict[str, bytes], mode: str, provider: str, model: str,
    threshold: int,
) -> tuple[dict[str, Any], dict[str, int]]:
    scan = scan_blobs(blobs, threshold=threshold)
    if mode == "rules":
        return scan, {}
    review, usage = review_with_model(scan, model=model, provider=provider)
    scan["verdict"], scan["decision"], scan["confidence"], scan["review"] = review["verdict"], review["decision"], review["confidence"], review
    return scan, usage


def _scan(args: argparse.Namespace) -> int:
    model = args.model or default_model(args.provider)
    if args.mode != "rules":
        require_api_key(args.provider)
    result, usage = _predict(read_directory(args.path), args.mode, args.provider, model, args.threshold)
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
    snapshot = GitSnapshot(args.dataset_repo, args.commit)
    run_name = args.mode if args.mode == "rules" else f"{args.provider}-{model}"
    output = args.output or Path("runs") / f"{run_name}-{datetime.now(timezone.utc).strftime('%y%m%d-%H%M%S')}"
    if output.exists() and not args.resume:
        raise ValueError(f"output directory already exists: {output}; use --resume for an incomplete run")
    output.mkdir(parents=True, exist_ok=True)
    predictions_path = output / "predictions.jsonl"
    records = []
    if args.resume and predictions_path.exists():
        records = [json.loads(line) for line in predictions_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    completed_ids = {record["sample_id"] for record in records}
    usage_total = Counter()
    for record in records:
        usage_total.update(record.get("usage", {}))
    started = time.perf_counter()

    config = {"mode": args.mode, "provider": args.provider if args.mode != "rules" else None, "model": model if args.mode != "rules" else None, "model_calls_per_package_max": 3 if args.mode != "rules" else 0, "threshold": args.threshold, "commit": args.commit, "samples": len(rows), "zero_execution": True}
    config_path = output / "config.json"
    if args.resume and config_path.exists() and json.loads(config_path.read_text(encoding="utf-8")) != config:
        raise ValueError("resume configuration does not match the existing run")
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    for index, row in enumerate(rows, 1):
        if row["Skill_name"] in completed_ids:
            print(f"[{index:03d}/{len(rows):03d}] {row['Skill_name']} -> resumed", flush=True)
            continue
        prefix = row["Ground_truth_path"].replace("\\", "/").strip("/")
        blobs = snapshot.package(prefix)
        if not any(Path(name).name.lower() == "skill.md" for name in blobs):
            raise RuntimeError(f"snapshot contains no SKILL.md for row {index}")
        try:
            result, usage = _predict(blobs, args.mode, args.provider, model, args.threshold)
        except Exception as exc:
            failure = {"sample_id": row["Skill_name"], "index": index, "completed": len(records), "error_type": type(exc).__name__, "error": str(exc)[:1000], "time_utc": datetime.now(timezone.utc).isoformat()}
            (output / "failure.json").write_text(json.dumps(failure, indent=2) + "\n", encoding="utf-8")
            raise
        usage_total.update(usage)
        record = public_scan(result) | {
            "sample_id": row["Skill_name"], "ground_truth": row["Label"].lower(), "usage": usage,
        }
        records.append(record)
        with predictions_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"[{index:03d}/{len(rows):03d}] {row['Skill_name']} -> {result['verdict']}", flush=True)

    if (output / "failure.json").exists():
        (output / "failure.json").unlink()
    labels = [record["ground_truth"] == "malicious" for record in records]
    predictions = [record["verdict"] == "malicious" for record in records]
    scores = [record["score"] if args.mode == "rules" else record["confidence"] * (1 if record["verdict"] == "malicious" else -1) for record in records]
    metrics = binary_metrics([int(x) for x in labels], [int(x) for x in predictions], scores)
    metrics["triage"] = triage_metrics([int(x) for x in labels], [record["decision"] for record in records])
    metrics["bootstrap_95_ci"] = bootstrap_ci([int(x) for x in labels], [int(x) for x in predictions], scores)
    metrics["coverage"] = {"requested": len(rows), "evaluated": len(records), "truncated": sum(record["truncated"] for record in records)}
    metrics["usage"], metrics["wall_seconds"] = dict(usage_total), time.perf_counter() - started
    (output / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    matrix = metrics["confusion_matrix"]
    malicious_total = matrix["tp"] + matrix["fn"]
    predicted_malicious = matrix["tp"] + matrix["fp"]
    benign_total = len(records) - sum(labels)
    human = "\n".join((
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


def main() -> int:
    args = _parser().parse_args()
    try:
        return _scan(args) if args.command == "scan" else _evaluate(args)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

"""Command-line interface for scanning and benchmark evaluation."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core import DEFAULT_MODEL, DEFAULT_THRESHOLD, GitSnapshot, public_scan, read_directory, review_with_gpt, scan_blobs
from .metrics import binary_metrics, bootstrap_ci


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skills-detector")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan one local Skill directory")
    scan.add_argument("path", type=Path)
    scan.add_argument("--mode", choices=("rules", "gpt"), default="rules")
    scan.add_argument("--model", default=DEFAULT_MODEL)
    scan.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)

    evaluate = commands.add_parser("evaluate", help="evaluate a MalSkillsBench checkout")
    evaluate.add_argument("--dataset-repo", type=Path, required=True)
    evaluate.add_argument("--commit", required=True)
    evaluate.add_argument("--labels-csv", default="data/ground_truth/ground_truth_final.csv")
    evaluate.add_argument("--mode", choices=("rules", "gpt"), default="rules")
    evaluate.add_argument("--model", default=DEFAULT_MODEL)
    evaluate.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    evaluate.add_argument("--output", type=Path)
    evaluate.add_argument("--limit", type=int, default=0)
    return parser


def _predict(blobs: dict[str, bytes], mode: str, model: str, threshold: int) -> tuple[dict[str, Any], dict[str, int]]:
    scan = scan_blobs(blobs, threshold=threshold)
    if mode == "rules":
        return scan, {}
    review, usage = review_with_gpt(scan, model=model)
    scan["verdict"], scan["decision"], scan["confidence"], scan["review"] = review["verdict"], review["decision"], review["confidence"], review
    return scan, usage


def _scan(args: argparse.Namespace) -> int:
    if args.mode == "gpt" and not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set")
    result, usage = _predict(read_directory(args.path), args.mode, args.model, args.threshold)
    output = public_scan(result)
    output["usage"] = usage
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


def _rows(path: Path, limit: int) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = [row for row in csv.DictReader(handle) if row.get("Label", "").lower() in {"benign", "malicious"}]
    rows.sort(key=lambda row: row["Skill_name"])
    return rows[:limit] if limit else rows


def _evaluate(args: argparse.Namespace) -> int:
    if args.mode == "gpt" and not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set")
    labels_path = args.dataset_repo / args.labels_csv
    rows = _rows(labels_path, args.limit)
    snapshot = GitSnapshot(args.dataset_repo, args.commit)
    output = args.output or Path("runs") / f"{args.mode}-{datetime.now(timezone.utc).strftime('%y%m%d-%H%M%S')}"
    output.mkdir(parents=True, exist_ok=False)
    records, usage_total = [], Counter()
    started = time.perf_counter()

    for index, row in enumerate(rows, 1):
        prefix = row["Ground_truth_path"].replace("\\", "/").strip("/")
        blobs = snapshot.package(prefix)
        if not any(Path(name).name.lower() == "skill.md" for name in blobs):
            raise RuntimeError(f"snapshot contains no SKILL.md for row {index}")
        result, usage = _predict(blobs, args.mode, args.model, args.threshold)
        usage_total.update(usage)
        record = public_scan(result) | {
            "sample_id": row["Skill_name"], "ground_truth": row["Label"].lower(),
        }
        records.append(record)
        print(f"[{index:03d}/{len(rows):03d}] {row['Skill_name']} -> {result['verdict']}", flush=True)

    with (output / "predictions.jsonl").open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    labels = [record["ground_truth"] == "malicious" for record in records]
    predictions = [record["verdict"] == "malicious" for record in records]
    scores = [record["score"] if args.mode == "rules" else record["confidence"] * (1 if record["verdict"] == "malicious" else -1) for record in records]
    metrics = binary_metrics([int(x) for x in labels], [int(x) for x in predictions], scores)
    metrics["bootstrap_95_ci"] = bootstrap_ci([int(x) for x in labels], [int(x) for x in predictions], scores)
    metrics["coverage"] = {"requested": len(rows), "evaluated": len(records), "truncated": sum(record["truncated"] for record in records)}
    metrics["usage"], metrics["wall_seconds"] = dict(usage_total), time.perf_counter() - started
    config = {"mode": args.mode, "model": args.model if args.mode == "gpt" else None, "threshold": args.threshold, "commit": args.commit, "samples": len(rows), "zero_execution": True}
    (output / "config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    (output / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    matrix = metrics["confusion_matrix"]
    human = "\n".join((
        f"Accuracy: {matrix['tp'] + matrix['tn']}/{metrics['n']}（{metrics['accuracy']:.2%}）",
        f"Malicious Recall: {matrix['tp']}/{matrix['tp'] + matrix['fn']}（{metrics['recall']:.2%}）",
        f"Precision: {matrix['tp']}/{matrix['tp'] + matrix['fp']}（{metrics['precision']:.2%}）",
        f"F1: {metrics['f1']:.2%}",
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

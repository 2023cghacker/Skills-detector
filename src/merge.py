"""Merge disjoint evaluator shards and recompute corpus-level metrics."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .metrics import binary_metrics, bootstrap_ci, triage_metrics


def _ratio(label: str, numerator: int, denominator: int, value: float) -> str:
    return f"{label}: {numerator}/{denominator}（{value:.2%}）" if denominator else f"{label}: N/A（分母为 0）"


def merge_runs(inputs: list[Path], output: Path) -> dict:
    if output.exists():
        raise ValueError(f"output directory already exists: {output}")
    configs = [json.loads((path / "config.json").read_text(encoding="utf-8")) for path in inputs]
    invariant_keys = {key for key in configs[0] if key not in {"samples", "shard_index"}}
    for config in configs[1:]:
        if any(config.get(key) != configs[0].get(key) for key in invariant_keys):
            raise ValueError("input shard configurations do not match")
    records = []
    failures = []
    for path in inputs:
        prediction_path = path / "predictions.jsonl"
        if prediction_path.exists():
            records.extend(json.loads(line) for line in prediction_path.read_text(encoding="utf-8").splitlines() if line.strip())
        failure_path = path / "failures.jsonl"
        if failure_path.exists():
            failures.extend(json.loads(line) for line in failure_path.read_text(encoding="utf-8").splitlines() if line.strip())
    ids = [record["sample_id"] for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("input shards contain duplicate sample identifiers")
    records.sort(key=lambda item: item["sample_id"])
    completed = set(ids)
    unresolved = sorted({item["sample_id"] for item in failures} - completed)
    requested = sum(int(config["samples"]) for config in configs)
    labels = [int(record["ground_truth"] == "malicious") for record in records]
    predictions = [int(record["verdict"] == "malicious") for record in records]
    scores = [record["confidence"] * (1 if record["verdict"] == "malicious" else -1) for record in records]
    metrics = binary_metrics(labels, predictions, scores)
    metrics["triage"] = triage_metrics(labels, [record["decision"] for record in records])
    metrics["bootstrap_95_ci"] = bootstrap_ci(labels, predictions, scores)
    metrics["coverage"] = {"requested": requested, "evaluated": len(records), "failed": len(unresolved), "failed_sample_ids": unresolved, "failure_attempts": len(failures), "truncated": sum(record["truncated"] for record in records)}
    usage = Counter()
    for record in records:
        usage.update(record.get("usage", {}))
    metrics["usage"] = dict(usage)
    output.mkdir(parents=True)
    (output / "config.json").write_text(json.dumps({**configs[0], "samples": requested, "shard_index": "merged", "merged_inputs": [str(path) for path in inputs]}, indent=2) + "\n", encoding="utf-8")
    (output / "predictions.jsonl").write_text("".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records), encoding="utf-8")
    (output / "failures.jsonl").write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in failures), encoding="utf-8")
    (output / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    matrix = metrics["confusion_matrix"]
    malicious_total = matrix["tp"] + matrix["fn"]
    predicted_malicious = matrix["tp"] + matrix["fp"]
    benign_total = len(records) - sum(labels)
    human = "\n".join((
        _ratio("Evaluation Coverage", len(records), requested, len(records) / requested if requested else 0),
        _ratio("Accuracy", matrix["tp"] + matrix["tn"], len(records), metrics["accuracy"]),
        _ratio("Malicious Recall", matrix["tp"], malicious_total, metrics["recall"]),
        _ratio("Precision", matrix["tp"], predicted_malicious, metrics["precision"]),
        f"F1: {metrics['f1']:.2%}",
        _ratio("Malicious BLOCK/REVIEW Coverage", sum(record["ground_truth"] == "malicious" and record["decision"] != "pass" for record in records), malicious_total, metrics["triage"]["malicious_containment_recall"]),
        _ratio("Benign PASS Rate", sum(record["ground_truth"] == "benign" and record["decision"] == "pass" for record in records), benign_total, metrics["triage"]["benign_pass_rate"]), "",
    ))
    (output / "metrics.md").write_text(human, encoding="utf-8")
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        metrics = merge_runs(args.inputs, args.output)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}")
        return 2
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

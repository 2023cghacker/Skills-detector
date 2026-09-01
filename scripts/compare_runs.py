"""Paired comparison of two labeled detector runs on their common samples."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

from src.metrics import binary_metrics, bootstrap_ci


def _load(path: Path) -> dict[str, dict]:
    return {
        row["sample_id"]: row
        for row in (json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    }


def _exact_mcnemar(left_only: int, right_only: int) -> float:
    discordant = left_only + right_only
    if discordant == 0:
        return 1.0
    tail = sum(math.comb(discordant, k) for k in range(min(left_only, right_only) + 1)) / (2 ** discordant)
    return min(1.0, 2 * tail)


def compare(left_path: Path, right_path: Path) -> dict:
    left, right = _load(left_path), _load(right_path)
    common = sorted(left.keys() & right.keys())
    if not common:
        raise ValueError("runs have no common successful samples")
    labels = []
    left_predictions = []
    right_predictions = []
    left_scores = []
    right_scores = []
    left_only = right_only = 0
    for sample_id in common:
        a, b = left[sample_id], right[sample_id]
        if a["ground_truth"] != b["ground_truth"]:
            raise ValueError(f"ground truth differs for {sample_id}")
        label = int(a["ground_truth"] == "malicious")
        pa, pb = int(a["verdict"] == "malicious"), int(b["verdict"] == "malicious")
        labels.append(label)
        left_predictions.append(pa)
        right_predictions.append(pb)
        left_scores.append(a["confidence"] * (1 if pa else -1))
        right_scores.append(b["confidence"] * (1 if pb else -1))
        left_correct, right_correct = pa == label, pb == label
        left_only += int(left_correct and not right_correct)
        right_only += int(right_correct and not left_correct)
    left_metrics = binary_metrics(labels, left_predictions, left_scores)
    right_metrics = binary_metrics(labels, right_predictions, right_scores)
    return {
        "common_samples": len(common),
        "left_total_successes": len(left),
        "right_total_successes": len(right),
        "left": left_metrics,
        "right": right_metrics,
        "delta_right_minus_left": {
            key: right_metrics[key] - left_metrics[key]
            for key in ("accuracy", "precision", "recall", "f1", "fpr", "balanced_accuracy", "mcc")
        },
        "paired_correctness": {
            "left_correct_right_wrong": left_only,
            "right_correct_left_wrong": right_only,
            "discordant": left_only + right_only,
            "exact_mcnemar_p": _exact_mcnemar(left_only, right_only),
        },
        "prediction_disagreements": sum(a != b for a, b in zip(left_predictions, right_predictions)),
        "bootstrap_95_ci": {
            "left": bootstrap_ci(labels, left_predictions, left_scores),
            "right": bootstrap_ci(labels, right_predictions, right_scores),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--left", type=Path, required=True)
    parser.add_argument("--right", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.left, args.right)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

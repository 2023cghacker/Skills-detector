"""Dependency-free binary classification metrics."""

from __future__ import annotations

import math
import random
from typing import Any


def _div(a: float, b: float) -> float:
    return a / b if b else 0.0


def _auc(labels: list[int], scores: list[float]) -> float:
    positives, negatives = sum(labels), len(labels) - sum(labels)
    if not positives or not negatives:
        return 0.0
    ordered = sorted(enumerate(scores), key=lambda pair: pair[1])
    rank_sum, i = 0.0, 0
    while i < len(ordered):
        j = i + 1
        while j < len(ordered) and ordered[j][1] == ordered[i][1]:
            j += 1
        rank_sum += ((i + 1 + j) / 2) * sum(labels[index] for index, _ in ordered[i:j])
        i = j
    return (rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def _average_precision(labels: list[int], scores: list[float]) -> float:
    positives = sum(labels)
    if not positives:
        return 0.0
    groups: dict[float, list[int]] = {}
    for score, label in zip(scores, labels):
        groups.setdefault(score, []).append(label)
    true_seen = false_seen = 0
    average_precision = 0.0
    for score in sorted(groups, reverse=True):
        group = groups[score]
        group_true = sum(group)
        true_seen += group_true
        false_seen += len(group) - group_true
        average_precision += (group_true / positives) * _div(true_seen, true_seen + false_seen)
    return average_precision


def binary_metrics(labels: list[int], predictions: list[int], scores: list[float]) -> dict[str, Any]:
    tp = sum(t == p == 1 for t, p in zip(labels, predictions))
    tn = sum(t == p == 0 for t, p in zip(labels, predictions))
    fp = sum(t == 0 and p == 1 for t, p in zip(labels, predictions))
    fn = sum(t == 1 and p == 0 for t, p in zip(labels, predictions))
    precision, recall = _div(tp, tp + fp), _div(tp, tp + fn)
    specificity = _div(tn, tn + fp)
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return {
        "n": len(labels), "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "accuracy": _div(tp + tn, len(labels)), "precision": precision, "recall": recall,
        "f1": _div(2 * precision * recall, precision + recall), "fpr": _div(fp, fp + tn),
        "fnr": _div(fn, fn + tp), "specificity": specificity,
        "balanced_accuracy": (recall + specificity) / 2,
        "mcc": _div(tp * tn - fp * fn, denominator),
        "roc_auc": _auc(labels, scores), "average_precision": _average_precision(labels, scores),
    }


def triage_metrics(labels: list[int], decisions: list[str]) -> dict[str, Any]:
    """Measure routing separately from the malicious binary hypothesis."""
    if len(labels) != len(decisions):
        raise ValueError("labels and decisions must have the same length")
    counts = {name: decisions.count(name) for name in ("pass", "review", "block")}
    malicious = sum(labels)
    benign = len(labels) - malicious
    malicious_blocked = sum(label == 1 and decision == "block" for label, decision in zip(labels, decisions))
    malicious_contained = sum(label == 1 and decision in {"block", "review"} for label, decision in zip(labels, decisions))
    benign_passed = sum(label == 0 and decision == "pass" for label, decision in zip(labels, decisions))
    return {
        "counts": counts,
        "block_rate": _div(counts["block"], len(labels)),
        "review_rate": _div(counts["review"], len(labels)),
        "pass_rate": _div(counts["pass"], len(labels)),
        "malicious_block_recall": _div(malicious_blocked, malicious),
        "malicious_containment_recall": _div(malicious_contained, malicious),
        "benign_pass_rate": _div(benign_passed, benign),
    }


def bootstrap_ci(labels: list[int], predictions: list[int], scores: list[float], rounds: int = 1000, seed: int = 1337) -> dict[str, list[float]]:
    rng = random.Random(seed)
    positive = [i for i, label in enumerate(labels) if label]
    negative = [i for i, label in enumerate(labels) if not label]
    keys = ("accuracy", "precision", "recall", "f1", "fpr")
    values = {key: [] for key in keys}
    for _ in range(rounds):
        indices = [rng.choice(positive) for _ in positive] + [rng.choice(negative) for _ in negative]
        result = binary_metrics([labels[i] for i in indices], [predictions[i] for i in indices], [scores[i] for i in indices])
        for key in keys:
            values[key].append(result[key])
    return {key: [sorted(group)[int(.025 * rounds)], sorted(group)[int(.975 * rounds) - 1]] for key, group in values.items()}

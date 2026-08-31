"""Prepare the frozen labeled benchmark sample or the current community sample."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.dataset_prep import (
    DEFAULT_COMMUNITY_CATEGORIES,
    download_registry_sample,
    fetch_registry_indexes,
    prepare_malicious_skill_bench_sample,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    benchmark = commands.add_parser("benchmark")
    benchmark.add_argument("--primary", type=Path, required=True)
    benchmark.add_argument("--split", type=Path, required=True)
    benchmark.add_argument("--output", type=Path, required=True)
    benchmark.add_argument("--per-class", type=int, default=500)
    benchmark.add_argument("--seed", type=int, default=1337)
    community = commands.add_parser("community")
    community.add_argument("--index-dir", type=Path, required=True)
    community.add_argument("--output", type=Path, required=True)
    community.add_argument("--per-category", type=int, default=100)
    community.add_argument("--per-repo-cap", type=int, default=5)
    community.add_argument("--candidate-overfetch", type=int, default=10)
    community.add_argument("--seed", type=int, default=1337)
    community.add_argument("--budget-mib", type=int, default=512)
    community.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    if args.command == "benchmark":
        summary = prepare_malicious_skill_bench_sample(
            args.primary, args.split, args.output, per_class=args.per_class, seed=args.seed
        )
    else:
        fetch_registry_indexes(args.index_dir, DEFAULT_COMMUNITY_CATEGORIES)
        summary = download_registry_sample(
            args.index_dir,
            args.output,
            categories=DEFAULT_COMMUNITY_CATEGORIES,
            target_per_category=args.per_category,
            per_repo_cap=args.per_repo_cap,
            candidate_overfetch=args.candidate_overfetch,
            seed=args.seed,
            total_budget_bytes=args.budget_mib * 1024 * 1024,
            workers=args.workers,
        )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

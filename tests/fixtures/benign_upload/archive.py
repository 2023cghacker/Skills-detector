"""Static test fixture. This file is read as data and is never imported."""

from pathlib import Path


def describe_archive(project_root: Path, selected: Path, endpoint: str) -> dict[str, str]:
    return {
        "project_root": str(project_root),
        "selected": str(selected),
        "endpoint": endpoint,
    }

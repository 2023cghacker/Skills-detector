"""Versioned review taxonomy shared by rules and model prompts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_TAXONOMY = Path(__file__).resolve().parents[2] / "data" / "library" / "risk_taxonomy.json"


def load_risk_taxonomy(path: Path = DEFAULT_TAXONOMY) -> dict[str, Any]:
    taxonomy = json.loads(path.read_text(encoding="utf-8"))
    domains = taxonomy.get("domains", [])
    if {domain.get("id") for domain in domains} != {"malicious_attack", "design_defect", "legal_risk"}:
        raise ValueError("risk taxonomy must define the three required domains")
    return taxonomy

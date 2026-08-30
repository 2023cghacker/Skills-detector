"""Deterministic Graphviz export for static behavior graphs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping


def _quote(value: object) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'


def write_behavior_graph_dot(scan: Mapping[str, Any], destination: Path) -> None:
    graph = scan.get("behavior_graph", {})
    lines = [
        "digraph behavior_graph {", "  rankdir=LR;", "  graph [bgcolor=white];",
        '  node [shape=box, style="rounded,filled", fillcolor="#EEF2FF", color="#334155", fontname="Arial"];',
        '  edge [color="#64748B", fontname="Arial", fontsize=9];',
    ]
    for node in graph.get("nodes", []):
        label = node["id"]
        if node.get("type") == "artifact":
            label = node.get("file", label)
        elif node.get("type") == "taint_path":
            label = f"taint path\\n{node.get('file', '')}:{node.get('line', '')}"
        color = {"artifact": "#FEF3C7", "function": "#E0E7FF", "taint_path": "#FEE2E2"}.get(node.get("type"), "#F8FAFC")
        lines.append(f"  {_quote(node['id'])} [label={_quote(label)}, fillcolor={_quote(color)}];")
    for edge in graph.get("edges", []):
        edge_type = edge["type"]
        color = "#DC2626" if edge_type.startswith("taint:") else "#64748B"
        penwidth = 2 if edge_type.startswith("taint:") else 1
        lines.append(
            f"  {_quote(edge['source'])} -> {_quote(edge['target'])} "
            f"[label={_quote(edge_type)}, color={_quote(color)}, penwidth={penwidth}];"
        )
    lines.append("}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")

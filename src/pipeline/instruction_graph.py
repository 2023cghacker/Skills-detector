"""Static behavior paths recovered from Markdown instructions and shell blocks."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping


MARKDOWN_SUFFIXES = {".md", ".markdown"}
SHELL_LANGS = {"bash", "sh", "zsh", "shell", "powershell", "ps1", "cmd", "bat"}
FENCE = re.compile(r"^\s*```\s*([A-Za-z0-9_+-]*)\s*$")
URL = re.compile(r"https?://[^\s)>'\"`]+", re.I)
DOWNLOAD_COMMAND = re.compile(r"\b(?:curl|wget|invoke-webrequest|iwr)\b", re.I)
PIPE_EXEC = re.compile(r"\|\s*(?:sh|bash|zsh|powershell|pwsh)\b", re.I)
FILE_EXEC = re.compile(r"(?:&&|;|\n)\s*(?:chmod\s+\+x\s+\S+\s*(?:&&|;|\n)\s*)?(?:\./\S+|(?:sh|bash|python(?:3)?|node|powershell|pwsh)\s+\S+)", re.I)
REQUIRED = re.compile(r"\b(?:must|required|require(?:s|d)?|prerequisite|before\s+(?:proceeding|use|setup)|will\s+not\s+(?:work|function)|ensure\b)", re.I)
RUN = re.compile(
    r"\b(?:run|launch|execute|open)\b.{0,80}"
    r"(?:(?:executable|binary|script|installer|file)\b|\.(?:exe|dmg|pkg|sh|ps1)\b)"
    r"|\bpaste\b.{0,80}\bterminal\b",
    re.I | re.S,
)
EXECUTION_INTENT = re.compile(
    r"\b(?:run|launch|execute|open)\b|\b(?:copy|paste)\b.{0,120}\b(?:terminal|powershell|shell)\b",
    re.I | re.S,
)
ARCHIVE_OR_SNIPPET = re.compile(
    r"(?:(?:password|pass(?:word)?(?:\s*[:=]|\s+[`'\"]?[A-Za-z0-9])).{0,60}(?:zip|archive|extract)|"
    r"(?:zip|archive|extract).{0,60}(?:password|pass(?:word)?(?:\s*[:=]|\s+[`'\"]?[A-Za-z0-9]))|"
    r"glot\.io/(?:snippets?|snip)/)",
    re.I | re.S,
)
VERIFY = re.compile(r"\b(?:sha(?:-?256|256sum)|checksum|signature|signed|gpg|cosign|verify\s+(?:the\s+)?hash)\b", re.I)
REVERSE_SHELL = re.compile(
    r"\bnc\b[^\n]{0,160}\s-(?:e|c)\s+['\"]?/bin/(?:ba)?sh\b"
    r"|\b(?:bash|sh)\s+-i\b[^\n]{0,200}(?:/dev/tcp/|\bnc\b)",
    re.I,
)
SYSTEM_WRITE = re.compile(
    r"(?:>>?|\btee(?:\s+-a)?)\s*"
    r"(?P<target>(?:/etc/hosts|/etc/(?:cron[^\s]*|sudoers)|[^\s]*(?:\.bashrc|\.profile|authorized_keys)))",
    re.I,
)
SYSTEM_DELETE = re.compile(
    r"(?:\brm\s+-[^\n]*f[^\n]*|:\s*>)\s*"
    r"(?P<target>(?:/root/|/var/log/|/etc/)[^\s;&|]*|[^\s;&|]*(?:audit|session)[^\s;&|]*\.log)",
    re.I,
)


def external_payload_chain(text: str) -> dict[str, Any] | None:
    """Recognize a required, unverified external executable acquisition."""
    for remote in URL.finditer(text):
        start = max(0, remote.start() - 500)
        end = min(len(text), remote.end() + 700)
        window = text[start:end]
        required = REQUIRED.search(window)
        run = EXECUTION_INTENT.search(window)
        campaign = ARCHIVE_OR_SNIPPET.search(window)
        if not (required and run and campaign) or VERIFY.search(window):
            continue
        matched = campaign.group(0).lower()
        return {
            "start": start + min(required.start(), remote.start() - start, run.start(), campaign.start()),
            "end": start + max(required.end(), remote.end() - start, run.end(), campaign.end()),
            "required_before_use": True, "remote_payload": True,
            "execution_requested": True,
            "password_archive": "glot.io/" not in matched,
            "snippet_host": "glot.io/" in matched,
            "integrity_verification": "absent",
        }
    return None


def fenced_blocks(text: str):
    lines = text.splitlines()
    active = False
    language = ""
    start = 0
    body: list[str] = []
    for number, line in enumerate(lines, 1):
        match = FENCE.match(line)
        if match:
            if not active:
                active = True
                language = match.group(1).lower()
                start = number + 1
                body = []
            else:
                yield language, start, "\n".join(body)
                active = False
                language = ""
                body = []
            continue
        if active:
            body.append(line)


def extract_instruction_paths(blobs: Mapping[str, bytes]) -> dict[str, Any]:
    paths: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    shell_blocks = 0
    prose_chains = 0
    for file in sorted(blobs):
        if Path(file).suffix.lower() not in MARKDOWN_SUFFIXES:
            continue
        text = blobs[file][:262_144].decode("utf-8", errors="replace").replace("\x00", "")
        for language, line, body in fenced_blocks(text):
            if language not in SHELL_LANGS:
                continue
            shell_blocks += 1
            url = URL.search(body)
            if url and DOWNLOAD_COMMAND.search(body) and (PIPE_EXEC.search(body) or FILE_EXEC.search(body)):
                evidence_id = f"IG{len(evidence) + 1}"
                source_id = f"instruction:{file}:{line}:remote"
                sink_id = f"instruction:{file}:{line}:execute"
                evidence.append({
                    "id": evidence_id, "kind": "instruction_command_path", "source_object": "external_payload",
                    "source_function": f"{file}:<instruction>", "sink_file": file, "sink_line": line,
                    "sink_callee": "shell_interpreter", "language": language,
                })
                nodes.extend([
                    {"id": source_id, "type": "untrusted_remote_content", "file": file, "line": line},
                    {"id": sink_id, "type": "process_execution", "file": file, "line": line},
                ])
                edges.append({"source": source_id, "target": sink_id, "type": "download_then_execute"})
                paths.append({
                    "operation": "download_execute", "object": "external_payload", "object_category": "untrusted_input",
                    "destination": "local_process", "source_file": file, "source_function": f"{file}:<instruction>",
                    "sink_file": file, "sink_line": line, "call_chain": [f"{file}:<instruction>"],
                    "evidence_ids": [evidence_id], "confidence": 0.98,
                    "relation_basis": "instruction_command_flow", "reachability": "explicitly_instructed",
                })

            for match, operation, node_type, edge_type, confidence in (
                (REVERSE_SHELL.search(body), "reverse_shell", "remote_shell", "opens_remote_shell", 0.99),
                (SYSTEM_WRITE.search(body), "change_security_setting", "system_configuration", "writes_system_configuration", 0.97),
                (SYSTEM_DELETE.search(body), "destroy", "system_or_audit_log", "destroys_system_resource", 0.97),
            ):
                if not match:
                    continue
                sink_line = line + body.count("\n", 0, match.start())
                evidence_id = f"IG{len(evidence) + 1}"
                source_id = f"instruction:{file}:{sink_line}:command"
                sink_id = f"instruction:{file}:{sink_line}:{operation}"
                target = match.groupdict().get("target") or "remote_interactive_shell"
                evidence.append({
                    "id": evidence_id, "kind": "instruction_command_path", "source_object": "instruction_command",
                    "source_function": f"{file}:<instruction>", "sink_file": file, "sink_line": sink_line,
                    "sink_callee": operation, "language": language,
                })
                nodes.extend([
                    {"id": source_id, "type": "instruction_command", "file": file, "line": sink_line},
                    {"id": sink_id, "type": node_type, "file": file, "line": sink_line},
                ])
                edges.append({"source": source_id, "target": sink_id, "type": edge_type})
                paths.append({
                    "operation": operation, "object": target, "object_category": "system_resource",
                    "destination": target, "source_file": file, "source_function": f"{file}:<instruction>",
                    "sink_file": file, "sink_line": sink_line, "call_chain": [f"{file}:<instruction>"],
                    "evidence_ids": [evidence_id], "confidence": confidence,
                    "relation_basis": "instruction_command_flow", "reachability": "explicitly_instructed",
                })

        chain = external_payload_chain(text)
        if chain:
            prose_chains += 1
            line = text.count("\n", 0, chain["start"]) + 1
            evidence_id = f"IG{len(evidence) + 1}"
            source_id = f"instruction:{file}:{line}:artifact"
            sink_id = f"instruction:{file}:{line}:required-execution"
            evidence.append({
                "id": evidence_id, "kind": "instruction_prose_path", "source_object": "external_payload",
                "source_function": f"{file}:<instruction>", "sink_file": file, "sink_line": line,
                "sink_callee": "required_external_program", "integrity_verification": "absent",
            })
            nodes.extend([
                {"id": source_id, "type": "untrusted_remote_content", "file": file, "line": line},
                {"id": sink_id, "type": "process_execution", "file": file, "line": line},
            ])
            edges.append({"source": source_id, "target": sink_id, "type": "required_unverified_execution"})
            paths.append({
                "operation": "download_execute", "object": "external_payload", "object_category": "untrusted_input",
                "destination": "local_process", "source_file": file, "source_function": f"{file}:<instruction>",
                "sink_file": file, "sink_line": line, "call_chain": [f"{file}:<instruction>"],
                "evidence_ids": [evidence_id], "confidence": 0.95,
                "relation_basis": "instruction_prose_chain", "reachability": "explicitly_required",
            })
    unique: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    for path in paths:
        key = (path["operation"], path["sink_file"], path["sink_line"], path["relation_basis"])
        unique[key] = path
    return {
        "paths": list(unique.values()), "evidence": evidence,
        "nodes": nodes, "edges": edges,
        "coverage": {"shell_blocks_parsed": shell_blocks, "prose_payload_chains": prose_chains},
    }

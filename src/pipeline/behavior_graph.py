"""Cross-file Python behavior graph and interprocedural taint summaries.

Target source is parsed as data with :mod:`ast`; it is never imported or
executed. Unsupported languages and unresolved calls remain explicit coverage
gaps instead of being interpreted as safe.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .sensitive_objects import SensitiveObjectLibrary


CODE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".sh", ".bash", ".zsh", ".ps1"}
TRANSMIT_CALLS = {"requests.post", "requests.put", "requests.patch", "httpx.post", "httpx.put", "httpx.patch"}
PROCESS_CALLS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "os.system"}
TRANSFORMS = {"b64encode", "b64decode", "encode", "decode", "dumps", "loads", "compress", "encrypt", "join", "format", "read", "read_text", "read_bytes"}


def _module_name(path: str) -> str:
    parts = list(PurePosixPath(path).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _attribute_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _attribute_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _literal(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float)):
        return str(node.value)
    if isinstance(node, ast.JoinedStr):
        return "".join(part.value for part in node.values if isinstance(part, ast.Constant) and isinstance(part.value, str))
    return ""


@dataclass
class FunctionInfo:
    function_id: str
    module: str
    file: str
    name: str
    line: int
    params: tuple[str, ...]
    body: list[ast.stmt]
    imports: dict[str, str]


@dataclass(frozen=True)
class SinkFact:
    operation: str
    file: str
    line: int
    callee: str
    destination: str
    taints: frozenset[str]
    call_chain: tuple[str, ...] = ()


@dataclass(frozen=True)
class Summary:
    returns: frozenset[str] = frozenset()
    sinks: tuple[SinkFact, ...] = ()
    calls: frozenset[str] = frozenset()
    unresolved_calls: frozenset[str] = frozenset()


@dataclass
class _State:
    env: dict[str, set[str]] = field(default_factory=dict)
    returns: set[str] = field(default_factory=set)
    sinks: list[SinkFact] = field(default_factory=list)
    calls: set[str] = field(default_factory=set)
    unresolved_calls: set[str] = field(default_factory=set)


class PythonBehaviorAnalyzer:
    def __init__(self, functions: Mapping[str, FunctionInfo], object_library: SensitiveObjectLibrary) -> None:
        self.functions = dict(functions)
        self.object_library = object_library
        self.summaries: dict[str, Summary] = {name: Summary() for name in functions}

    def run(self, max_rounds: int | None = None) -> tuple[dict[str, Summary], int, bool]:
        # A simple call chain has at most |F| functions.  One additional round
        # is sufficient to observe stability after facts traverse that chain.
        round_limit = max_rounds if max_rounds is not None else max(1, len(self.functions) + 1)
        rounds = 0
        converged = False
        for rounds in range(1, round_limit + 1):
            updated = {function_id: self._analyze(info) for function_id, info in sorted(self.functions.items())}
            changed = updated != self.summaries
            self.summaries = updated
            if not changed:
                converged = True
                break
        return self.summaries, rounds, converged

    def _analyze(self, info: FunctionInfo) -> Summary:
        state = _State(env={name: {f"param:{index}"} for index, name in enumerate(info.params)})
        self._statements(info, info.body, state)
        sinks = tuple(sorted(set(state.sinks), key=lambda item: (item.file, item.line, item.operation, item.call_chain)))
        return Summary(frozenset(state.returns), sinks, frozenset(state.calls), frozenset(state.unresolved_calls))

    def _statements(self, info: FunctionInfo, statements: list[ast.stmt], state: _State) -> None:
        for statement in statements:
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                value = getattr(statement, "value", None)
                taints = self._expr(info, value, state) if value is not None else set()
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    self._assign(target, taints, state)
            elif isinstance(statement, ast.Expr):
                self._expr(info, statement.value, state)
            elif isinstance(statement, ast.Return):
                state.returns.update(self._expr(info, statement.value, state))
            elif isinstance(statement, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try)):
                branches = [getattr(statement, attr, []) for attr in ("body", "orelse", "finalbody")]
                branches.extend(handler.body for handler in getattr(statement, "handlers", []))
                for branch in branches:
                    if not branch:
                        continue
                    branch_state = _State(
                        env={name: set(values) for name, values in state.env.items()},
                        returns=set(state.returns), sinks=list(state.sinks), calls=set(state.calls),
                        unresolved_calls=set(state.unresolved_calls),
                    )
                    self._statements(info, branch, branch_state)
                    for name, values in branch_state.env.items():
                        state.env.setdefault(name, set()).update(values)
                    state.returns.update(branch_state.returns)
                    state.sinks.extend(branch_state.sinks)
                    state.calls.update(branch_state.calls)
                    state.unresolved_calls.update(branch_state.unresolved_calls)

    def _assign(self, target: ast.AST, taints: set[str], state: _State) -> None:
        if isinstance(target, ast.Name):
            state.env[target.id] = set(taints)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                self._assign(child, taints, state)

    def _expr(self, info: FunctionInfo, node: ast.AST | None, state: _State) -> set[str]:
        if node is None:
            return set()
        if isinstance(node, ast.Name):
            return set(state.env.get(node.id, set()))
        if isinstance(node, ast.Constant):
            return self._literal_taints(str(node.value), info.file) if isinstance(node.value, str) else set()
        if isinstance(node, ast.Subscript):
            taints = self._expr(info, node.value, state) | self._expr(info, node.slice, state)
            if _attribute_name(node.value) in {"os.environ", "environ"} and _literal(node.slice):
                taints.update(self._literal_taints(_literal(node.slice), info.file))
            return taints
        if isinstance(node, ast.Attribute):
            return self._expr(info, node.value, state)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return set().union(*(self._expr(info, child, state) for child in node.elts), set())
        if isinstance(node, ast.Dict):
            return set().union(*(self._expr(info, child, state) for child in [*node.keys, *node.values] if child is not None), set())
        if isinstance(node, ast.Call):
            return self._call(info, node, state)
        return set().union(*(self._expr(info, child, state) for child in ast.iter_child_nodes(node)), set())

    def _call(self, info: FunctionInfo, node: ast.Call, state: _State) -> set[str]:
        raw_name = _attribute_name(node.func)
        positional = [self._expr(info, arg, state) for arg in node.args]
        keyword = [self._expr(info, item.value, state) for item in node.keywords]
        combined = set().union(*positional, *keyword, set())
        literal_args = [_literal(arg) for arg in node.args]
        if raw_name in {"os.getenv", "getenv", "os.environ.get", "open", "Path", "pathlib.Path"} and literal_args:
            combined.update(self._literal_taints(literal_args[0], info.file))

        operation = ""
        if raw_name in TRANSMIT_CALLS or any(raw_name.endswith(f".{name}") for name in ("post", "put", "patch", "send")):
            operation = "transmit"
        elif raw_name in PROCESS_CALLS:
            operation = "execute_process"
        if operation and combined:
            destination = literal_args[0][:160] if literal_args and literal_args[0] else "dynamic"
            state.sinks.append(SinkFact(operation, info.file, node.lineno, raw_name, destination, frozenset(combined)))

        resolved = self._resolve_call(info, raw_name)
        if resolved:
            state.calls.add(resolved)
            summary = self.summaries[resolved]
            mapped_returns = self._substitute(summary.returns, positional)
            for sink in summary.sinks:
                mapped = self._substitute(sink.taints, positional)
                if mapped:
                    # Keep a finite simple call chain.  Recursive cycles do not
                    # create an unbounded sequence of otherwise identical facts.
                    call_chain = sink.call_chain if resolved in sink.call_chain else (resolved, *sink.call_chain)
                    state.sinks.append(SinkFact(sink.operation, sink.file, sink.line, sink.callee, sink.destination, frozenset(mapped), call_chain))
            return mapped_returns | combined if raw_name.rsplit(".", 1)[-1] in TRANSFORMS else mapped_returns

        if raw_name and not self._known_external(raw_name):
            state.unresolved_calls.add(raw_name)
        return combined if raw_name.rsplit(".", 1)[-1] in TRANSFORMS or isinstance(node.func, ast.Attribute) else set()

    def _resolve_call(self, info: FunctionInfo, raw_name: str) -> str:
        if not raw_name:
            return ""
        head, _, tail = raw_name.partition(".")
        qualified = f"{info.imports[head]}.{tail}" if head in info.imports and tail else info.imports.get(head, f"{info.module}.{raw_name}")
        module, _, function = qualified.rpartition(".")
        candidate = f"{module}:{function}"
        return candidate if candidate in self.functions else ""

    @staticmethod
    def _substitute(tokens: frozenset[str], positional: list[set[str]]) -> set[str]:
        output: set[str] = set()
        for token in tokens:
            if token.startswith("param:"):
                index = int(token.split(":", 1)[1])
                if index < len(positional):
                    output.update(positional[index])
            else:
                output.add(token)
        return output

    def _literal_taints(self, value: str, file: str) -> set[str]:
        return {f"source:{item['object']}" for item in self.object_library.extract(value, file)}

    @staticmethod
    def _known_external(name: str) -> bool:
        return name.split(".", 1)[0] in {"os", "sys", "json", "base64", "pathlib", "requests", "httpx", "urllib", "subprocess", "logging", "print", "open", "len", "str", "bytes"}


def _parse_functions(blobs: Mapping[str, bytes]) -> tuple[dict[str, FunctionInfo], list[dict[str, Any]], list[str]]:
    functions: dict[str, FunctionInfo] = {}
    parse_errors: list[dict[str, Any]] = []
    parsed_files: list[str] = []
    for file in sorted(blobs):
        if Path(file).suffix.lower() != ".py":
            continue
        try:
            tree = ast.parse(blobs[file].decode("utf-8", errors="replace").replace("\x00", ""), filename=file)
        except (SyntaxError, ValueError) as exc:
            parse_errors.append({"file": file, "reason": type(exc).__name__, "line": getattr(exc, "lineno", None)})
            continue
        parsed_files.append(file)
        module = _module_name(file)
        imports: dict[str, str] = {}
        module_body: list[ast.stmt] = []
        for statement in tree.body:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    imports[alias.asname or alias.name.split(".", 1)[0]] = alias.name
            elif isinstance(statement, ast.ImportFrom) and statement.module:
                for alias in statement.names:
                    imports[alias.asname or alias.name] = f"{statement.module}.{alias.name}"
            elif not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                module_body.append(statement)
        module_id = f"{module}:<module>"
        functions[module_id] = FunctionInfo(module_id, module, file, "<module>", 1, (), module_body, imports)
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params = tuple(arg.arg for arg in [*statement.args.posonlyargs, *statement.args.args, *statement.args.kwonlyargs])
                function_id = f"{module}:{statement.name}"
                functions[function_id] = FunctionInfo(function_id, module, file, statement.name, statement.lineno, params, statement.body, imports)
    return functions, parse_errors, parsed_files


def build_behavior_graph(blobs: Mapping[str, bytes], object_findings: list[dict[str, Any]], object_library: SensitiveObjectLibrary) -> dict[str, Any]:
    """Return a typed graph, coverage record, and concrete source-to-sink paths."""
    functions, parse_errors, parsed_files = _parse_functions(blobs)
    summaries, rounds, converged = PythonBehaviorAnalyzer(functions, object_library).run()
    paths: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for function_id, summary in summaries.items():
        info = functions[function_id]
        for sink in summary.sinks:
            for source in sorted(token.split(":", 1)[1] for token in sink.taints if token.startswith("source:")):
                key = (function_id, source, sink.file, sink.line, sink.operation, sink.call_chain)
                if key in seen:
                    continue
                seen.add(key)
                evidence_id = f"G{len(evidence) + 1}"
                evidence.append({"id": evidence_id, "kind": "taint_path", "source_object": source, "source_function": function_id, "sink_file": sink.file, "sink_line": sink.line, "sink_callee": sink.callee})
                object_ids = [item["id"] for item in object_findings if item["object"] == source and item["file"] == info.file][:1]
                paths.append({
                    "operation": sink.operation, "object": source,
                    "object_category": next((item["category"] for item in object_findings if item["object"] == source), "unknown"),
                    "destination": sink.destination, "source_file": info.file, "source_function": function_id,
                    "sink_file": sink.file, "sink_line": sink.line, "call_chain": [function_id, *sink.call_chain],
                    "evidence_ids": [evidence_id, *object_ids], "confidence": 0.95,
                    "relation_basis": "interprocedural_taint", "reachability": "statically_possible",
                })
    call_edges = sorted({(caller, callee) for caller, summary in summaries.items() for callee in summary.calls})
    unsupported_files = sorted(file for file in blobs if Path(file).suffix.lower() in CODE_SUFFIXES and Path(file).suffix.lower() != ".py")
    unresolved_calls = sorted({call for summary in summaries.values() for call in summary.unresolved_calls})
    nodes = ([{"id": f"file:{file}", "type": "artifact", "file": file} for file in parsed_files]
             + [{"id": function_id, "type": "function", "file": info.file, "line": info.line} for function_id, info in sorted(functions.items())]
             + [{"id": item["id"], "type": "taint_path", "file": item["sink_file"], "line": item["sink_line"]} for item in evidence])
    path_edges = [
        {
            "source": path["source_function"],
            "target": path["evidence_ids"][0],
            "type": f"taint:{path['object']}->{path['operation']}",
        }
        for path in paths
    ]
    edges = ([{"source": f"file:{info.file}", "target": function_id, "type": "contains"} for function_id, info in sorted(functions.items())]
             + [{"source": caller, "target": callee, "type": "calls"} for caller, callee in call_edges]
             + path_edges)
    return {
        "engine": "python_ast_interprocedural_v1", "fixed_point_rounds": rounds,
        "fixed_point_converged": converged,
        "nodes": nodes[:500], "edges": edges[:1000], "graph_evidence": evidence[:100], "behavior_paths": paths[:100],
        "coverage": {"python_files_seen": sum(Path(file).suffix.lower() == ".py" for file in blobs), "python_files_parsed": len(parsed_files), "functions": len(functions), "call_edges": len(call_edges), "taint_paths": len(paths), "parse_errors": parse_errors, "unsupported_code_files": unsupported_files, "unresolved_calls": unresolved_calls[:100]},
    }

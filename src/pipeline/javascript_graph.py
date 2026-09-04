"""Syntax-aware JavaScript behavior summaries using Tree-sitter.

The analyzer is intentionally bounded.  It parses source bytes, computes
monotone may-taint summaries for top-level functions, and never imports or
executes target code.  Unsupported constructs are retained as unresolved
coverage rather than interpreted as benign.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Mapping

from tree_sitter import Language, Node, Parser
import tree_sitter_javascript

from .sensitive_objects import SensitiveObjectLibrary


JS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs"}
TRANSMIT_NAMES = {"post", "put", "patch", "send"}
PROCESS_NAMES = {"exec", "execsync", "spawn", "spawnsync", "execfile"}
READ_NAMES = {"readfile", "readfilesync"}
TRANSFORM_NAMES = {"stringify", "parse", "tostring", "slice", "join", "concat", "trim"}


def _module_name(path: str) -> str:
    return ".".join(PurePosixPath(path).with_suffix("").parts)


def _text(node: Node | None, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace") if node is not None else ""


def _line(node: Node) -> int:
    return node.start_point.row + 1


def _descendants(node: Node):
    yield node
    for child in node.named_children:
        yield from _descendants(child)


@dataclass
class JSFunction:
    function_id: str
    module: str
    file: str
    name: str
    line: int
    params: tuple[str, ...]
    body: tuple[Node, ...]
    source: bytes
    globals: dict[str, set[str]]


@dataclass(frozen=True)
class JSSink:
    operation: str
    file: str
    line: int
    callee: str
    destination: str
    taints: frozenset[str]
    call_chain: tuple[str, ...] = ()


@dataclass(frozen=True)
class JSSummary:
    returns: frozenset[str] = frozenset()
    sinks: tuple[JSSink, ...] = ()
    calls: frozenset[str] = frozenset()
    unresolved_calls: frozenset[str] = frozenset()


@dataclass
class _State:
    env: dict[str, set[str]] = field(default_factory=dict)
    returns: set[str] = field(default_factory=set)
    sinks: list[JSSink] = field(default_factory=list)
    calls: set[str] = field(default_factory=set)
    unresolved_calls: set[str] = field(default_factory=set)


class JavaScriptAnalyzer:
    def __init__(self, functions: Mapping[str, JSFunction], object_library: SensitiveObjectLibrary) -> None:
        self.functions = dict(functions)
        self.object_library = object_library
        self.summaries = {name: JSSummary() for name in functions}

    def run(self, max_rounds: int | None = None) -> tuple[dict[str, JSSummary], int, bool]:
        # Bound propagation depth: real Skill call chains are shallow, while a
        # conservative graph with callbacks can otherwise generate many path
        # permutations that carry the same source--sink fact.
        limit = max_rounds if max_rounds is not None else min(3, max(1, len(self.functions) + 1))
        converged = False
        rounds = 0
        for rounds in range(1, limit + 1):
            updated = {name: self._analyze(info) for name, info in sorted(self.functions.items())}
            changed = updated != self.summaries
            self.summaries = updated
            if not changed:
                converged = True
                break
        return self.summaries, rounds, converged

    def _analyze(self, info: JSFunction) -> JSSummary:
        env = {name: set(values) for name, values in info.globals.items()}
        env.update({name: {f"param:{index}"} for index, name in enumerate(info.params)})
        state = _State(env=env)
        for node in info.body:
            self._statement(info, node, state)
        # Call-chain variants are provenance hints, not distinct data-flow
        # facts.  Keep the shortest witness per semantic sink key.
        unique: dict[tuple[Any, ...], JSSink] = {}
        for sink in state.sinks:
            key = (sink.operation, sink.file, sink.line, sink.callee, sink.destination, sink.taints)
            prior = unique.get(key)
            if prior is None or len(sink.call_chain) < len(prior.call_chain):
                unique[key] = sink
        sinks = tuple(sorted(unique.values(), key=lambda item: (item.file, item.line, item.operation, item.call_chain)))[:64]
        return JSSummary(
            frozenset(sorted(state.returns)[:128]), sinks,
            frozenset(sorted(state.calls)[:128]), frozenset(sorted(state.unresolved_calls)[:128]),
        )

    def _statement(self, info: JSFunction, node: Node, state: _State) -> None:
        kind = node.type
        if kind in {"lexical_declaration", "variable_declaration"}:
            for child in node.named_children:
                if child.type != "variable_declarator":
                    continue
                name = _text(child.child_by_field_name("name"), info.source)
                value = child.child_by_field_name("value")
                if name and value is not None and value.type not in {"arrow_function", "function_expression"}:
                    state.env[name] = self._expr(info, value, state)
            return
        if kind == "expression_statement" and node.named_children:
            self._expr(info, node.named_children[0], state)
            return
        if kind == "return_statement":
            if node.named_children:
                state.returns.update(self._expr(info, node.named_children[0], state))
            return
        if kind in {"if_statement", "for_statement", "for_in_statement", "while_statement", "try_statement", "switch_statement"}:
            for child in node.named_children:
                if child.type in {"statement_block", "else_clause", "catch_clause", "finally_clause", "switch_body"}:
                    branch = _State(
                        env={name: set(values) for name, values in state.env.items()},
                    )
                    for statement in child.named_children:
                        self._statement(info, statement, branch)
                    for name, values in branch.env.items():
                        state.env.setdefault(name, set()).update(values)
                    state.returns.update(branch.returns)
                    state.sinks.extend(branch.sinks)
                    state.calls.update(branch.calls)
                    state.unresolved_calls.update(branch.unresolved_calls)
            return
        if kind == "statement_block":
            for child in node.named_children:
                self._statement(info, child, state)
            return
        # Conservative fallback visits expressions but does not infer control flow.
        for child in node.named_children:
            if child.type.endswith("statement") or child.type in {"lexical_declaration", "variable_declaration"}:
                self._statement(info, child, state)
            else:
                self._expr(info, child, state)

    def _expr(self, info: JSFunction, node: Node | None, state: _State) -> set[str]:
        if node is None:
            return set()
        kind = node.type
        raw = _text(node, info.source)
        if kind in {"identifier", "shorthand_property_identifier", "property_identifier"}:
            return set(state.env.get(raw, set()))
        if kind in {"string", "template_string"}:
            return self._literal_sources(raw.strip("'\"`"), info.file)
        if kind == "member_expression":
            values = set().union(*(self._expr(info, child, state) for child in node.named_children), set())
            if "process.env" in raw:
                values.update(self._literal_sources(raw, info.file))
                if not any(token.startswith("source:") for token in values):
                    values.add("source:api_token")
            return values
        if kind in {"await_expression", "parenthesized_expression", "optional_chain", "unary_expression"}:
            return set().union(*(self._expr(info, child, state) for child in node.named_children), set())
        if kind in {"object", "array", "pair", "template_substitution", "binary_expression", "ternary_expression"}:
            return set().union(*(self._expr(info, child, state) for child in node.named_children), set())
        if kind == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            values = self._expr(info, right, state)
            name = _text(left, info.source)
            if left is not None and left.type == "identifier" and name:
                state.env[name] = set(values)
            return values
        if kind == "call_expression":
            return self._call(info, node, state)
        return set().union(*(self._expr(info, child, state) for child in node.named_children), set())

    def _call(self, info: JSFunction, node: Node, state: _State) -> set[str]:
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        raw_name = _text(function, info.source)
        argument_nodes = tuple(arguments.named_children) if arguments is not None else ()
        positional = [self._expr(info, item, state) for item in argument_nodes]
        receiver = self._expr(info, function.child_by_field_name("object"), state) if function is not None and function.type == "member_expression" else set()
        combined = set().union(receiver, *positional, set())
        lower = raw_name.lower()
        tail = lower.rsplit(".", 1)[-1]
        literal_args = [_text(item, info.source).strip("'\"`") for item in argument_nodes]

        if tail in READ_NAMES and literal_args:
            combined.update(self._literal_sources(literal_args[0], info.file))

        transmit = tail in TRANSMIT_NAMES or self._fetch_writes(node, info.source)
        execute = tail in PROCESS_NAMES
        if transmit and combined:
            destination = literal_args[0][:160] if literal_args else "dynamic"
            if len(state.sinks) < 256:
                state.sinks.append(JSSink("transmit", info.file, _line(node), raw_name, destination, frozenset(combined)))
        if execute and combined:
            destination = literal_args[0][:160] if literal_args else "dynamic"
            if len(state.sinks) < 256:
                state.sinks.append(JSSink("execute_process", info.file, _line(node), raw_name, destination, frozenset(combined)))

        resolved = self._resolve(info, raw_name)
        if resolved:
            state.calls.add(resolved)
            summary = self.summaries[resolved]
            returned = self._substitute(summary.returns, positional)
            for sink in summary.sinks:
                if len(state.sinks) >= 256:
                    break
                mapped = self._substitute(sink.taints, positional)
                if mapped:
                    chain = sink.call_chain if resolved in sink.call_chain else (resolved, *sink.call_chain[:7])
                    state.sinks.append(JSSink(sink.operation, sink.file, sink.line, sink.callee, sink.destination, frozenset(mapped), chain))
            return returned

        if lower == "fetch" or lower.endswith(".get"):
            return combined | {"source:external_response"}
        if tail in TRANSFORM_NAMES or function is not None and function.type == "member_expression":
            return combined
        if raw_name and raw_name[0].islower() and tail not in {"settimeout", "cleartimeout", "number", "string", "parseint"}:
            state.unresolved_calls.add(raw_name[:120])
        return set()

    def _resolve(self, info: JSFunction, raw_name: str) -> str:
        name = raw_name.rsplit(".", 1)[-1]
        candidate = f"{info.module}:{name}"
        return candidate if candidate in self.functions else ""

    @staticmethod
    def _substitute(tokens: frozenset[str], positional: list[set[str]]) -> set[str]:
        result: set[str] = set()
        for token in tokens:
            if token.startswith("param:"):
                index = int(token.split(":", 1)[1])
                if index < len(positional):
                    result.update(positional[index])
                else:
                    result.add(token)
            else:
                result.add(token)
        return result

    def _literal_sources(self, value: str, file: str) -> set[str]:
        result = {f"source:{item['object']}" for item in self.object_library.extract(value, file)}
        if "http://" in value.lower() or "https://" in value.lower():
            result.add("source:external_payload")
        return result

    @staticmethod
    def _fetch_writes(node: Node, source: bytes) -> bool:
        raw = _text(node, source).lower()
        if not raw.lstrip().startswith("fetch"):
            return False
        return bool("body:" in raw or any(f"method:{quote}{verb}" in raw.replace(" ", "") for quote in ("'", '"', "`") for verb in ("post", "put", "patch")))


def _params(node: Node | None, source: bytes) -> tuple[str, ...]:
    if node is None:
        return ()
    return tuple(_text(child, source) for child in node.named_children if child.type in {"identifier", "required_parameter"})


def _literal_globals(root: Node, source: bytes, file: str, object_library: SensitiveObjectLibrary) -> dict[str, set[str]]:
    globals_: dict[str, set[str]] = {}
    for node in root.named_children:
        if node.type not in {"lexical_declaration", "variable_declaration"}:
            continue
        for child in node.named_children:
            if child.type != "variable_declarator":
                continue
            name_node = child.child_by_field_name("name")
            value = child.child_by_field_name("value")
            if name_node is None or value is None or value.type in {"arrow_function", "function_expression"}:
                continue
            value_text = _text(value, source)
            tokens = {f"source:{item['object']}" for item in object_library.extract(value_text, file)}
            if "http://" in value_text.lower() or "https://" in value_text.lower():
                tokens.add("source:external_payload")
            if tokens:
                globals_[_text(name_node, source)] = tokens
    return globals_


def parse_javascript_functions(blobs: Mapping[str, bytes], object_library: SensitiveObjectLibrary) -> tuple[dict[str, JSFunction], list[dict[str, Any]], list[str], list[str]]:
    parser = Parser(Language(tree_sitter_javascript.language()))
    functions: dict[str, JSFunction] = {}
    errors: list[dict[str, Any]] = []
    parsed: list[str] = []
    candidates = [file for file in blobs if PurePosixPath(file).suffix.lower() in JS_SUFFIXES]
    candidates.sort(key=lambda file: (
        any(part.lower() in {"test", "tests", "fixtures", "examples"} for part in PurePosixPath(file).parts),
        PurePosixPath(file).name.lower() not in {"index.js", "main.js"},
        file.lower(),
    ))
    selected = candidates[:8]
    skipped = candidates[8:]
    for file in selected:
        source = blobs[file][:262_144].replace(b"\x00", b"")
        tree = parser.parse(source)
        root = tree.root_node
        if root.has_error:
            errors.append({"file": file, "reason": "tree_sitter_error", "line": 1})
        parsed.append(file)
        module = _module_name(file)
        globals_ = _literal_globals(root, source, file, object_library)
        module_body: list[Node] = []
        for node in root.named_children:
            if len(functions) >= 128:
                errors.append({"file": file, "reason": "package_function_limit", "line": _line(node)})
                break
            if node.type == "function_declaration":
                name = _text(node.child_by_field_name("name"), source)
                body = node.child_by_field_name("body")
                function_id = f"{module}:{name}"
                functions[function_id] = JSFunction(
                    function_id, module, file, name, _line(node),
                    _params(node.child_by_field_name("parameters"), source),
                    tuple(body.named_children) if body is not None else (), source, globals_,
                )
                continue
            found_function = False
            if node.type in {"lexical_declaration", "variable_declaration"}:
                for child in node.named_children:
                    if child.type != "variable_declarator":
                        continue
                    value = child.child_by_field_name("value")
                    if value is None or value.type not in {"arrow_function", "function_expression"}:
                        continue
                    name = _text(child.child_by_field_name("name"), source)
                    body = value.child_by_field_name("body")
                    function_id = f"{module}:{name}"
                    functions[function_id] = JSFunction(
                        function_id, module, file, name, _line(child),
                        _params(value.child_by_field_name("parameters"), source),
                        tuple(body.named_children) if body is not None and body.type == "statement_block" else ((body,) if body is not None else ()),
                        source, globals_,
                    )
                    found_function = True
            if not found_function:
                module_body.append(node)
        module_id = f"{module}:<module>"
        functions[module_id] = JSFunction(module_id, module, file, "<module>", 1, (), tuple(module_body), source, globals_)
    return functions, errors, parsed, skipped

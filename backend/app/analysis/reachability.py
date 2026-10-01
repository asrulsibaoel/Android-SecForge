"""Static dataflow & reachability engine.

Builds a conservative code graph from JADX-decompiled Java plus the existing
native/JNI models, then answers reachability queries (entry point -> sink,
source -> sink, entry -> JNI -> native sink) with an evidence chain and an
explicit confidence. Nothing is asserted that cannot be shown: unresolved
dispatch is left out or marked LOW, and a source and a sink merely coexisting in
the app never counts as a connection.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field

from app.analysis.signatures import (
    JAVA_SINK_SIGNATURES,
    NATIVE_SINK_SYMBOLS,
    SOURCE_SIGNATURES,
)

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
_CONF_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}

DEFAULT_MAX_DEPTH = 50

# Node types
N_COMPONENT = "COMPONENT"
N_JAVA_METHOD = "JAVA_METHOD"
N_NATIVE_LIB = "NATIVE_LIBRARY"
N_NATIVE_FUNC = "NATIVE_FUNCTION"
N_JNI = "JNI_BINDING"
N_SINK = "SECURITY_SINK"
N_SOURCE = "SOURCE"
N_ENTRY = "ENTRY_POINT"
N_FRAMEWORK = "ANDROID_FRAMEWORK"
N_BOUNDARY = "SECURITY_BOUNDARY"

# Edge types
E_DECLARES = "DECLARES"
E_CALLS = "CALLS"
E_INVOKES = "INVOKES"
E_LOADS = "LOADS_LIBRARY"
E_BINDS = "BINDS_TO"
E_DEPENDS = "DEPENDS_ON"
E_FLOWS = "FLOWS_TO"
E_ACQUIRES = "ACQUIRES"
# Android semantic edge types (added by the semantics pass).
E_FRAMEWORK_DISPATCH = "FRAMEWORK_DISPATCH"
E_IPC_CALL = "IPC_CALL"
E_INTENT_FLOW = "INTENT_FLOW"
E_SECURITY_BOUNDARY = "SECURITY_BOUNDARY"
E_DEEP_LINK = "DEEP_LINK"
E_WEBVIEW_BRIDGE = "WEBVIEW_BRIDGE"
E_REFLECTION_TARGET = "REFLECTION_TARGET"
E_DYNAMIC_LOAD = "DYNAMIC_LOAD"


# ---------------------------------------------------------------------------
# Java parsing (conservative, regex + brace matching)
# ---------------------------------------------------------------------------

_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
_CLASS_DECL = re.compile(r"\b(?:class|interface|enum)\s+([A-Za-z_]\w*)")
_METHOD_DECL = re.compile(
    r"(?P<mods>(?:public|private|protected|static|final|synchronized|native|abstract|default|\s)*)"
    r"[\w.$<>\[\]]+\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{)]*)\)\s*(?:throws [\w.,\s]+)?\{"
)
_LOCAL_DECL_RE = re.compile(r"\b([A-Z][\w.$]*)\s+([A-Za-z_]\w*)\s*=")
_CTOR_RE = re.compile(r"\bnew\s+([A-Z][\w.$]*)\s*\(")
_STATIC_CALL_RE = re.compile(r"\b([A-Z][\w.$]*)\.([A-Za-z_]\w*)\s*\(")
_RECEIVER_CALL_RE = re.compile(r"\b([a-z_]\w*)\.([A-Za-z_]\w*)\s*\(")
_BARE_CALL_RE = re.compile(r"(?<![\w.])([a-z_]\w*)\s*\(")
_CONTROL = {"if", "for", "while", "switch", "catch", "return", "new", "synchronized", "super", "this"}


@dataclass
class MethodInfo:
    fqcn: str
    class_simple: str
    name: str
    params: str
    is_native: bool
    start_line: int
    body: str
    file: str

    @property
    def key(self) -> str:
        return f"{self.fqcn}#{self.name}"


def _mask(text: str) -> str:
    """Blank out string/char literals and comments, preserving length and lines."""
    out = []
    i = 0
    n = len(text)
    state = None  # None | 'line' | 'block' | 'str' | 'char'
    while i < n:
        c = text[i]
        two = text[i : i + 2]
        if state is None:
            if two == "//":
                state = "line"; out.append("  "); i += 2; continue
            if two == "/*":
                state = "block"; out.append("  "); i += 2; continue
            if c == '"':
                state = "str"; out.append('"'); i += 1; continue
            if c == "'":
                state = "char"; out.append("'"); i += 1; continue
            out.append(c); i += 1; continue
        if state == "line":
            if c == "\n":
                state = None; out.append("\n")
            else:
                out.append(" ")
            i += 1; continue
        if state == "block":
            if two == "*/":
                state = None; out.append("  "); i += 2; continue
            out.append("\n" if c == "\n" else " "); i += 1; continue
        if state == "str":
            if c == "\\":
                out.append("  "); i += 2; continue
            if c == '"':
                state = None; out.append('"'); i += 1; continue
            out.append(" "); i += 1; continue
        if state == "char":
            if c == "\\":
                out.append("  "); i += 2; continue
            if c == "'":
                state = None; out.append("'"); i += 1; continue
            out.append(" "); i += 1; continue
    return "".join(out)


def _match_brace(masked: str, open_pos: int) -> int:
    depth = 0
    for i in range(open_pos, len(masked)):
        if masked[i] == "{":
            depth += 1
        elif masked[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(masked) - 1


def parse_java(path: str, text: str) -> list[MethodInfo]:
    masked = _mask(text)
    package_match = _PACKAGE_RE.search(masked)
    package = package_match.group(1) if package_match else None

    # Class spans (simple; nested classes get chained simple names).
    classes: list[tuple[str, int, int]] = []  # (simple_name, start, end)
    for match in _CLASS_DECL.finditer(masked):
        brace = masked.find("{", match.end())
        if brace == -1:
            continue
        end = _match_brace(masked, brace)
        classes.append((match.group(1), match.start(), end))
    classes.sort(key=lambda item: item[1])

    def fqcn_for(pos: int) -> str:
        enclosing = [name for name, start, end in classes if start <= pos <= end]
        simple = ".".join(enclosing) if enclosing else "UnknownClass"
        return f"{package}.{simple}" if package else simple

    def class_simple_for(pos: int) -> str:
        enclosing = [(name, start) for name, start, end in classes if start <= pos <= end]
        if not enclosing:
            return "UnknownClass"
        return max(enclosing, key=lambda item: item[1])[0]

    methods: list[MethodInfo] = []
    line_starts = _line_index(text)
    for match in _METHOD_DECL.finditer(masked):
        name = match.group("name")
        if name in _CONTROL:
            continue
        brace = match.end() - 1
        end = _match_brace(masked, brace)
        body = text[brace + 1 : end]
        is_native = "native" in (match.group("mods") or "")
        methods.append(
            MethodInfo(
                fqcn=fqcn_for(match.start()),
                class_simple=class_simple_for(match.start()),
                name=name,
                params=match.group("params").strip(),
                is_native=is_native,
                start_line=_line_of(line_starts, match.start()),
                body="" if is_native else body,
                file=path,
            )
        )
    # Native methods have no body ('{' would not match); detect declarations too.
    for lineno, line in enumerate(text.splitlines(), 1):
        masked_line = _mask(line)
        m = re.search(r"\bnative\b[\w<>\[\].,\s]+?\b([A-Za-z_]\w*)\s*\([^;{)]*\)\s*;", masked_line)
        if m:
            pos = text.find(line)
            methods.append(
                MethodInfo(
                    fqcn=fqcn_for(pos if pos >= 0 else 0),
                    class_simple=class_simple_for(pos if pos >= 0 else 0),
                    name=m.group(1),
                    params="",
                    is_native=True,
                    start_line=lineno,
                    body="",
                    file=path,
                )
            )
    return methods


def _line_index(text: str) -> list[int]:
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _line_of(line_starts: list[int], pos: int) -> int:
    lo, hi = 0, len(line_starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_starts[mid] <= pos:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


# ---------------------------------------------------------------------------
# Graph model
# ---------------------------------------------------------------------------


@dataclass
class Node:
    key: str
    node_type: str
    label: str
    class_name: str | None = None
    method_name: str | None = None
    source_file: str | None = None
    line: int | None = None
    confidence: str = MEDIUM
    extra: dict = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    edge_type: str
    evidence: str
    line: int | None = None
    confidence: str = MEDIUM


@dataclass
class PathResult:
    nodes: list[Node]
    edges: list[Edge]
    status: str
    confidence: str


@dataclass
class CodeGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    adjacency: dict[str, list[Edge]] = field(default_factory=dict)
    sources: list[dict] = field(default_factory=list)
    sinks: list[dict] = field(default_factory=list)
    entry_points: list[dict] = field(default_factory=list)
    # Parsed Java reused by the Android semantics pass (avoids re-parsing).
    methods: list = field(default_factory=list)
    by_simple: dict = field(default_factory=dict)
    class_names: set = field(default_factory=set)
    # Android semantic outputs (populated by app.analysis.semantics).
    android_entry_points: list[dict] = field(default_factory=list)
    intents: list[dict] = field(default_factory=list)
    deep_links: list[dict] = field(default_factory=list)
    ipc_transactions: list[dict] = field(default_factory=list)
    security_boundaries: list[dict] = field(default_factory=list)
    semantic_edges: list[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> None:
        self.nodes.setdefault(node.key, node)

    def add_edge(self, edge: Edge) -> None:
        if edge.src not in self.nodes or edge.dst not in self.nodes:
            return
        self.edges.append(edge)
        self.adjacency.setdefault(edge.src, []).append(edge)


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

_ENTRY_METHODS = {
    "activity": {"onCreate", "onNewIntent", "onStart", "onResume"},
    "activity-alias": {"onCreate", "onNewIntent"},
    "service": {"onCreate", "onStartCommand", "onBind", "onHandleIntent"},
    "receiver": {"onReceive"},
    "provider": {"onCreate", "query", "insert", "update", "delete", "call"},
}


def build_code_graph(sources, native_results, jni_bindings, components) -> CodeGraph:
    """Assemble the code graph from decompiled Java + native/JNI facts."""
    graph = CodeGraph()
    methods = [m for path, text in sources for m in parse_java(path, text)]

    index_by_key: dict[str, MethodInfo] = {}
    by_simple: dict[tuple[str, str], list[MethodInfo]] = {}
    class_names: set[str] = set()
    for method in methods:
        index_by_key.setdefault(method.key, method)
        by_simple.setdefault((method.class_simple, method.name), []).append(method)
        class_names.add(method.class_simple)
    graph.methods = methods
    graph.by_simple = by_simple
    graph.class_names = class_names

    for method in methods:
        graph.add_node(
            Node(
                key=method.key,
                node_type=N_JAVA_METHOD,
                label=f"{method.class_simple}.{method.name}",
                class_name=method.fqcn,
                method_name=method.name,
                source_file=method.file,
                line=method.start_line,
                extra={"is_native": method.is_native},
            )
        )

    _detect_sources_sinks(graph, methods)
    _build_call_edges(graph, methods, index_by_key, by_simple, class_names)
    _build_native(graph, native_results, jni_bindings, index_by_key, by_simple)
    _build_entry_points(graph, components, methods)
    return graph


def _detect_sources_sinks(graph: CodeGraph, methods: list[MethodInfo]) -> None:
    for method in methods:
        if not method.body:
            continue
        masked = _mask(method.body)
        base_line = method.start_line
        # Sources
        for sig in SOURCE_SIGNATURES:
            for m in sig.regex().finditer(masked):
                line = base_line + masked[: m.start()].count("\n")
                key = f"src:{method.key}:{sig.id}:{line}"
                graph.add_node(
                    Node(key, N_SOURCE, sig.api, method.fqcn, method.name, method.file, line, confidence=MEDIUM,
                         extra={"source_type": sig.kind, "api": sig.api})
                )
                graph.add_edge(Edge(method.key, key, E_ACQUIRES, f"{sig.api} at {method.file}:{line}", line, MEDIUM))
                graph.sources.append({"key": key, "type": sig.kind, "api": sig.api, "class": method.fqcn,
                                      "method": method.name, "line": line, "confidence": MEDIUM,
                                      "evidence": f"{sig.api} at {method.file}:{line}"})
        # Java sinks
        for sig in JAVA_SINK_SIGNATURES:
            for m in sig.regex().finditer(masked):
                line = base_line + masked[: m.start()].count("\n")
                key = f"sink:{method.key}:{sig.id}:{line}"
                graph.add_node(
                    Node(key, N_SINK, sig.api, method.fqcn, method.name, method.file, line, confidence=MEDIUM,
                         extra={"sink_type": sig.kind, "api": sig.api, "category": "java"})
                )
                graph.add_edge(Edge(method.key, key, E_INVOKES, f"{sig.api} at {method.file}:{line}", line, MEDIUM))
                graph.sinks.append({"key": key, "type": sig.kind, "api": sig.api, "category": "java",
                                    "class": method.fqcn, "method": method.name, "line": line,
                                    "confidence": MEDIUM, "evidence": f"{sig.api} at {method.file}:{line}"})
        _intra_method_taint(graph, method, masked)


def _intra_method_taint(graph: CodeGraph, method: MethodInfo, masked: str) -> None:
    """Link a source to a sink in the same method when a tainted var reaches it."""
    tainted: dict[str, int] = {}
    for lineno, line in enumerate(masked.splitlines()):
        assign = re.match(r"\s*(?:[\w.$<>\[\]]+\s+)?([A-Za-z_]\w*)\s*=\s*(.+)", line)
        if assign and any(sig.regex().search(assign.group(2)) for sig in SOURCE_SIGNATURES):
            tainted[assign.group(1)] = method.start_line + lineno
        for sig in JAVA_SINK_SIGNATURES:
            if sig.regex().search(line):
                args = line[line.find("(") :]
                for var in tainted:
                    if re.search(rf"\b{re.escape(var)}\b", args):
                        src_key = f"taint:{method.key}:{var}"
                        graph.add_node(Node(src_key, N_SOURCE, f"tainted:{var}", method.fqcn, method.name,
                                            method.file, tainted[var], MEDIUM, {"source_type": "tainted_local"}))
                        sink_key = f"sink:{method.key}:{sig.id}:{method.start_line + lineno}"
                        if sink_key in graph.nodes:
                            graph.add_edge(Edge(src_key, sink_key, E_FLOWS,
                                                f"tainted '{var}' reaches {sig.api}", method.start_line + lineno, MEDIUM))


def _build_call_edges(graph, methods, index_by_key, by_simple, class_names) -> None:
    for method in methods:
        if not method.body:
            continue
        masked = _mask(method.body)
        base_line = method.start_line
        locals_types = {m.group(2): m.group(1).split(".")[-1] for m in _LOCAL_DECL_RE.finditer(masked)}
        seen: set[tuple[str, str]] = set()

        def emit(target: MethodInfo, confidence: str, pos: int, label: str) -> None:
            edge_key = (target.key, label)
            if edge_key in seen:
                return
            seen.add(edge_key)
            line = base_line + masked[:pos].count("\n")
            graph.add_edge(Edge(method.key, target.key, E_CALLS, f"{label} at {method.file}:{line}", line, confidence))

        # Type.method(...) with a known class
        for m in _STATIC_CALL_RE.finditer(masked):
            simple = m.group(1).split(".")[-1]
            targets = by_simple.get((simple, m.group(2)))
            if targets:
                emit(targets[0], MEDIUM, m.start(), f"{simple}.{m.group(2)}()")
        # receiver.method(...) where receiver's declared type is known
        for m in _RECEIVER_CALL_RE.finditer(masked):
            recv, name = m.group(1), m.group(2)
            type_simple = locals_types.get(recv)
            if type_simple:
                targets = by_simple.get((type_simple, name))
                if targets:
                    emit(targets[0], LOW, m.start(), f"{recv}.{name}()")
        # bare method(...) -> same class
        for m in _BARE_CALL_RE.finditer(masked):
            name = m.group(1)
            if name in _CONTROL:
                continue
            targets = by_simple.get((method.class_simple, name))
            if targets and targets[0].key != method.key:
                emit(targets[0], MEDIUM, m.start(), f"{name}()")


def _build_native(graph, native_results, jni_bindings, index_by_key, by_simple) -> None:
    native_results = native_results or []
    jni_bindings = jni_bindings or []
    lib_nodes: dict[str, str] = {}
    for lib in native_results:
        if getattr(lib, "status", "COMPLETE") != "COMPLETE":
            continue
        lib_key = f"lib:{lib.filename}:{lib.abi}"
        graph.add_node(Node(lib_key, N_NATIVE_LIB, lib.filename, extra={"abi": lib.abi, "arch": lib.architecture}))
        lib_nodes[lib.filename] = lib_key
        # Native functions + native sinks (imported dangerous symbols)
        imported = {f.name for f in lib.functions if f.kind == "imported"}
        for func in lib.functions:
            if func.kind != "exported":
                continue
            fn_key = f"nfunc:{lib.filename}:{func.name}"
            graph.add_node(Node(fn_key, N_NATIVE_FUNC, func.name, extra={"library": lib.filename, "is_jni": func.is_jni}))
            graph.add_edge(Edge(lib_key, fn_key, E_DECLARES, f"exported by {lib.filename}", None, HIGH))
        for symbol, category in NATIVE_SINK_SYMBOLS.items():
            if symbol in imported:
                sink_key = f"nsink:{lib.filename}:{symbol}"
                graph.add_node(Node(sink_key, N_SINK, symbol, extra={"sink_type": category, "category": "native",
                                                                      "library": lib.filename}))
                graph.add_edge(Edge(lib_key, sink_key, E_DEPENDS, f"{lib.filename} imports {symbol}", None, LOW))
                graph.sinks.append({"key": sink_key, "type": category, "api": symbol, "category": "native",
                                    "class": lib.filename, "method": symbol, "line": None, "confidence": LOW,
                                    "evidence": f"{lib.filename} imports {symbol}"})

    # JNI bindings: Java native method -> JNI -> native function
    for binding in jni_bindings:
        if binding.source not in ("ELF_EXPORT", "JAVA_NATIVE", "JNI_ONLOAD"):
            continue
        jni_key = f"jni:{binding.native_function or binding.java_method or binding.evidence[:32]}"
        graph.add_node(Node(jni_key, N_JNI, binding.native_function or "jni", binding.java_class, binding.java_method,
                            confidence=binding.confidence, extra={"source": binding.source}))
        # Java native method node -> BINDS_TO -> jni
        if binding.java_class and binding.java_method:
            simple = binding.java_class.rsplit(".", 1)[-1]
            targets = by_simple.get((simple, binding.java_method))
            if targets:
                graph.add_edge(Edge(targets[0].key, jni_key, E_BINDS,
                                    f"native method {binding.java_class}.{binding.java_method} -> {binding.native_function}",
                                    None, binding.confidence))
        # jni -> native function
        if binding.library_name and binding.native_function:
            fn_key = f"nfunc:{binding.library_name}:{binding.native_function}"
            if fn_key in graph.nodes:
                graph.add_edge(Edge(jni_key, fn_key, E_BINDS, f"{binding.native_function} in {binding.library_name}",
                                    None, binding.confidence))


def _build_entry_points(graph, components, methods) -> None:
    by_class: dict[str, list[MethodInfo]] = {}
    for method in methods:
        by_class.setdefault(method.fqcn, []).append(method)
        by_class.setdefault(method.class_simple, []).append(method)

    for component in components or []:
        if not component.get("effective_exported"):
            continue
        name = component.get("name") or ""
        simple = name.rsplit(".", 1)[-1].lstrip(".") if name else ""
        kind = component.get("type", "activity")
        entry_names = _ENTRY_METHODS.get(kind, {"onCreate"})
        comp_key = f"entry:{name}"
        graph.add_node(Node(comp_key, N_ENTRY, name, class_name=name, confidence=HIGH,
                            extra={"kind": kind, "exported": True, "permission": component.get("permission"),
                                   "intent_filters": component.get("intent_filters", [])}))
        graph.entry_points.append({"key": comp_key, "component": name, "kind": kind, "exported": True,
                                   "permission": component.get("permission"),
                                   "intent_filters": component.get("intent_filters", []),
                                   "evidence": "AndroidManifest.xml exported component"})
        # Connect entry point to the class's entry methods, if decompiled.
        candidates = by_class.get(name) or by_class.get(simple) or []
        for method in candidates:
            if method.name in entry_names:
                graph.add_edge(Edge(comp_key, method.key, E_DECLARES,
                                    f"exported {kind} entry {method.name}", method.start_line, HIGH))


# ---------------------------------------------------------------------------
# Path search
# ---------------------------------------------------------------------------

_TRAVERSABLE = {
    E_CALLS, E_INVOKES, E_BINDS, E_DEPENDS, E_FLOWS, E_DECLARES, E_ACQUIRES, E_LOADS,
    E_FRAMEWORK_DISPATCH, E_IPC_CALL, E_INTENT_FLOW, E_SECURITY_BOUNDARY,
    E_DEEP_LINK, E_WEBVIEW_BRIDGE, E_REFLECTION_TARGET, E_DYNAMIC_LOAD,
}


def find_paths(graph: CodeGraph, from_key: str, to_key: str, max_depth: int = DEFAULT_MAX_DEPTH, limit: int = 20):
    """BFS shortest paths from a start node to a target node (bounded)."""
    if from_key not in graph.nodes or to_key not in graph.nodes:
        return []
    results: list[PathResult] = []
    queue: deque = deque([(from_key, [from_key], [])])
    while queue and len(results) < limit:
        current, node_path, edge_path = queue.popleft()
        if len(node_path) > max_depth:
            continue
        if current == to_key and edge_path:
            results.append(_materialize(graph, node_path, edge_path))
            continue
        for edge in graph.adjacency.get(current, []):
            if edge.edge_type not in _TRAVERSABLE:
                continue
            if edge.dst in node_path:  # prevent cycles
                continue
            queue.append((edge.dst, node_path + [edge.dst], edge_path + [edge]))
    results.sort(key=lambda p: len(p.nodes))
    return results


def reachable_node_set(graph: CodeGraph, max_nodes: int = 200000) -> set[str]:
    """Forward-reachable node keys from all entry points and sources (one BFS).

    Reused by CVE reachability correlation so we do not run a path search per
    dependency. Bounded to keep large APKs usable.
    """
    starts = [n.key for n in graph.nodes.values() if n.node_type in (N_ENTRY, N_SOURCE, N_FRAMEWORK, N_BOUNDARY)]
    visited: set[str] = set(starts)
    queue: deque = deque(starts)
    while queue and len(visited) < max_nodes:
        current = queue.popleft()
        for edge in graph.adjacency.get(current, []):
            if edge.edge_type in _TRAVERSABLE and edge.dst not in visited:
                visited.add(edge.dst)
                queue.append(edge.dst)
    return visited


def _target_keys(graph: CodeGraph) -> set[str]:
    """Reachability targets: security sinks and JNI-boundary native functions.

    A native function is a boundary target only when it is reached from Java via a
    BINDS_TO edge (statically justified). Without Ghidra, native functions are not
    linked to imported native sinks, so no fabricated Activity->strcpy path exists.
    """
    targets = {key for key, node in graph.nodes.items() if node.node_type == N_SINK}
    for edge in graph.edges:
        if edge.edge_type == E_BINDS and graph.nodes.get(edge.dst) and graph.nodes[edge.dst].node_type == N_NATIVE_FUNC:
            targets.add(edge.dst)
    return targets


def find_target_paths(graph: CodeGraph, from_key: str, targets: set[str], max_depth: int = DEFAULT_MAX_DEPTH, limit: int = 50):
    """All shortest paths from a start node to any target node (bounded BFS)."""
    if from_key not in graph.nodes:
        return []
    results: list[PathResult] = []
    seen: set[str] = set()
    queue: deque = deque([(from_key, [from_key], [])])
    while queue and len(results) < limit:
        current, node_path, edge_path = queue.popleft()
        if len(node_path) > max_depth:
            continue
        if current in targets and edge_path and current not in seen:
            seen.add(current)
            results.append(_materialize(graph, node_path, edge_path))
            continue
        for edge in graph.adjacency.get(current, []):
            if edge.edge_type not in _TRAVERSABLE or edge.dst in node_path:
                continue
            queue.append((edge.dst, node_path + [edge.dst], edge_path + [edge]))
    return results


def _materialize(graph: CodeGraph, node_keys: list[str], edges: list[Edge]) -> PathResult:
    nodes = [graph.nodes[k] for k in node_keys]
    confidence = HIGH
    for edge in edges:
        if _CONF_RANK[edge.confidence] < _CONF_RANK[confidence]:
            confidence = edge.confidence
    has_source = any(n.node_type == N_SOURCE for n in nodes)
    has_entry = any(n.node_type == N_ENTRY for n in nodes)
    status = "REACHABLE" if (has_source or has_entry) else "UNKNOWN"
    return PathResult(nodes=nodes, edges=edges, status=status, confidence=confidence)


# ---------------------------------------------------------------------------
# Reachability findings
# ---------------------------------------------------------------------------

_SINK_TYPE_TO_RULE = {
    "webview": ("ANDROID-REACH-001", "External input reaches WebView sink", "medium"),
    "command_exec": ("ANDROID-REACH-002", "External input reaches command execution sink", "medium"),
    "unsafe_string": ("ANDROID-REACH-004", "External input reaches native security-relevant API", "medium"),
    "unsafe_parse": ("ANDROID-REACH-004", "External input reaches native security-relevant API", "low"),
    "reflection": ("ANDROID-REACH-001", "External input reaches reflection sink", "low"),
    "dynamic_loading": ("ANDROID-REACH-001", "External input reaches dynamic class loading sink", "medium"),
    "file_write": ("ANDROID-REACH-001", "External input reaches file write sink", "low"),
    "sql": ("ANDROID-REACH-001", "External input reaches SQL sink", "low"),
}


def reachability_paths(graph: CodeGraph, max_depth: int = DEFAULT_MAX_DEPTH) -> list[PathResult]:
    """Compute reachable entry->target and source->target paths across the graph."""
    starts = [n.key for n in graph.nodes.values() if n.node_type in (N_ENTRY, N_SOURCE)]
    targets = _target_keys(graph)
    paths: list[PathResult] = []
    for start in starts:
        paths.extend(find_target_paths(graph, start, targets, max_depth=max_depth))
    # Deduplicate by (start, end) keeping the shortest.
    best: dict[tuple[str, str], PathResult] = {}
    for path in paths:
        key = (path.nodes[0].key, path.nodes[-1].key)
        if key not in best or len(path.nodes) < len(best[key].nodes):
            best[key] = path
    return sorted(best.values(), key=lambda p: len(p.nodes))


def reachability_findings(paths: list[PathResult]):
    """Generate reachability findings from established paths. Imported lazily to
    avoid a hard import cycle with the rule engine's dataclasses."""
    from app.rules.engine import Evidence, Finding

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for path in sorted(paths, key=lambda p: len(p.nodes)):
        terminal = path.nodes[-1]
        has_source = any(n.node_type == N_SOURCE for n in path.nodes)
        has_entry = any(n.node_type == N_ENTRY for n in path.nodes)

        if terminal.node_type == N_SINK:
            if not has_source:
                continue  # a sink reachable without external input is not a finding
            category = terminal.extra.get("sink_type", "")
            rule_id, title, severity = _SINK_TYPE_TO_RULE.get(
                category, ("ANDROID-REACH-001", "External input reaches security-relevant sink", "low")
            )
        elif terminal.node_type == N_NATIVE_FUNC:
            if not (has_entry or has_source):
                continue
            rule_id, title, severity = ("ANDROID-REACH-003", "Exported component reaches JNI/native boundary", "low")
        else:
            continue

        dedupe = (rule_id, terminal.key)
        if dedupe in seen:
            continue
        seen.add(dedupe)

        evidence = _path_evidence(Evidence, path)
        findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                category="reachability",
                severity=severity,
                confidence=path.confidence,
                status=path.status,
                description=(
                    "A statically reachable path connects an attack-surface entry point or "
                    "external input source to a security-relevant operation. This is a reachability "
                    "observation, not a confirmed vulnerability; exploitability requires further review."
                ),
                remediation=(
                    "Validate and sanitize external input before it reaches the sink, restrict the "
                    "exported component, and confirm whether the input is truly attacker-controllable."
                ),
                references=["https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0024/"],
                evidence=evidence,
                component=path.nodes[0].label,
            )
        )
    return findings


def _path_evidence(Evidence, path: PathResult) -> list:
    evidence = []
    for index, node in enumerate(path.nodes):
        relation = path.edges[index - 1].edge_type if index > 0 else "ENTRY"
        detail = f"[{index + 1}] {node.node_type} {node.label}"
        if index > 0:
            detail += f"  ({relation}: {path.edges[index - 1].evidence})"
        evidence.append(
            Evidence(
                source="reachability",
                location=f"{node.source_file or ''}:{node.line}" if node.line else (node.class_name or node.label),
                detail=detail,
                artifact=node.source_file,
                class_name=node.class_name,
                method_name=node.method_name,
                line=node.line,
            )
        )
    return evidence

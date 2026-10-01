"""Android semantic analysis.

Extends the existing reachability graph (never a second graph) with Android
execution semantics: framework lifecycle dispatch, intents, deep links, IPC/
Binder, ContentProvider inputs, WebView JavaScript bridges, reflection, dynamic
class loading, storage/crypto/network classification, and security boundaries.

Every relationship is evidence-backed. Values are extracted only when they are
constants; dynamic values are recorded as UNKNOWN. Reachability is established,
never exploitability.
"""

from __future__ import annotations

import re

from app.analysis import reachability as R
from app.analysis.reachability import CodeGraph, Edge, Node

HIGH, MEDIUM, LOW, UNKNOWN = "HIGH", "MEDIUM", "LOW", "UNKNOWN"

FRAMEWORK_KEY = "android:framework"

# Lifecycle / framework entry methods per component type -> lifecycle event.
LIFECYCLE: dict[str, dict[str, str]] = {
    "activity": {
        "onCreate": "CREATE", "onStart": "START", "onResume": "RESUME", "onPause": "PAUSE",
        "onStop": "STOP", "onDestroy": "DESTROY", "onNewIntent": "NEW_INTENT",
    },
    "activity-alias": {"onCreate": "CREATE", "onNewIntent": "NEW_INTENT"},
    "service": {
        "onCreate": "CREATE", "onStartCommand": "START_COMMAND", "onBind": "BIND",
        "onUnbind": "UNBIND", "onDestroy": "DESTROY", "onHandleIntent": "HANDLE_INTENT",
    },
    "receiver": {"onReceive": "RECEIVE"},
    "provider": {
        "onCreate": "CREATE", "query": "QUERY", "insert": "INSERT", "update": "UPDATE",
        "delete": "DELETE", "getType": "GET_TYPE", "openFile": "OPEN_FILE",
        "openAssetFile": "OPEN_ASSET_FILE", "call": "CALL",
    },
    "application": {"onCreate": "CREATE"},
}

_PROVIDER_INPUT_METHODS = {"query", "insert", "update", "delete", "getType", "openFile", "openAssetFile", "call"}

_CAP = 2000  # bound per-category semantic outputs on very large APKs

# Detectors (regex on masked method bodies).
_INTENT_OPS = (
    ("getIntent", re.compile(r"\.getIntent\s*\(")),
    ("new Intent", re.compile(r"\bnew\s+Intent\s*\(")),
    ("startActivity", re.compile(r"\.startActivity\s*\(")),
    ("startActivityForResult", re.compile(r"\.startActivityForResult\s*\(")),
    ("startService", re.compile(r"\.startService\s*\(")),
    ("bindService", re.compile(r"\.bindService\s*\(")),
    ("sendBroadcast", re.compile(r"\.sendBroadcast\s*\(")),
    ("sendOrderedBroadcast", re.compile(r"\.sendOrderedBroadcast\s*\(")),
)
_ACTION_RE = re.compile(r'new\s+Intent\s*\(\s*"([^"]+)"')
_SETACTION_RE = re.compile(r'\.setAction\s*\(\s*"([^"]+)"')
_SETDATA_RE = re.compile(r'\.setData\s*\(\s*Uri\.parse\s*\(\s*"([^"]+)"')
_SETCLASS_RE = re.compile(r'\.setClassName\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"')

_WEBVIEW_JSI_RE = re.compile(r'\.addJavascriptInterface\s*\(\s*([A-Za-z_]\w*|new\s+[\w.]+)[^,]*,\s*"([^"]+)"')
_JS_ANNOT_RE = re.compile(r"@JavascriptInterface")
_REFLECT_FORNAME_RE = re.compile(r'Class\.forName\s*\(\s*"([^"]+)"')
_REFLECT_DYNAMIC_RE = re.compile(r"Class\.forName\s*\(\s*(?!\")")
_DYNLOAD_RE = re.compile(r"new\s+(DexClassLoader|PathClassLoader|BaseDexClassLoader|InMemoryDexClassLoader)\s*\(([^)]*)\)")
_CRYPTO_RE = re.compile(r"\b(Cipher|MessageDigest|Mac|KeyGenerator)\.getInstance\s*\(\s*\"([^\"]+)\"")
_KEYSPEC_RE = re.compile(r"\b(SecretKeySpec|KeyStore\.getInstance)\b")
_NET_URL_RE = re.compile(r'new\s+URL\s*\(\s*"([^"]+)"')
_NET_API_RE = re.compile(r"\b(HttpURLConnection|OkHttpClient|Retrofit|WebSocket|new\s+Socket)\b")
_TLS_RE = re.compile(r"\b(X509TrustManager|HostnameVerifier|SSLContext|setHostnameVerifier)\b")
_STORAGE_RE = re.compile(
    r"\b(openFileInput|openFileOutput|getFilesDir|getCacheDir|new\s+FileInputStream|new\s+FileOutputStream|"
    r"getSharedPreferences|SQLiteDatabase|RoomDatabase)\b"
)
_ONTRANSACT_RE = re.compile(r"\bonTransact\b")
_TRANSACT_CALL_RE = re.compile(r"\.transact\s*\(")
_CASE_RE = re.compile(r"case\s+(\w+)\s*:")


def _simple(name: str | None) -> str:
    if not name:
        return ""
    return name.rsplit(".", 1)[-1].lstrip(".")


def _line(method, masked: str, pos: int) -> int:
    return method.start_line + masked[:pos].count("\n")


def augment_graph(graph: CodeGraph, components, jni_bindings=None, native_results=None) -> CodeGraph:
    graph.add_node(Node(FRAMEWORK_KEY, R.N_FRAMEWORK, "Android Framework", confidence=HIGH))
    exported = {c.get("name"): c for c in (components or []) if c.get("effective_exported")}
    all_components = {c.get("name"): c for c in (components or [])}

    _framework_and_boundaries(graph, all_components)
    _deep_links(graph, exported)
    _provider_inputs(graph, exported)
    _scan_methods(graph)
    _jni_boundary(graph, jni_bindings)
    return graph


def _method_nodes_for(graph: CodeGraph, component_name: str):
    simple = _simple(component_name)
    matches = []
    for method in graph.methods:
        if method.class_simple == simple or method.fqcn == component_name or method.fqcn.endswith("." + simple):
            matches.append(method)
    return matches


def _framework_and_boundaries(graph: CodeGraph, components: dict) -> None:
    for name, component in components.items():
        kind = component.get("type", "activity")
        exported = bool(component.get("effective_exported"))
        lifecycle = LIFECYCLE.get(kind, {"onCreate": "CREATE"})
        methods = _method_nodes_for(graph, name)
        boundary_key = f"boundary:external_intent:{name}"
        if exported:
            graph.add_node(Node(boundary_key, R.N_BOUNDARY, f"EXTERNAL_INTENT -> {_simple(name)}", confidence=HIGH,
                                extra={"boundary_type": "EXTERNAL_INTENT", "component": name}))
            graph.security_boundaries.append({
                "boundary_type": "EXTERNAL_INTENT", "component": name, "node_key": boundary_key,
                "evidence": f"exported {kind} {name}", "confidence": HIGH})
        for method in methods:
            event = lifecycle.get(method.name)
            if event is None:
                continue
            graph.android_entry_points.append({
                "component": name, "component_type": kind, "method": method.name, "lifecycle_event": event,
                "exported": exported, "permission": component.get("permission"),
                "intent_filters": component.get("intent_filters", []),
                "evidence": f"framework dispatch to {_simple(name)}.{method.name} ({event})",
                "confidence": HIGH, "node_key": method.key})
            graph.add_edge(Edge(FRAMEWORK_KEY, method.key, R.E_FRAMEWORK_DISPATCH,
                                f"Android framework dispatches {_simple(name)}.{method.name}", method.start_line, HIGH))
            graph.semantic_edges.append(Edge(FRAMEWORK_KEY, method.key, R.E_FRAMEWORK_DISPATCH,
                                             f"lifecycle {event}", method.start_line, HIGH))
            if exported:
                graph.add_edge(Edge(boundary_key, method.key, R.E_SECURITY_BOUNDARY,
                                    f"external entry into {_simple(name)}.{method.name}", method.start_line, HIGH))
                graph.semantic_edges.append(Edge(boundary_key, method.key, R.E_SECURITY_BOUNDARY,
                                                 "external intent crosses boundary", method.start_line, HIGH))


def _deep_links(graph: CodeGraph, exported: dict) -> None:
    for name, component in exported.items():
        for filt in component.get("intent_filters", []):
            for data in filt.get("data", []):
                if not any(data.get(k) for k in ("scheme", "host", "path", "pathPrefix", "pathPattern")):
                    continue
                dl_key = f"deeplink:{name}:{data.get('scheme')}:{data.get('host')}:{data.get('path') or data.get('pathPrefix') or data.get('pathPattern')}"
                graph.add_node(Node(dl_key, R.N_BOUNDARY, f"DEEP_LINK {data.get('scheme')}://{data.get('host','')}",
                                    confidence=HIGH, extra={"boundary_type": "DEEP_LINK", "component": name}))
                graph.deep_links.append({
                    "component": name, "scheme": data.get("scheme"), "host": data.get("host"),
                    "port": data.get("port"), "path": data.get("path"), "path_prefix": data.get("pathPrefix"),
                    "path_pattern": data.get("pathPattern"), "mime_type": data.get("mimeType"),
                    "action": ",".join(filt.get("actions", [])) or None,
                    "category": ",".join(filt.get("categories", [])) or None,
                    "evidence": f"manifest intent-filter data on {name}", "confidence": HIGH, "node_key": dl_key})
                for method in _method_nodes_for(graph, name):
                    if method.name in ("onCreate", "onNewIntent"):
                        graph.add_edge(Edge(dl_key, method.key, R.E_DEEP_LINK,
                                            f"deep link routes to {_simple(name)}.{method.name}", method.start_line, HIGH))
                        graph.semantic_edges.append(Edge(dl_key, method.key, R.E_DEEP_LINK, "deep link entry", None, HIGH))


def _provider_inputs(graph: CodeGraph, exported: dict) -> None:
    for name, component in exported.items():
        if component.get("type") != "provider":
            continue
        for method in _method_nodes_for(graph, name):
            if method.name not in _PROVIDER_INPUT_METHODS:
                continue
            src_key = f"cpinput:{method.key}"
            graph.add_node(Node(src_key, R.N_SOURCE, f"CONTENT_PROVIDER_INPUT:{method.name}", method.fqcn,
                                method.name, method.file, method.start_line, MEDIUM,
                                extra={"source_type": "content_provider_input"}))
            graph.add_edge(Edge(method.key, src_key, R.E_ACQUIRES,
                                f"exported provider {_simple(name)}.{method.name} receives external Uri/args",
                                method.start_line, MEDIUM))
            graph.sources.append({"key": src_key, "type": "content_provider_input",
                                  "api": f"ContentProvider.{method.name}", "class": method.fqcn,
                                  "method": method.name, "line": method.start_line, "confidence": MEDIUM,
                                  "evidence": f"exported provider entry {_simple(name)}.{method.name}"})


def _strip_comments(text: str) -> str:
    """Remove comments while KEEPING string literals (needed for constant extraction)."""
    out = []
    i, n, state = 0, len(text), None
    while i < n:
        c, two = text[i], text[i : i + 2]
        if state is None:
            if two == "//":
                state = "line"; out.append("  "); i += 2; continue
            if two == "/*":
                state = "block"; out.append("  "); i += 2; continue
            if c == '"':
                state = "str"; out.append(c); i += 1; continue
            out.append(c); i += 1
        elif state == "line":
            if c == "\n":
                state = None
            out.append(c if c == "\n" else " "); i += 1
        elif state == "block":
            if two == "*/":
                state = None; out.append("  "); i += 2; continue
            out.append("\n" if c == "\n" else " "); i += 1
        elif state == "str":
            out.append(c)
            if c == "\\":
                out.append(text[i + 1] if i + 1 < n else ""); i += 2; continue
            if c == '"':
                state = None
            i += 1
    return "".join(out)


def _scan_methods(graph: CodeGraph) -> None:
    counters = {"intent": 0, "crypto": 0, "network": 0, "storage": 0, "webview": 0, "reflect": 0, "dynload": 0, "ipc": 0}

    for method in graph.methods:
        # IPC service entry is identified by the METHOD NAME, not the body.
        if method.name == "onTransact" and counters["ipc"] < _CAP:
            counters["ipc"] += 1
            codes = sorted({c.group(1) for c in _CASE_RE.finditer(method.body or "")})[:20]
            graph.ipc_transactions.append({
                "kind": "SERVICE_ENTRY", "class_name": method.fqcn, "method_name": method.name,
                "interface_name": method.class_simple, "transaction_code": ",".join(codes) or None,
                "confidence": MEDIUM if codes else LOW,
                "evidence": f"onTransact in {method.class_simple} (codes: {codes or 'UNKNOWN'})"})
            boundary = f"boundary:binder:{method.fqcn}"
            graph.add_node(Node(boundary, R.N_BOUNDARY, f"BINDER_IPC:{method.class_simple}", confidence=MEDIUM,
                                extra={"boundary_type": "BINDER_IPC"}))
            graph.add_edge(Edge(boundary, method.key, R.E_IPC_CALL, f"Binder onTransact entry {method.class_simple}",
                                method.start_line, MEDIUM))
            graph.security_boundaries.append({"boundary_type": "BINDER_IPC", "component": method.fqcn,
                                              "node_key": boundary, "evidence": "onTransact entry", "confidence": MEDIUM})

        if not method.body:
            continue
        # Comment-stripped but string-preserving body (constants must survive).
        body = _strip_comments(method.body)

        # Intents
        for op_name, regex in _INTENT_OPS:
            m = regex.search(body)
            if m and counters["intent"] < _CAP:
                counters["intent"] += 1
                am = _ACTION_RE.search(body) or _SETACTION_RE.search(body)
                dm = _SETDATA_RE.search(body)
                cm = _SETCLASS_RE.search(body)
                action = am.group(1) if am else None
                data_uri = dm.group(1) if dm else None
                target_package, target_component = (cm.group(1), cm.group(2)) if cm else (None, None)
                graph.intents.append({
                    "operation": op_name, "action": action or (UNKNOWN if op_name in ("startActivity", "startService") else None),
                    "data_uri": data_uri, "target_component": target_component, "target_package": target_package,
                    "categories": [], "class_name": method.fqcn, "method_name": method.name,
                    "line": _line(method, body, m.start()),
                    "confidence": HIGH if (action or data_uri or target_component) else MEDIUM,
                    "evidence": f"{op_name} in {method.class_simple}.{method.name}"})

        # WebView JavaScript bridge
        jsi = _WEBVIEW_JSI_RE.search(body)
        if jsi and counters["webview"] < _CAP:
            counters["webview"] += 1
            bridge_name = jsi.group(2)
            bridge_node = f"jsbridge:{bridge_name}"
            graph.add_node(Node(bridge_node, R.N_BOUNDARY, f"WEBVIEW_BRIDGE:{bridge_name}", confidence=MEDIUM,
                                extra={"boundary_type": "WEBVIEW_JS", "bridge": bridge_name}))
            graph.add_edge(Edge(method.key, bridge_node, R.E_WEBVIEW_BRIDGE,
                                f'JavaScript bridge "{bridge_name}" exposed', _line(method, body, jsi.start()), MEDIUM))
            graph.semantic_edges.append(Edge(method.key, bridge_node, R.E_WEBVIEW_BRIDGE,
                                             f'addJavascriptInterface(..., "{bridge_name}")', _line(method, body, jsi.start()), MEDIUM))
            graph.security_boundaries.append({"boundary_type": "WEBVIEW_JS", "component": None, "node_key": bridge_node,
                                              "evidence": f'addJavascriptInterface "{bridge_name}"', "confidence": MEDIUM})

        # Reflection
        rf = _REFLECT_FORNAME_RE.search(body)
        if rf and counters["reflect"] < _CAP:
            counters["reflect"] += 1
            target = rf.group(1)
            dst = f"reflect:{target}"
            graph.add_node(Node(dst, "REFLECTION_TARGET", target, confidence=MEDIUM, extra={"reflection_target": target}))
            graph.add_edge(Edge(method.key, dst, R.E_REFLECTION_TARGET,
                                f'Class.forName("{target}")', _line(method, body, rf.start()), MEDIUM))
            graph.semantic_edges.append(Edge(method.key, dst, R.E_REFLECTION_TARGET, f"constant target {target}", None, MEDIUM))
        elif _REFLECT_DYNAMIC_RE.search(body) and counters["reflect"] < _CAP:
            counters["reflect"] += 1
            graph.semantic_edges.append(Edge(method.key, "reflect:UNKNOWN", R.E_REFLECTION_TARGET,
                                             "Class.forName(<dynamic>) target UNKNOWN", None, UNKNOWN))

        # Dynamic class loading (reuse the existing DEX-loader sink; do not duplicate)
        dl = _DYNLOAD_RE.search(body)
        if dl and counters["dynload"] < _CAP:
            counters["dynload"] += 1
            args = dl.group(2)
            path_kind = "static_constant" if '"' in args else ("external" if any(
                s.regex().search(args) for s in R.SOURCE_SIGNATURES) else "application_controlled")
            dex_sink = next(
                (k for k, n in graph.nodes.items()
                 if n.node_type == R.N_SINK and n.extra.get("sink_type") == "dynamic_loading"
                 and n.class_name == method.fqcn and n.method_name == method.name),
                None,
            )
            if dex_sink is not None:
                graph.add_edge(Edge(method.key, dex_sink, R.E_DYNAMIC_LOAD,
                                    f"{dl.group(1)} (path: {path_kind})", _line(method, body, dl.start()), MEDIUM))
            graph.semantic_edges.append(Edge(method.key, dex_sink or "dynload:UNKNOWN", R.E_DYNAMIC_LOAD,
                                             f"{dl.group(1)} path={path_kind}", _line(method, body, dl.start()), MEDIUM))

        # Crypto (algorithm extraction)
        for cm in _CRYPTO_RE.finditer(body):
            if counters["crypto"] >= _CAP:
                break
            counters["crypto"] += 1
            graph.semantic_edges.append(Edge(method.key, f"crypto:{cm.group(2)}", "CRYPTO",
                                             f'{cm.group(1)}.getInstance("{cm.group(2)}") algorithm={cm.group(2)}',
                                             _line(method, body, cm.start()), HIGH))

        # Network
        if (_NET_URL_RE.search(body) or _NET_API_RE.search(body)) and counters["network"] < _CAP:
            counters["network"] += 1
            um = _NET_URL_RE.search(body)
            tls = "custom" if _TLS_RE.search(body) else "default"
            graph.semantic_edges.append(Edge(method.key, "network", "NETWORK",
                                             f"network usage (url={um.group(1) if um else UNKNOWN}, tls={tls})", None, MEDIUM))

        # Storage
        sm = _STORAGE_RE.search(body)
        if sm and counters["storage"] < _CAP:
            counters["storage"] += 1
            graph.semantic_edges.append(Edge(method.key, "storage", "STORAGE",
                                             f"storage API {sm.group(1)}", _line(method, body, sm.start()), MEDIUM))

        # IPC client-side invocation
        if _TRANSACT_CALL_RE.search(body) and counters["ipc"] < _CAP:
            counters["ipc"] += 1
            graph.ipc_transactions.append({
                "kind": "CLIENT_INVOKE", "class_name": method.fqcn, "method_name": method.name,
                "interface_name": None, "transaction_code": None, "confidence": LOW,
                "evidence": f"transact() call in {method.class_simple}.{method.name} (target UNKNOWN)"})


def _jni_boundary(graph: CodeGraph, jni_bindings) -> None:
    for binding in jni_bindings or []:
        if binding.source != "ELF_EXPORT" or not (binding.java_class and binding.java_method):
            continue
        boundary = f"boundary:jni:{binding.java_class}.{binding.java_method}"
        graph.add_node(Node(boundary, R.N_BOUNDARY, f"JNI_BOUNDARY:{binding.java_method}", confidence=binding.confidence,
                            extra={"boundary_type": "JNI"}))
        graph.security_boundaries.append({"boundary_type": "JNI", "component": binding.java_class,
                                          "node_key": boundary, "evidence": binding.evidence,
                                          "confidence": binding.confidence})


# ---------------------------------------------------------------------------
# Semantic findings
# ---------------------------------------------------------------------------


def semantic_findings(graph: CodeGraph, max_depth: int = 50):
    from app.rules.engine import Evidence, Finding

    findings: list[Finding] = []
    targets = R._target_keys(graph)

    def make(rule_id, title, severity, path, extra_ev=None):
        evidence = R._path_evidence(Evidence, path) if path else []
        if extra_ev:
            evidence = extra_ev + evidence
        return Finding(
            rule_id=rule_id, title=title, category="semantic", severity=severity,
            confidence=path.confidence if path else MEDIUM, status=path.status if path else "REACHABLE",
            description="Android semantic analysis established a security-relevant relationship. This is a "
                        "reachability observation with explicit evidence, not a confirmed vulnerability.",
            remediation="Validate external input at the component boundary and restrict exported surfaces.",
            references=["https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0024/"],
            evidence=evidence, component=path.nodes[0].label if path else None)

    seen: set[tuple] = set()

    # SEMANTIC-001: exported component receives externally controlled input.
    for entry in graph.android_entry_points:
        if not entry["exported"]:
            continue
        method_key = entry["node_key"]
        # a source acquired within the entry method (Intent/provider input)
        has_source = any(e.src == method_key and graph.nodes.get(e.dst) and graph.nodes[e.dst].node_type == R.N_SOURCE
                         for e in graph.adjacency.get(method_key, []))
        key = ("ANDROID-SEMANTIC-001", entry["component"])
        if has_source and key not in seen:
            seen.add(key)
            from app.rules.engine import Evidence
            ev = [Evidence(source="semantic", location=f"{entry['component']}.{entry['method']}",
                           detail=f"exported {entry['component_type']} {entry['component']}.{entry['method']} "
                                  f"({entry['lifecycle_event']}) receives external input", method_name=entry["method"])]
            findings.append(make("ANDROID-SEMANTIC-001",
                                 "Exported component receives externally controlled input", "low", None, ev))

    # Path-based semantic findings from entry points / sources to specific sinks.
    starts = [n.key for n in graph.nodes.values() if n.node_type in (R.N_ENTRY, R.N_SOURCE, R.N_BOUNDARY, R.N_FRAMEWORK)]
    for start in starts:
        for path in R.find_target_paths(graph, start, targets, max_depth=max_depth, limit=30):
            terminal = path.nodes[-1]
            stype = terminal.extra.get("sink_type", "")
            has_source = any(n.node_type == R.N_SOURCE for n in path.nodes)
            if stype == "dynamic_loading" and has_source:  # external INPUT, not merely a boundary
                k = ("ANDROID-SEMANTIC-005", terminal.key)
                if k not in seen:
                    seen.add(k)
                    findings.append(make("ANDROID-SEMANTIC-005",
                                         "External input reaches dynamic class loading", "medium", path))

    # SEMANTIC-002: exported ContentProvider entry method reaches a file operation.
    for entry in graph.android_entry_points:
        if entry["component_type"] != "provider" or not entry["exported"]:
            continue
        if entry["method"] not in _PROVIDER_INPUT_METHODS:
            continue
        for path in R.find_target_paths(graph, entry["node_key"], targets, max_depth=max_depth, limit=10):
            if path.nodes[-1].extra.get("sink_type") == "file_write":
                k = ("ANDROID-SEMANTIC-002", path.nodes[-1].key)
                if k not in seen:
                    seen.add(k)
                    findings.append(make("ANDROID-SEMANTIC-002",
                                         "Exported ContentProvider reaches file operation", "medium", path))

    # SEMANTIC-004: WebView JavaScript interface exposed through a reachable path.
    for edge in graph.semantic_edges:
        if edge.edge_type == R.E_WEBVIEW_BRIDGE and edge.dst.startswith("jsbridge:"):
            k = ("ANDROID-SEMANTIC-004", edge.dst)
            if k in seen:
                continue
            # reachable from an entry point?
            reachable = any(
                edge.src == method_key or _reaches(graph, ep["node_key"], edge.src, max_depth)
                for ep in graph.android_entry_points if ep["exported"]
                for method_key in [ep["node_key"]]
            )
            seen.add(k)
            from app.rules.engine import Evidence
            ev = [Evidence(source="semantic", location=graph.nodes[edge.src].label if edge.src in graph.nodes else edge.src,
                           detail=f"WebView JavaScript interface exposed: {edge.evidence}"
                                  + ("; reachable from an exported entry point" if reachable else ""))]
            findings.append(make("ANDROID-SEMANTIC-004",
                                 "WebView JavaScript interface exposed through reachable path",
                                 "medium" if reachable else "low", None, ev))

    # SEMANTIC-003: Binder entry reaches a security-sensitive operation.
    for txn in graph.ipc_transactions:
        if txn["kind"] != "SERVICE_ENTRY":
            continue
        boundary = f"boundary:binder:{txn['class_name']}"
        for path in R.find_target_paths(graph, boundary, targets, max_depth=max_depth, limit=10):
            k = ("ANDROID-SEMANTIC-003", path.nodes[-1].key)
            if k not in seen:
                seen.add(k)
                findings.append(make("ANDROID-SEMANTIC-003",
                                     "Binder entry reaches security-sensitive operation", "medium", path))
    return findings


def _reaches(graph: CodeGraph, src: str, dst: str, max_depth: int) -> bool:
    return bool(R.find_paths(graph, src, dst, max_depth=max_depth, limit=1))

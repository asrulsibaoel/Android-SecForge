"""Deterministic, bounded graph queries + path investigation (prompt 14).

A small *safe* query abstraction: a fixed registry of named queries — NOT an
arbitrary-code execution mechanism. Each query runs over the existing canonical
graph / persisted entities using indexed lookups and adjacency traversal, with
hard bounds (max depth, max paths, max nodes, timeout, min-confidence). Results
are structured and never invented: a query returns only what the graph can
actually show, and UNKNOWN / POSSIBLY_AFFECTED / NOT_REACHABLE / NOT_OBSERVED
states are preserved verbatim (never upgraded).
"""

from __future__ import annotations

import time
from collections import deque

from app.core.config import settings

_CONF_RANK = {"UNKNOWN": -1, "LOW": 0, "MEDIUM": 1, "HIGH": 2}

# Sink API groupings for the external-to-X queries (substring match on api/label).
_WEBVIEW_APIS = ("loadurl", "loaddata", "addjavascriptinterface", "evaluatejavascript", "webview")
_EXEC_APIS = ("runtime.exec", "processbuilder", "exec", "system", "loadlibrary", "dexclassloader",
              "pathclassloader", "class.forname")


# ---------------------------------------------------------------------------
# Code-graph reconstruction (shared)
# ---------------------------------------------------------------------------


def load_code_graph(analysis):
    """Rebuild the in-memory CodeGraph from persisted code_nodes/code_edges.

    Semantic traversable edges were folded into code_edges at analysis time, so
    this reconstruction is complete for traversal. UNKNOWN reflection/dynamic-load
    targets live only in semantic_edges and are returned separately so uncertainty
    is never hidden."""
    from app.analysis.reachability import CodeGraph, Edge, Node

    graph = CodeGraph()
    for n in analysis.code_nodes:
        graph.add_node(Node(n.node_key, n.node_type, n.label, n.class_name, n.method_name,
                            n.source_file, n.line, n.confidence))
    for e in analysis.code_edges:
        graph.add_edge(Edge(e.src_key, e.dst_key, e.edge_type, e.evidence, e.line, e.confidence))
    unknown_targets: dict[str, list[dict]] = {}
    for se in analysis.semantic_edges:
        if se.dst_key.endswith("UNKNOWN") or se.dst_key.startswith(("reflect:", "dynload:")):
            unknown_targets.setdefault(se.src_key, []).append(
                {"type": se.edge_type, "target": se.dst_key, "evidence": se.evidence, "confidence": se.confidence})
    return graph, unknown_targets


def _match(node, key: str, query: str) -> bool:
    hay = f"{node.label} {node.class_name or ''} {node.node_type} {key}".lower()
    return query.lower() in hay


def _conf_ok(confidence: str, minimum: str | None) -> bool:
    if not minimum:
        return True
    return _CONF_RANK.get((confidence or "UNKNOWN").upper(), -1) >= _CONF_RANK.get(minimum.upper(), -1)


def _path_min_confidence(edges) -> str:
    if not edges:
        return "UNKNOWN"
    ranks = [_CONF_RANK.get((e.confidence or "UNKNOWN").upper(), -1) for e in edges]
    lowest = min(ranks)
    for name, rank in _CONF_RANK.items():
        if rank == lowest:
            return name
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Path investigation (Phase 7)
# ---------------------------------------------------------------------------


def investigate_paths(analysis, from_query: str, to_query: str, max_depth: int | None = None,
                      edge_types: list[str] | None = None, min_confidence: str | None = None,
                      max_paths: int | None = None) -> dict:
    """Bounded path search between node sets matched by from/to queries.

    Returns paths with node metadata, edge types, evidence, confidence, and
    explicit uncertainty boundaries (unresolved reflection/dynamic-load targets
    reachable from the path are surfaced, never silently truncated)."""
    from app.analysis.reachability import _TRAVERSABLE

    max_depth = max_depth or settings.graph_query_max_depth
    max_paths = max_paths or settings.graph_query_max_paths
    timeout = settings.graph_query_timeout_seconds
    allowed = set(edge_types) if edge_types else set(_TRAVERSABLE)

    graph, unknown_targets = load_code_graph(analysis)
    froms = [k for k, n in graph.nodes.items() if _match(n, k, from_query)]
    tos = {k for k, n in graph.nodes.items() if _match(n, k, to_query)}
    if not froms or not tos:
        return {"query": "path", "from": from_query, "to": to_query, "status": "UNKNOWN",
                "reason": "no matching start/target nodes" if not (froms and tos) else "",
                "paths": [], "count": 0, "bounds": _bounds(max_depth, max_paths, timeout),
                "uncertainty": []}

    started = time.monotonic()
    results: list[dict] = []
    truncated = False
    for start in sorted(froms)[:50]:
        if len(results) >= max_paths or time.monotonic() - started > timeout:
            truncated = True
            break
        for path in _bfs_paths(graph, start, tos, allowed, max_depth, max_paths - len(results),
                               min_confidence, started, timeout):
            results.append(path)
            if len(results) >= max_paths:
                truncated = True
                break

    uncertainty = _collect_uncertainty(results, unknown_targets)
    status = "REACHABLE" if results else "NOT_REACHABLE"
    # If reflection/dynamic-load introduces unresolved targets from the start set,
    # the true reachability may be UNKNOWN rather than NOT_REACHABLE.
    if not results and any(k in unknown_targets for k in froms):
        status = "UNKNOWN"
    return {"query": "path", "from": from_query, "to": to_query, "status": status,
            "paths": results, "count": len(results), "truncated": truncated,
            "bounds": _bounds(max_depth, max_paths, timeout), "uncertainty": uncertainty}


def _bfs_paths(graph, start, targets, allowed, max_depth, limit, min_confidence, started, timeout):
    if start not in graph.nodes:
        return []
    out: list[dict] = []
    queue: deque = deque([(start, [start], [])])
    while queue and len(out) < limit:
        if time.monotonic() - started > timeout:
            break
        current, node_path, edge_path = queue.popleft()
        if len(node_path) > max_depth:
            continue
        if current in targets and edge_path:
            out.append(_render_path(graph, node_path, edge_path))
            continue
        for edge in graph.adjacency.get(current, []):
            if edge.edge_type not in allowed:
                continue
            if not _conf_ok(edge.confidence, min_confidence):
                continue
            if edge.dst in node_path:
                continue
            queue.append((edge.dst, node_path + [edge.dst], edge_path + [edge]))
    out.sort(key=lambda p: len(p["nodes"]))
    return out


def _render_path(graph, node_path, edge_path) -> dict:
    nodes = []
    for k in node_path:
        n = graph.nodes[k]
        nodes.append({"key": k, "type": n.node_type, "label": n.label, "class": n.class_name,
                      "file": n.source_file, "line": n.line, "confidence": n.confidence})
    edges = [{"type": e.edge_type, "evidence": e.evidence, "confidence": e.confidence,
              "src": e.src, "dst": e.dst} for e in edge_path]
    return {"length": len(node_path), "confidence": _path_min_confidence(edge_path),
            "edge_types": [e.edge_type for e in edge_path], "nodes": nodes, "edges": edges}


def _collect_uncertainty(paths, unknown_targets) -> list[dict]:
    seen = set()
    out = []
    for p in paths:
        for n in p["nodes"]:
            for u in unknown_targets.get(n["key"], []):
                marker = (n["key"], u["target"])
                if marker in seen:
                    continue
                seen.add(marker)
                out.append({"from": n["key"], "from_label": n["label"], "boundary": u["type"],
                            "target": u["target"], "evidence": u["evidence"],
                            "note": "unresolved target; downstream reachability is UNKNOWN"})
    return out


def _bounds(max_depth, max_paths, timeout) -> dict:
    return {"max_depth": max_depth, "max_paths": max_paths, "timeout_seconds": timeout,
            "max_nodes": settings.graph_query_max_nodes}


# ---------------------------------------------------------------------------
# Named query registry (Phases 9 + 10)
# ---------------------------------------------------------------------------


def _exported_components(analysis, p) -> dict:
    rows = [{"name": c.name, "kind": c.kind, "exposure": c.exposure, "permission": c.permission}
            for c in analysis.components if c.effective_exported]
    return _result("exported-components", rows, "Components reachable from outside the app (Android exposure semantics)")


def _public_attack_surface(analysis, p) -> dict:
    rows = [{"name": n.name, "type": n.node_type, "exposure": n.exposure, "risk_score": n.risk_score,
             "component": n.component}
            for n in sorted(analysis.attack_surface_nodes, key=lambda n: -n.risk_score)
            if n.exposure == "PUBLIC"]
    return _result("public-attack-surface", rows, "Attack-surface nodes classified PUBLIC")


def _findings_reachable_from_exported(analysis, p) -> dict:
    exported = {c.name for c in analysis.components if c.effective_exported}
    rows = [_finding_row(f) for f in analysis.findings
            if f.component in exported and not f.is_duplicate]
    return _result("findings-reachable-from-exported", rows,
                   "Findings whose component is externally exported (reachability of the finding's site)")


def _external_to_webview(analysis, p) -> dict:
    return _external_to(analysis, p, _WEBVIEW_APIS, "external-to-webview",
                        "Paths from an exported/external entry point to a WebView sink")


def _external_to_exec(analysis, p) -> dict:
    return _external_to(analysis, p, _EXEC_APIS, "external-to-exec",
                        "Paths from an exported/external entry point to a command/loader sink")


def _external_to(analysis, p, sink_apis, name, desc) -> dict:
    graph, unknown = load_code_graph(analysis)
    from app.analysis.reachability import N_ENTRY, N_FRAMEWORK, N_BOUNDARY, N_SOURCE, _TRAVERSABLE
    starts = [k for k, n in graph.nodes.items() if n.node_type in (N_ENTRY, N_FRAMEWORK, N_BOUNDARY, N_SOURCE)]
    targets = {k for k, n in graph.nodes.items()
               if n.node_type == "SECURITY_SINK" and any(a in (n.label or "").lower() for a in sink_apis)}
    if not targets:
        return _result(name, [], desc, extra={"status": "NOT_APPLICABLE", "reason": "no matching sink in graph"})
    min_conf = p.get("min_confidence")
    max_depth = p.get("max_depth") or settings.graph_query_max_depth
    started = time.monotonic()
    rows = []
    for s in starts[:100]:
        if len(rows) >= settings.graph_query_max_paths or time.monotonic() - started > settings.graph_query_timeout_seconds:
            break
        for path in _bfs_paths(graph, s, targets, set(_TRAVERSABLE), max_depth,
                               settings.graph_query_max_paths - len(rows), min_conf, started,
                               settings.graph_query_timeout_seconds):
            rows.append({"chain": [n["label"] for n in path["nodes"]], "confidence": path["confidence"],
                         "edge_types": path["edge_types"]})
    uncertainty = _collect_uncertainty(
        [{"nodes": [{"key": k, "label": graph.nodes[k].label} for k in [s]]} for s in starts], unknown)
    return _result(name, rows, desc, extra={"uncertainty": uncertainty})


def _exported_to_jni(analysis, p) -> dict:
    graph, _ = load_code_graph(analysis)
    from app.analysis.reachability import N_ENTRY, N_FRAMEWORK, N_NATIVE_FUNC, E_BINDS, _TRAVERSABLE
    starts = [k for k, n in graph.nodes.items() if n.node_type in (N_ENTRY, N_FRAMEWORK)]
    targets = set()
    for e in graph.edges:
        if e.edge_type == E_BINDS and graph.nodes.get(e.dst) and graph.nodes[e.dst].node_type == N_NATIVE_FUNC:
            targets.add(e.dst)
    if not targets:
        return _result("exported-to-jni", [], "Paths from exported entry points crossing the JNI boundary",
                       extra={"status": "NOT_APPLICABLE", "reason": "no statically-linked JNI boundary"})
    started = time.monotonic()
    rows = []
    for s in starts[:100]:
        for path in _bfs_paths(graph, s, targets, set(_TRAVERSABLE), settings.graph_query_max_depth,
                               settings.graph_query_max_paths - len(rows), p.get("min_confidence"), started,
                               settings.graph_query_timeout_seconds):
            rows.append({"chain": [n["label"] for n in path["nodes"]], "confidence": path["confidence"]})
    return _result("exported-to-jni", rows, "Paths from exported entry points crossing the JNI boundary")


def _cve_reachable(analysis, p) -> dict:
    rows = [_match_row(m) for m in analysis.vulnerability_matches
            if m.correlation_state == "AFFECTED_REACHABLE"]
    return _result("cve-reachable", rows, "CVE matches whose vulnerable dependency is statically reachable")


def _possibly_affected(analysis, p) -> dict:
    # POSSIBLY_AFFECTED is preserved verbatim and never inferred to AFFECTED.
    rows = [_match_row(m) for m in analysis.vulnerability_matches if m.version_state == "POSSIBLY_AFFECTED"]
    return _result("possibly-affected", rows,
                   "Dependencies POSSIBLY_AFFECTED by a CVE (version uncertain; state preserved, not upgraded)")


def _dependencies_with_cve(analysis, p) -> dict:
    by_dep: dict[str, list] = {}
    for m in analysis.vulnerability_matches:
        by_dep.setdefault(m.dependency.name, []).append(m.cve_id)
    rows = [{"dependency": name, "cves": sorted(set(cves))} for name, cves in sorted(by_dep.items())]
    return _result("dependencies-with-cve", rows, "Dependencies with at least one CVE match")


def _runtime_confirmed(analysis, p) -> dict:
    rows = [_finding_row(f) for f in analysis.findings
            if f.runtime_status in ("STATIC_RUNTIME_CONFIRMED", "RUNTIME_SUPPORTS_STATIC_PATH")]
    return _result("runtime-confirmed", rows,
                   "Findings observed / supported at runtime (runtime is corroborating evidence, not proof of exploitability)")


def _runtime_not_observed(analysis, p) -> dict:
    rows = [_finding_row(f) for f in analysis.findings if f.validation_state == "NOT_OBSERVED"]
    return _result("runtime-not-observed", rows,
                   "Findings NOT observed during instrumentation — NOT_OBSERVED does NOT mean safe",
                   extra={"note": "NOT_OBSERVED does not mean safe; absence of an observation is not proof of absence"})


def _unknown_boundaries(analysis, p) -> dict:
    rows = []
    for b in analysis.security_boundaries:
        if (b.confidence or "").upper() in ("LOW", "UNKNOWN"):
            rows.append({"boundary_type": b.boundary_type, "component": b.component, "confidence": b.confidence,
                         "evidence": b.evidence})
    for t in analysis.ipc_transactions:
        if (t.confidence or "").upper() in ("LOW", "UNKNOWN"):
            rows.append({"boundary_type": "BINDER_IPC", "component": t.class_name, "confidence": t.confidence,
                         "evidence": t.evidence})
    return _result("unknown-boundaries", rows,
                   "Security / Binder boundaries whose relationship confidence is LOW or UNKNOWN")


def _webview_bridges(analysis, p) -> dict:
    rows = [{"boundary_type": b.boundary_type, "component": b.component, "confidence": b.confidence,
             "evidence": b.evidence}
            for b in analysis.security_boundaries if "WEBVIEW" in (b.boundary_type or "").upper()]
    return _result("webview-bridges", rows, "WebView JavaScript-bridge boundaries")


def _reflection_paths(analysis, p) -> dict:
    rows = [{"src": se.src_key, "target": se.dst_key, "confidence": se.confidence, "evidence": se.evidence,
             "resolved": not se.dst_key.endswith("UNKNOWN")}
            for se in analysis.semantic_edges if se.edge_type == "REFLECTION_TARGET"]
    return _result("reflection-paths", rows,
                   "Reflection targets; unresolved targets remain UNKNOWN (never assumed benign or malicious)")


def _dynamic_load_paths(analysis, p) -> dict:
    rows = [{"src": se.src_key, "target": se.dst_key, "confidence": se.confidence, "evidence": se.evidence,
             "resolved": not se.dst_key.endswith("UNKNOWN")}
            for se in analysis.semantic_edges if se.edge_type == "DYNAMIC_LOAD"]
    return _result("dynamic-load-paths", rows,
                   "Dynamic code-load sites; unresolved load targets remain UNKNOWN")


def _high_risk_entrypoints(analysis, p) -> dict:
    threshold = int(p.get("threshold", 70))
    rows = [{"name": n.name, "exposure": n.exposure, "risk_score": n.risk_score, "component": n.component}
            for n in sorted(analysis.attack_surface_nodes, key=lambda n: -n.risk_score)
            if n.risk_score >= threshold]
    return _result("high-risk-entrypoints", rows, f"Attack-surface nodes with risk_score >= {threshold}")


def _findings_crossing_jni(analysis, p) -> dict:
    rows = []
    for f in analysis.findings:
        text = " ".join([f.title or ""] + [e.detail or "" for e in f.evidence]).upper()
        if "JNI" in text or "BINDS_TO" in text or "NATIVE_FUNCTION" in text:
            rows.append(_finding_row(f))
    return _result("findings-crossing-jni", rows, "Findings whose evidence crosses the Java/native (JNI) boundary")


def _findings_involving_native(analysis, p) -> dict:
    lib_names = {lib.filename for lib in analysis.native_libraries}
    rows = []
    for f in analysis.findings:
        if f.category == "native" or (f.component and f.component in lib_names):
            rows.append(_finding_row(f))
    return _result("findings-involving-native", rows, "Findings involving a native library")


def _obfuscated_components(analysis, p) -> dict:
    rows = [{"target": o.target, "category": o.category, "state": o.state, "confidence": o.confidence,
             "indicator": o.indicator}
            for o in analysis.obfuscation_observations if o.target]
    return _result("obfuscated-components", rows, "Components/targets with obfuscation observations")


def _obfuscated_entrypoints(analysis, p) -> dict:
    entry_components = {e.component for e in analysis.android_entry_points}
    rows = [{"target": o.target, "category": o.category, "state": o.state, "indicator": o.indicator}
            for o in analysis.obfuscation_observations
            if o.target and any((o.target or "").split("#")[0].endswith(c.rsplit(".", 1)[-1]) or c in (o.target or "")
                                for c in entry_components if c)]
    return _result("obfuscated-entrypoints", rows, "Entry-point components carrying obfuscation observations")


def _anti_analysis_query(analysis, p) -> dict:
    rows = [{"category": i.category, "indicator": i.indicator, "evidence_level": i.evidence_level,
             "confidence": i.confidence, "finding_type": i.finding_type}
            for i in analysis.anti_analysis_indicators]
    return _result("anti-analysis", rows,
                   "Anti-analysis indicators (presence is an indicator, not proof of active anti-analysis)")


def _unresolved_reflection(analysis, p) -> dict:
    rows = [{"target": o.target, "state": o.state, "indicator": o.indicator}
            for o in analysis.obfuscation_observations
            if o.category == "DYNAMIC_RESOLUTION" and "reflection" in o.indicator
            and o.state in ("UNRESOLVED", "EXTERNALLY_INFLUENCED")]
    return _result("unresolved-reflection", rows, "Unresolved/externally-influenced reflection targets (UNKNOWN preserved)")


def _unresolved_dynamic_loading(analysis, p) -> dict:
    rows = [{"target": o.target, "state": o.state, "indicator": o.indicator}
            for o in analysis.obfuscation_observations
            if o.category == "DYNAMIC_RESOLUTION" and "dynamic_load" in o.indicator
            and o.state in ("UNRESOLVED", "EXTERNALLY_INFLUENCED")]
    return _result("unresolved-dynamic-loading", rows, "Unresolved dynamic-load targets (UNKNOWN preserved)")


def _native_indirection(analysis, p) -> dict:
    rows = [{"target": o.target, "state": o.state, "indicator": o.indicator, "confidence": o.confidence}
            for o in analysis.obfuscation_observations if o.category == "NATIVE_INDIRECTION"]
    return _result("native-indirection", rows, "Native indirection observations (UNKNOWN_NATIVE_TARGET preserved)")


def _analysis_uncertainty(analysis, p) -> dict:
    rows = [{"impact_category": i.impact_category, "affected_target": i.affected_target,
             "description": i.description, "confidence": i.confidence}
            for i in analysis.analysis_impacts]
    return _result("analysis-uncertainty", rows,
                   "Analytical impacts from obfuscation (reduced name/native confidence, unresolved reflection/dynload)")


def _root_causes_for_component(analysis, p) -> dict:
    component = p.get("component")
    if not component:
        return _result("root-causes-for-component", [], "Root causes affecting a component (requires --component)",
                       extra={"status": "NOT_APPLICABLE", "reason": "no --component provided"})
    rows = [{"identifier": rc.identifier, "category": rc.category, "title": rc.title, "severity": rc.severity,
             "confidence": rc.confidence}
            for rc in analysis.root_causes
            if any(component in (c or "") for c in (rc.affected_components or []))]
    return _result("root-causes-for-component", rows, f"Root causes affecting component '{component}'")


_REGISTRY = {
    "exported-components": _exported_components,
    "public-attack-surface": _public_attack_surface,
    "findings-reachable-from-exported": _findings_reachable_from_exported,
    "external-to-webview": _external_to_webview,
    "external-to-exec": _external_to_exec,
    "exported-to-jni": _exported_to_jni,
    "cve-reachable": _cve_reachable,
    "possibly-affected": _possibly_affected,
    "dependencies-with-cve": _dependencies_with_cve,
    "runtime-confirmed": _runtime_confirmed,
    "runtime-not-observed": _runtime_not_observed,
    "unknown-boundaries": _unknown_boundaries,
    "webview-bridges": _webview_bridges,
    "reflection-paths": _reflection_paths,
    "dynamic-load-paths": _dynamic_load_paths,
    "high-risk-entrypoints": _high_risk_entrypoints,
    "findings-crossing-jni": _findings_crossing_jni,
    "findings-involving-native": _findings_involving_native,
    "root-causes-for-component": _root_causes_for_component,
    "obfuscated-components": _obfuscated_components,
    "obfuscated-entrypoints": _obfuscated_entrypoints,
    "anti-analysis": _anti_analysis_query,
    "unresolved-reflection": _unresolved_reflection,
    "unresolved-dynamic-loading": _unresolved_dynamic_loading,
    "native-indirection": _native_indirection,
    "analysis-uncertainty": _analysis_uncertainty,
}


def available_queries() -> list[str]:
    return sorted(_REGISTRY)


def run_query(analysis, name: str, params: dict | None = None) -> dict:
    fn = _REGISTRY.get(name)
    if fn is None:
        raise ValueError(f"unknown query '{name}'. Available: {', '.join(available_queries())}")
    return fn(analysis, params or {})


# --- row/result helpers ----------------------------------------------------


def _result(name, rows, description, extra: dict | None = None) -> dict:
    out = {"query": name, "description": description, "count": len(rows), "results": rows}
    if extra:
        out.update(extra)
    return out


def _finding_row(f) -> dict:
    return {"id": str(f.id), "rule_id": f.rule_id, "category": f.category, "severity": f.severity,
            "confidence": f.confidence, "status": f.status, "component": f.component,
            "runtime_status": f.runtime_status, "validation_state": f.validation_state}


def _match_row(m) -> dict:
    return {"cve_id": m.cve_id, "dependency": m.dependency.name, "version_state": m.version_state,
            "correlation_state": m.correlation_state, "reachability_state": m.reachability_state,
            "match_confidence": m.match_confidence, "severity": m.severity}

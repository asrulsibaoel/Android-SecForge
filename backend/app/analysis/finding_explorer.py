"""Finding-centric investigation + deterministic explanation engine (prompt 14).

``explore_finding`` returns the complete evidence neighbourhood of a finding
(root cause, evidence, correlated findings, attack surface, component, entry
points, sources/sinks, reachability paths, dependencies, CVE matches, JNI/native,
runtime observations, graph neighbours). ``explain_finding`` answers
"why is this a finding?" deterministically.

Invariants: analytical states are preserved verbatim — a POSSIBLY_AFFECTED CVE
stays POSSIBLY_AFFECTED even when the dependency is reachable; UNKNOWN stays
UNKNOWN; NOT_OBSERVED never becomes SAFE. The engine never uses the word
"exploitable" and never asserts exploitability.
"""

from __future__ import annotations

from app.analysis import knowledge_graph as KG


def _finding_component(analysis, finding):
    return next((c for c in analysis.components if c.name == finding.component), None)


def explore_finding(analysis, finding) -> dict:
    """Full finding-centric bundle. All relationships preserve UNKNOWN states."""
    component = _finding_component(analysis, finding)
    root_cause = None
    if finding.root_cause_id:
        root_cause = next((rc for rc in analysis.root_causes if rc.id == finding.root_cause_id), None)

    correlated = _correlated_findings(analysis, finding)
    entry_points = [
        {"component": e.component, "method": e.method, "lifecycle_event": e.lifecycle_event,
         "exported": e.exported, "confidence": e.confidence}
        for e in analysis.android_entry_points if e.component == finding.component
    ]
    sources, sinks = _sources_sinks_from_evidence(analysis, finding)
    paths = _reachability_paths(analysis, finding)
    deps, cves = _dependencies_and_cves(analysis, finding)
    jni, native_libs = _native_context(analysis, finding)
    runtime = _runtime_observations(analysis, finding)
    neighbors = _graph_neighbors(analysis, finding)

    return {
        "finding": {
            "id": str(finding.id), "rule_id": finding.rule_id, "title": finding.title,
            "category": finding.category, "severity": finding.severity, "confidence": finding.confidence,
            "status": finding.status, "component": finding.component,
            "is_duplicate": finding.is_duplicate,
            "runtime_status": finding.runtime_status, "validation_state": finding.validation_state,
            "runtime_evidence_count": finding.runtime_evidence_count,
        },
        "root_cause": None if root_cause is None else {
            "identifier": root_cause.identifier, "category": root_cause.category, "title": root_cause.title,
            "severity": root_cause.severity, "confidence": root_cause.confidence},
        "supporting_evidence": [
            {"source": e.source, "location": e.location, "detail": e.detail, "class": e.class_name,
             "method": e.method_name, "line": e.line}
            for e in finding.evidence],
        "correlated_findings": correlated,
        "attack_surface": [
            {"name": n.name, "type": n.node_type, "exposure": n.exposure, "risk_score": n.risk_score}
            for n in analysis.attack_surface_nodes if n.component == finding.component],
        "affected_component": None if component is None else {
            "name": component.name, "kind": component.kind, "exposure": component.exposure,
            "effective_exported": component.effective_exported, "permission": component.permission},
        "entry_points": entry_points,
        "sources": sources,
        "sinks": sinks,
        "reachability_paths": paths,
        "dependencies": deps,
        "cve_matches": cves,  # version_state preserved verbatim
        "jni_boundaries": jni,
        "native_libraries": native_libs,
        "runtime_observations": runtime,
        "graph_neighbors": neighbors,
    }


def _correlated_findings(analysis, finding) -> list[dict]:
    dims = {(c.dimension, c.correlation_key) for c in analysis.finding_correlations if c.finding_id == finding.id}
    if not dims:
        return []
    peers: dict = {}
    id_to_finding = {f.id: f for f in analysis.findings}
    for corr in analysis.finding_correlations:
        if (corr.dimension, corr.correlation_key) in dims and corr.finding_id != finding.id:
            peer = id_to_finding.get(corr.finding_id)
            if peer is not None:
                peers[peer.id] = {"id": str(peer.id), "rule_id": peer.rule_id, "severity": peer.severity,
                                  "status": peer.status, "dimension": corr.dimension,
                                  "correlation_key": corr.correlation_key}
    return sorted(peers.values(), key=lambda r: (r["dimension"], r["rule_id"]))


def _sources_sinks_from_evidence(analysis, finding):
    text = " ".join(e.detail or "" for e in finding.evidence)
    sources = [{"api": s.api, "type": s.source_type, "class": s.class_name, "method": s.method_name}
               for s in analysis.dataflow_sources if s.api and s.api in text]
    sinks = [{"api": s.api, "type": s.sink_type, "category": s.category, "class": s.class_name,
              "method": s.method_name}
             for s in analysis.security_sinks if s.api and s.api in text]
    return sources, sinks


def _reachability_paths(analysis, finding) -> list[dict]:
    rows = []
    for p in analysis.reachability_paths:
        if p.rule_id == finding.rule_id or (finding.component and p.from_label and finding.component.rsplit(".", 1)[-1] in p.from_label):
            rows.append({"status": p.status, "confidence": p.confidence, "length": p.length,
                         "chain": [n.get("label") for n in (p.nodes or [])]})
    return rows[:25]


def _dependencies_and_cves(analysis, finding):
    if finding.category != "cve":
        return [], []
    import re
    m = re.search(r"(CVE-\d{4}-\d{4,7})", finding.title or "")
    cve_id = m.group(1) if m else None
    cves, deps = [], []
    seen_dep = set()
    for match in analysis.vulnerability_matches:
        if cve_id and match.cve_id != cve_id:
            continue
        cves.append({"cve_id": match.cve_id, "dependency": match.dependency.name,
                     "version_state": match.version_state, "correlation_state": match.correlation_state,
                     "reachability_state": match.reachability_state, "severity": match.severity})
        if match.dependency.id not in seen_dep:
            seen_dep.add(match.dependency.id)
            d = match.dependency
            deps.append({"name": d.name, "ecosystem": d.ecosystem, "version": d.version,
                         "version_confidence": d.version_confidence, "identity_confidence": d.identity_confidence})
    return deps, cves


def _native_context(analysis, finding):
    if finding.category != "native":
        return [], []
    jni = [{"java_class": b.java_class, "java_method": b.java_method, "native_function": b.native_function,
            "library": b.library_name, "confidence": b.confidence}
           for b in analysis.jni_bindings if b.library_name == finding.component]
    libs = [{"filename": lib.filename, "abi": lib.abi, "architecture": lib.architecture, "stripped": lib.stripped}
            for lib in analysis.native_libraries if lib.filename == finding.component]
    return jni, libs


def _runtime_observations(analysis, finding) -> list[dict]:
    text = " ".join([finding.title or ""] + [e.detail or "" for e in finding.evidence])
    out = []
    for s in analysis.runtime_sessions:
        for o in s.observations:
            token = None
            if o.class_name and o.method_name:
                token = f"{o.class_name.rsplit('.', 1)[-1]}.{o.method_name}"
            elif o.symbol:
                token = o.symbol
            if token and token in text:
                out.append({"type": o.observation_type, "class": o.class_name, "method": o.method_name,
                            "symbol": o.symbol, "source": o.source, "confidence": o.confidence})
    return out


def _graph_neighbors(analysis, finding, limit: int = 40) -> list[dict]:
    kg = KG.build_knowledge_graph(analysis, include_code=False)
    fref = KG._finding_ref(finding)
    if fref not in kg.nodes:
        return []
    return kg.neighbors(fref)[:limit]


# ---------------------------------------------------------------------------
# Explanation engine (Phase 8) — deterministic "why is this a finding?"
# ---------------------------------------------------------------------------

_CATEGORY_STATEMENT = {
    "reachability": "the static rule identifies a potential external-input-to-sink dataflow",
    "semantic": "the static rule identifies a potential Android-semantic exposure",
    "webview": "the static rule identifies a potentially unsafe WebView configuration",
    "cve": "the dependency matches a known-vulnerable version range in the local CVE database",
    "native": "the static rule flags a native indicator (imported symbol / bundled library)",
    "manifest": "the manifest configuration matches a static rule",
    "code": "the decompiled code matches a static rule pattern",
}


def explain_finding(analysis, finding) -> dict:
    """Deterministic WHY_FOUND / EVIDENCE_CHAIN / ASSUMPTIONS / UNCERTAINTIES /
    LIMITATIONS / RELATED_ENTITIES. Never claims exploitability."""
    why = _why_found(analysis, finding)
    chain = [{"step": i + 1, "source": e.source, "location": e.location, "detail": e.detail}
             for i, e in enumerate(finding.evidence)]
    assumptions = [
        "static call resolution is conservative (only statically-resolvable calls are edges)",
        "dynamic dispatch and virtual calls may be unresolved and therefore under-approximated",
    ]
    if finding.category in ("semantic", "reachability"):
        assumptions.append("reflection and dynamic class-loading targets may remain UNKNOWN")

    uncertainties = _uncertainties(analysis, finding)
    limitations = _limitations(analysis, finding)
    related = _related_entities(analysis, finding)

    return {
        "finding": {"rule_id": finding.rule_id, "title": finding.title, "severity": finding.severity,
                    "confidence": finding.confidence, "status": finding.status},
        "WHY_FOUND": why,
        "EVIDENCE_CHAIN": chain,
        "ASSUMPTIONS": assumptions,
        "UNCERTAINTIES": uncertainties,
        "LIMITATIONS": limitations,
        "RELATED_ENTITIES": related,
    }


def _why_found(analysis, finding) -> list[str]:
    steps: list[str] = []
    component = _finding_component(analysis, finding)
    if component is not None and component.effective_exported:
        steps.append(f"Component {component.name} ({component.kind}) is exported (exposure={component.exposure}).")
    # Prefer a real reachability path when one produced this finding.
    path = next((p for p in analysis.reachability_paths
                 if p.rule_id == finding.rule_id and p.status == "REACHABLE"), None)
    if path is not None:
        labels = [n.get("label") for n in (path.nodes or []) if n.get("label")]
        for i, label in enumerate(labels):
            if i == 0:
                steps.append(f"Input enters at {label}.")
            elif i == len(labels) - 1:
                steps.append(f"The dataflow reaches {label}.")
            else:
                steps.append(f"Control/data flows through {label}.")
    else:
        for e in finding.evidence:
            steps.append(f"Evidence ({e.source}): {e.detail}")
    statement = _CATEGORY_STATEMENT.get(finding.category, "a static rule matched the observed evidence")
    steps.append(f"Therefore {statement}.")
    return steps


def _uncertainties(analysis, finding) -> list[str]:
    out: list[str] = []
    if finding.validation_state in (None, "NOT_RUN"):
        out.append("runtime reachability not observed (no runtime instrumentation run for this finding)")
    elif finding.validation_state == "NOT_OBSERVED":
        out.append("runtime instrumentation ran but did not observe this behavior — NOT_OBSERVED does not mean safe")
    elif finding.validation_state == "INCONCLUSIVE":
        out.append("runtime observation was inconclusive for this finding")
    if finding.category == "cve":
        for m in analysis.vulnerability_matches:
            if m.version_state in ("POSSIBLY_AFFECTED", "UNKNOWN") and (m.cve_id in (finding.title or "")):
                out.append(f"CVE version match is {m.version_state}; not inferred to AFFECTED even if reachable")
    if any(se.edge_type in ("REFLECTION_TARGET", "DYNAMIC_LOAD") and se.dst_key.endswith("UNKNOWN")
           for se in analysis.semantic_edges):
        out.append("reflection/dynamic-load targets in this app include unresolved (UNKNOWN) destinations")
    return out


def _limitations(analysis, finding) -> list[str]:
    caps = analysis.capabilities or {}
    out: list[str] = []
    if not analysis.runtime_sessions:
        out.append("no runtime observation available for this analysis")
    if caps.get("code_analysis") in ("UNAVAILABLE", None) or caps.get("jadx") not in ("AVAILABLE", "COMPLETE"):
        out.append("Java decompilation (JADX) was unavailable/partial; code-level reachability is limited")
    if caps.get("ghidra") in ("UNAVAILABLE", "DISABLED", None):
        out.append("native decompilation (Ghidra) not applied; deep native dataflow is not modeled")
    return out


def _related_entities(analysis, finding) -> dict:
    related: dict = {"component": finding.component}
    if finding.root_cause_id:
        rc = next((rc for rc in analysis.root_causes if rc.id == finding.root_cause_id), None)
        if rc is not None:
            related["root_cause"] = rc.identifier
    correlated = _correlated_findings(analysis, finding)
    if correlated:
        related["correlated_findings"] = [c["rule_id"] for c in correlated]
    if finding.category == "cve":
        _, cves = _dependencies_and_cves(analysis, finding)
        related["cves"] = [c["cve_id"] for c in cves]
    return related


def evidence_chain(analysis, finding) -> dict:
    """The ordered, provenance-tagged evidence chain behind a finding."""
    kg_source = None
    steps = []
    for i, e in enumerate(finding.evidence):
        steps.append({
            "step": i + 1, "source": e.source, "provenance": KG._source_provenance(e.source),
            "location": e.location, "class": e.class_name, "method": e.method_name, "line": e.line,
            "detail": e.detail,
        })
    return {
        "finding": {"rule_id": finding.rule_id, "title": finding.title, "status": finding.status,
                    "severity": finding.severity, "confidence": finding.confidence},
        "fingerprint": finding.fingerprint,
        "chain": steps,
        "note": "Every step traces to persisted evidence; nothing is inferred beyond the recorded provenance.",
    }

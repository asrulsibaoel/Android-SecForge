"""Comparative (APK diff) engine — prompt 15.

Compares two existing analyses (baseline A, candidate B) entity-by-entity using
stable identities (never decompiler line numbers), reusing prompt-14 graph
snapshots for integrity where available. It is read-only against both analyses:
it only writes comparison_* rows. Every diff record keeps evidence + provenance +
confidence, analytical states are preserved verbatim (UNKNOWN / NOT_REACHABLE /
NOT_OBSERVED / POSSIBLY_AFFECTED are never re-interpreted), and nothing is ever
called "fixed" or "exploitable" without positive evidence.

Security-impact classification is conservative: a regression/improvement verdict
requires positive security evidence; a disappeared finding is NO_LONGER_DETECTED,
not FIXED; an appeared finding is not automatically exploitable.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.core.config import settings
from app.models.comparison import (
    CHANGE_ADDED, CHANGE_CHANGED, CHANGE_REMOVED,
    IMPACT_IMPROVEMENT, IMPACT_INCONCLUSIVE, IMPACT_MIXED, IMPACT_NONE, IMPACT_REGRESSION,
    MODE_MIXED, MODE_RECONSTRUCTED, MODE_SNAPSHOT,
    STATUS_COMPLETE, STATUS_FAILED, STATUS_PARTIAL,
    AnalysisComparison, ComparisonChange, ComparisonFinding, ComparisonRiskDelta, ComparisonSummary,
)

_CONF_RANK = {"UNKNOWN": -1, "LOW": 0, "MEDIUM": 1, "HIGH": 2}

# Categories.
CAT_MANIFEST = "manifest"
CAT_SEMANTICS = "semantics"
CAT_CODE = "code"
CAT_NATIVE = "native"
CAT_DEPENDENCY = "dependency"
CAT_CVE = "cve"
CAT_ROOT_CAUSE = "root_cause"
CAT_ATTACK_SURFACE = "attack_surface"
CAT_REACHABILITY = "reachability"
CAT_RUNTIME = "runtime"
CAT_OBFUSCATION = "obfuscation"
CAT_NATIVE_DEEP = "native_deep"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class _Change:
    category: str
    entity_type: str
    identity: str
    change_type: str
    baseline_value: str | None = None
    candidate_value: str | None = None
    confidence: str = "MEDIUM"
    security_relevant: bool = False
    provenance: str = "STATIC"
    evidence: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Comparison identity + snapshot integrity
# ---------------------------------------------------------------------------


def comparison_fingerprint(baseline, candidate, snap_a_digest: str | None, snap_b_digest: str | None) -> str:
    """Deterministic, direction-sensitive identity for the ordered pair (A→B)."""
    raw = f"{baseline.id}|{candidate.id}|{snap_a_digest or 'none'}|{snap_b_digest or 'none'}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _latest_snapshot(analysis):
    snaps = list(analysis.graph_snapshots)
    if not snaps:
        return None
    return max(snaps, key=lambda s: s.created_at or datetime.min.replace(tzinfo=timezone.utc))


def _verify_snapshot(analysis, snap) -> tuple[bool, str | None]:
    """Recompute the knowledge-graph digest and compare to the stored snapshot.
    Deterministic projection means an intact analysis reproduces its digest."""
    from app.analysis.knowledge_graph import build_knowledge_graph, graph_digest

    recomputed = graph_digest(build_knowledge_graph(analysis))
    if recomputed != snap.digest:
        return False, (f"snapshot digest mismatch (recorded {snap.digest[:12]}, "
                       f"recomputed {recomputed[:12]}) — refusing to compare a stale/corrupted snapshot")
    return True, None


# ---------------------------------------------------------------------------
# Indexing (built once per analysis; no O(N×M))
# ---------------------------------------------------------------------------


def _index(analysis) -> dict:
    idx: dict = {}
    idx["permissions"] = {p.name: p for p in analysis.permissions}
    idx["components"] = {c.name: c for c in analysis.components if c.name}
    idx["deep_links"] = {(d.component, d.scheme, d.host, d.path or d.path_prefix or d.path_pattern): d
                         for d in analysis.deep_links}
    idx["intent_filters"] = {(c.name, tuple(sorted(a for f in (c.intent_filters or []) for a in f.get("actions", []))))
                             for c in analysis.components if c.name}
    idx["entry_points"] = {(e.component, e.method): e for e in analysis.android_entry_points}
    idx["intents"] = {(i.operation, i.action, i.data_uri, i.target_component) for i in analysis.intents}
    idx["ipc"] = {(t.kind, t.class_name, t.method_name, t.interface_name) for t in analysis.ipc_transactions}
    idx["boundaries"] = {(b.boundary_type, b.component): b for b in analysis.security_boundaries}
    idx["webview_bridges"] = {(e.src_key, e.dst_key) for e in analysis.semantic_edges if e.edge_type == "WEBVIEW_BRIDGE"}
    idx["reflection"] = {(e.src_key, e.dst_key): e for e in analysis.semantic_edges if e.edge_type == "REFLECTION_TARGET"}
    idx["dynamic_load"] = {(e.src_key, e.dst_key): e for e in analysis.semantic_edges if e.edge_type == "DYNAMIC_LOAD"}
    idx["classes"] = {e.class_name for e in analysis.code_entities if e.entity_type == "class" and e.class_name}
    idx["methods"] = {(e.class_name, e.name, e.signature) for e in analysis.code_entities if e.entity_type == "method"}
    idx["fields"] = {(e.class_name, e.name) for e in analysis.code_entities if e.entity_type == "field"}
    idx["calls"] = {(e.src_key, e.dst_key) for e in analysis.code_edges if e.edge_type in ("CALLS", "INVOKES")}
    idx["sources"] = {(s.api, s.class_name, s.method_name) for s in analysis.dataflow_sources}
    idx["sinks"] = {(s.api, s.class_name, s.method_name, s.category) for s in analysis.security_sinks}
    idx["reach_paths"] = {(p.rule_id, p.from_key, p.to_key, p.status): p for p in analysis.reachability_paths}
    idx["native_libs"] = {lib.archive_path: lib for lib in analysis.native_libraries}
    idx["native_funcs"] = {(f.library.filename if f.library else "?", f.name, f.kind)
                           for f in analysis.native_functions}
    idx["jni"] = {(b.java_class, b.java_method, b.native_function, b.library_name): b for b in analysis.jni_bindings}
    idx["deps"] = {(d.ecosystem, d.name): d for d in analysis.dependencies}
    idx["cve"] = {(m.cve_id, m.dependency.name): m for m in analysis.vulnerability_matches}
    idx["root_causes"] = {rc.identifier: rc for rc in analysis.root_causes}
    # root-cause UUID -> stable identifier (never compare raw PKs across analyses).
    idx["rc_by_id"] = {rc.id: rc.identifier for rc in analysis.root_causes}
    idx["as_nodes"] = {n.node_key: n for n in analysis.attack_surface_nodes}
    idx["as_edges"] = {(e.src_key, e.dst_key, e.edge_type) for e in analysis.attack_surface_edges}
    idx["observations"] = {(o.observation_type, o.class_name, o.method_name, o.symbol)
                           for s in analysis.runtime_sessions for o in s.observations}
    idx["findings"] = list(analysis.findings)
    return idx


def _set_diff(a: set, b: set):
    return (a - b, b - a)  # removed, added


# ---------------------------------------------------------------------------
# Category differs
# ---------------------------------------------------------------------------


def _diff_manifest(ia, ib) -> list[_Change]:
    out: list[_Change] = []
    rem, add = _set_diff(set(ia["permissions"]), set(ib["permissions"]))
    for name in sorted(rem):
        p = ia["permissions"][name]
        out.append(_Change(CAT_MANIFEST, "permission", name, CHANGE_REMOVED,
                           baseline_value=p.protection_level, confidence="HIGH",
                           security_relevant=p.is_dangerous, provenance="MANIFEST",
                           evidence={"protection_level": p.protection_level, "dangerous": p.is_dangerous}))
    for name in sorted(add):
        p = ib["permissions"][name]
        out.append(_Change(CAT_MANIFEST, "permission", name, CHANGE_ADDED,
                           candidate_value=p.protection_level, confidence="HIGH",
                           security_relevant=p.is_dangerous, provenance="MANIFEST",
                           evidence={"protection_level": p.protection_level, "dangerous": p.is_dangerous}))

    rem, add = _set_diff(set(ia["components"]), set(ib["components"]))
    for name in sorted(rem):
        c = ia["components"][name]
        out.append(_Change(CAT_MANIFEST, "component", name, CHANGE_REMOVED,
                           baseline_value=f"{c.kind} exposure={c.exposure}", confidence="HIGH",
                           security_relevant=c.effective_exported, provenance="MANIFEST",
                           evidence={"kind": c.kind, "exposure": c.exposure, "exported": c.effective_exported}))
    for name in sorted(add):
        c = ib["components"][name]
        out.append(_Change(CAT_MANIFEST, "component", name, CHANGE_ADDED,
                           candidate_value=f"{c.kind} exposure={c.exposure}", confidence="HIGH",
                           security_relevant=c.effective_exported, provenance="MANIFEST",
                           evidence={"kind": c.kind, "exposure": c.exposure, "exported": c.effective_exported}))
    for name in sorted(set(ia["components"]) & set(ib["components"])):
        ca, cb = ia["components"][name], ib["components"][name]
        dims = {}
        if ca.exposure != cb.exposure:
            dims["exposure"] = [ca.exposure, cb.exposure]
        if ca.effective_exported != cb.effective_exported:
            dims["effective_exported"] = [ca.effective_exported, cb.effective_exported]
        if ca.permission != cb.permission:
            dims["permission"] = [ca.permission, cb.permission]
        if dims:
            # exported_state_changed is security-relevant either direction.
            sec = "effective_exported" in dims or "exposure" in dims or "permission" in dims
            out.append(_Change(CAT_MANIFEST, "component", name, CHANGE_CHANGED,
                               baseline_value=f"exposure={ca.exposure} exported={ca.effective_exported}",
                               candidate_value=f"exposure={cb.exposure} exported={cb.effective_exported}",
                               confidence="HIGH", security_relevant=sec, provenance="MANIFEST",
                               evidence={"changed": dims}))

    rem, add = _set_diff(ia["intent_filters"], ib["intent_filters"])
    for comp, actions in sorted(rem, key=lambda x: str(x[0])):
        if actions:
            out.append(_Change(CAT_MANIFEST, "intent_filter", f"{comp}", CHANGE_REMOVED,
                               baseline_value=",".join(actions), confidence="HIGH", provenance="MANIFEST",
                               evidence={"actions": list(actions)}))
    for comp, actions in sorted(add, key=lambda x: str(x[0])):
        if actions:
            out.append(_Change(CAT_MANIFEST, "intent_filter", f"{comp}", CHANGE_ADDED,
                               candidate_value=",".join(actions), confidence="HIGH", provenance="MANIFEST",
                               evidence={"actions": list(actions)}))

    rem, add = _set_diff(set(ia["deep_links"]), set(ib["deep_links"]))
    for key in sorted(rem, key=str):
        out.append(_Change(CAT_MANIFEST, "deep_link", str(key), CHANGE_REMOVED, confidence="HIGH",
                           security_relevant=True, provenance="MANIFEST", evidence={"key": list(key)}))
    for key in sorted(add, key=str):
        out.append(_Change(CAT_MANIFEST, "deep_link", str(key), CHANGE_ADDED, confidence="HIGH",
                           security_relevant=True, provenance="MANIFEST", evidence={"key": list(key)}))
    return out


def _diff_semantics(ia, ib) -> list[_Change]:
    out: list[_Change] = []

    def simple_set(key, etype, sec=False, prov="SEMANTICS"):
        rem, add = _set_diff(set(ia[key]) if not isinstance(ia[key], set) else ia[key],
                             set(ib[key]) if not isinstance(ib[key], set) else ib[key])
        for k in sorted(rem, key=str):
            out.append(_Change(CAT_SEMANTICS, etype, str(k), CHANGE_REMOVED, confidence="MEDIUM",
                               security_relevant=sec, provenance=prov, evidence={"key": list(k) if isinstance(k, tuple) else k}))
        for k in sorted(add, key=str):
            out.append(_Change(CAT_SEMANTICS, etype, str(k), CHANGE_ADDED, confidence="MEDIUM",
                               security_relevant=sec, provenance=prov, evidence={"key": list(k) if isinstance(k, tuple) else k}))

    # entry points (keyed dict)
    rem, add = _set_diff(set(ia["entry_points"]), set(ib["entry_points"]))
    for k in sorted(rem, key=str):
        e = ia["entry_points"][k]
        out.append(_Change(CAT_SEMANTICS, "entry_point", str(k), CHANGE_REMOVED, confidence=e.confidence,
                           security_relevant=e.exported, provenance="SEMANTICS",
                           evidence={"component": e.component, "method": e.method, "exported": e.exported}))
    for k in sorted(add, key=str):
        e = ib["entry_points"][k]
        out.append(_Change(CAT_SEMANTICS, "entry_point", str(k), CHANGE_ADDED, confidence=e.confidence,
                           security_relevant=e.exported, provenance="SEMANTICS",
                           evidence={"component": e.component, "method": e.method, "exported": e.exported}))

    simple_set("intents", "intent")
    simple_set("ipc", "ipc", sec=True)
    simple_set("webview_bridges", "webview_bridge", sec=True)

    # boundaries (keyed dict)
    rem, add = _set_diff(set(ia["boundaries"]), set(ib["boundaries"]))
    for k in sorted(rem, key=str):
        b = ia["boundaries"][k]
        out.append(_Change(CAT_SEMANTICS, "boundary", str(k), CHANGE_REMOVED, confidence=b.confidence,
                           security_relevant=True, provenance="SEMANTICS", evidence={"boundary_type": b.boundary_type}))
    for k in sorted(add, key=str):
        b = ib["boundaries"][k]
        out.append(_Change(CAT_SEMANTICS, "boundary", str(k), CHANGE_ADDED, confidence=b.confidence,
                           security_relevant=True, provenance="SEMANTICS", evidence={"boundary_type": b.boundary_type}))

    # reflection / dynamic-load (preserve UNKNOWN targets explicitly)
    for key, etype in (("reflection", "reflection_target"), ("dynamic_load", "dynamic_load")):
        rem, add = _set_diff(set(ia[key]), set(ib[key]))
        for k in sorted(rem, key=str):
            e = ia[key][k]
            out.append(_Change(CAT_SEMANTICS, etype, str(k), CHANGE_REMOVED, confidence=e.confidence,
                               security_relevant=True, provenance="SEMANTICS",
                               evidence={"target": k[1], "unknown_target": str(k[1]).endswith("UNKNOWN")}))
        for k in sorted(add, key=str):
            e = ib[key][k]
            out.append(_Change(CAT_SEMANTICS, etype, str(k), CHANGE_ADDED, confidence=e.confidence,
                               security_relevant=True, provenance="SEMANTICS",
                               evidence={"target": k[1], "unknown_target": str(k[1]).endswith("UNKNOWN")}))
    return out


def _diff_code(ia, ib) -> list[_Change]:
    # Emits the full code delta; the persist loop applies (and records) the
    # per-category bound so truncation is never silent.
    out: list[_Change] = []
    for key, etype in (("classes", "class"), ("methods", "method"), ("fields", "field"),
                       ("calls", "call"), ("sources", "source"), ("sinks", "sink")):
        rem, add = _set_diff(ia[key], ib[key])
        for k in sorted(rem, key=str):
            out.append(_Change(CAT_CODE, etype, str(k), CHANGE_REMOVED, confidence="MEDIUM", provenance="JADX",
                               evidence={"identity": list(k) if isinstance(k, tuple) else k}))
        for k in sorted(add, key=str):
            out.append(_Change(CAT_CODE, etype, str(k), CHANGE_ADDED, confidence="MEDIUM", provenance="JADX",
                               evidence={"identity": list(k) if isinstance(k, tuple) else k}))
    return out


def _diff_reachability(ia, ib) -> list[_Change]:
    out: list[_Change] = []
    rem, add = _set_diff(set(ia["reach_paths"]), set(ib["reach_paths"]))
    for k in sorted(rem, key=str):
        p = ia["reach_paths"][k]
        out.append(_Change(CAT_REACHABILITY, "reach_path", str(k), CHANGE_REMOVED, confidence=p.confidence,
                           security_relevant=(p.status == "REACHABLE"), provenance="REACHABILITY",
                           baseline_value=f"{p.status}/{p.confidence}",
                           evidence={"rule_id": p.rule_id, "status": p.status, "from": p.from_label, "to": p.to_label}))
    for k in sorted(add, key=str):
        p = ib["reach_paths"][k]
        out.append(_Change(CAT_REACHABILITY, "reach_path", str(k), CHANGE_ADDED, confidence=p.confidence,
                           security_relevant=(p.status == "REACHABLE"), provenance="REACHABILITY",
                           candidate_value=f"{p.status}/{p.confidence}",
                           evidence={"rule_id": p.rule_id, "status": p.status, "from": p.from_label, "to": p.to_label}))
    return out


def _diff_native(ia, ib) -> list[_Change]:
    out: list[_Change] = []
    rem, add = _set_diff(set(ia["native_libs"]), set(ib["native_libs"]))
    for path in sorted(rem):
        lib = ia["native_libs"][path]
        out.append(_Change(CAT_NATIVE, "native_library", path, CHANGE_REMOVED, confidence="HIGH", provenance="ELF",
                           baseline_value=f"{lib.abi} soname={lib.soname}",
                           evidence={"abi": lib.abi, "soname": lib.soname, "architecture": lib.architecture}))
    for path in sorted(add):
        lib = ib["native_libs"][path]
        out.append(_Change(CAT_NATIVE, "native_library", path, CHANGE_ADDED, confidence="HIGH", provenance="ELF",
                           candidate_value=f"{lib.abi} soname={lib.soname}",
                           evidence={"abi": lib.abi, "soname": lib.soname, "architecture": lib.architecture}))
    for path in sorted(set(ia["native_libs"]) & set(ib["native_libs"])):
        la, lb = ia["native_libs"][path], ib["native_libs"][path]
        dims = {}
        for attr in ("architecture", "soname", "stripped"):
            if getattr(la, attr) != getattr(lb, attr):
                dims[attr] = [getattr(la, attr), getattr(lb, attr)]
        needed_a = {d.needed for d in la.dependencies}
        needed_b = {d.needed for d in lb.dependencies}
        if needed_a != needed_b:
            dims["needed"] = {"removed": sorted(needed_a - needed_b), "added": sorted(needed_b - needed_a)}
        if dims:
            out.append(_Change(CAT_NATIVE, "native_library", path, CHANGE_CHANGED, confidence="HIGH",
                               provenance="ELF", evidence={"changed": dims}))

    rem, add = _set_diff(ia["native_funcs"], ib["native_funcs"])
    for k in sorted(rem, key=str):
        out.append(_Change(CAT_NATIVE, "native_function", str(k), CHANGE_REMOVED, confidence="HIGH",
                           provenance="ELF", evidence={"identity": list(k)}))
    for k in sorted(add, key=str):
        out.append(_Change(CAT_NATIVE, "native_function", str(k), CHANGE_ADDED, confidence="HIGH",
                           provenance="ELF", evidence={"identity": list(k)}))

    rem, add = _set_diff(set(ia["jni"]), set(ib["jni"]))
    for k in sorted(rem, key=str):
        b = ia["jni"][k]
        out.append(_Change(CAT_NATIVE, "jni_binding", str(k), CHANGE_REMOVED, confidence=b.confidence,
                           security_relevant=True, provenance="JNI",
                           evidence={"source": b.source, "confidence": b.confidence}))
    for k in sorted(add, key=str):
        b = ib["jni"][k]
        out.append(_Change(CAT_NATIVE, "jni_binding", str(k), CHANGE_ADDED, confidence=b.confidence,
                           security_relevant=True, provenance="JNI",
                           evidence={"source": b.source, "confidence": b.confidence}))
    for k in sorted(set(ia["jni"]) & set(ib["jni"]), key=str):
        ba, bb = ia["jni"][k], ib["jni"][k]
        if ba.confidence != bb.confidence:
            out.append(_Change(CAT_NATIVE, "jni_binding", str(k), CHANGE_CHANGED,
                               baseline_value=ba.confidence, candidate_value=bb.confidence, confidence="HIGH",
                               provenance="JNI", evidence={"confidence": [ba.confidence, bb.confidence]}))
    return out


def _diff_dependencies(ia, ib) -> list[_Change]:
    out: list[_Change] = []
    rem, add = _set_diff(set(ia["deps"]), set(ib["deps"]))
    for k in sorted(rem, key=str):
        d = ia["deps"][k]
        out.append(_Change(CAT_DEPENDENCY, "dependency", f"{d.ecosystem}:{d.name}", CHANGE_REMOVED,
                           baseline_value=d.version or "UNKNOWN", confidence=d.identity_confidence,
                           provenance="STATIC_RULE",
                           evidence={"classification": "REMOVED", "version": d.version, "kind": d.kind}))
    for k in sorted(add, key=str):
        d = ib["deps"][k]
        out.append(_Change(CAT_DEPENDENCY, "dependency", f"{d.ecosystem}:{d.name}", CHANGE_ADDED,
                           candidate_value=d.version or "UNKNOWN", confidence=d.identity_confidence,
                           provenance="STATIC_RULE",
                           evidence={"classification": "ADDED", "version": d.version, "kind": d.kind}))
    for k in sorted(set(ia["deps"]) & set(ib["deps"]), key=str):
        da, db_ = ia["deps"][k], ib["deps"][k]
        dims = {}
        if da.version != db_.version:
            if da.version and db_.version:
                dims["classification"] = "VERSION_CHANGED"
            else:
                dims["classification"] = "VERSION_UNKNOWN"
            dims["version"] = [da.version, db_.version]
        elif da.kind != db_.kind or da.bundled != db_.bundled:
            dims["classification"] = "CLASSIFICATION_CHANGED"
            dims["kind"] = [da.kind, db_.kind]
            dims["bundled"] = [da.bundled, db_.bundled]
        if dims:
            # A version change alone is NOT a security conclusion (see CVE diff).
            out.append(_Change(CAT_DEPENDENCY, "dependency", f"{da.ecosystem}:{da.name}", CHANGE_CHANGED,
                               baseline_value=da.version or "UNKNOWN", candidate_value=db_.version or "UNKNOWN",
                               confidence="MEDIUM", provenance="STATIC_RULE", evidence=dims))
    return out


def _diff_cve(ia, ib) -> list[_Change]:
    out: list[_Change] = []
    keys = set(ia["cve"]) | set(ib["cve"])
    for k in sorted(keys, key=str):
        ma, mb = ia["cve"].get(k), ib["cve"].get(k)
        cve_id, dep = k
        if ma and not mb:
            ev = _cve_evidence(ma)
            ev["transition"] = "REMOVED_MATCH"
            out.append(_Change(CAT_CVE, "cve_match", f"{cve_id}@{dep}", CHANGE_REMOVED,
                               baseline_value=f"{ma.version_state}/{ma.correlation_state}",
                               confidence=ma.match_confidence, security_relevant=True, provenance="CVE_DATABASE",
                               evidence=ev))
        elif mb and not ma:
            ev = _cve_evidence(mb)
            ev["transition"] = "NEW_MATCH"
            out.append(_Change(CAT_CVE, "cve_match", f"{cve_id}@{dep}", CHANGE_ADDED,
                               candidate_value=f"{mb.version_state}/{mb.correlation_state}",
                               confidence=mb.match_confidence, security_relevant=True, provenance="CVE_DATABASE",
                               evidence=ev))
        else:
            # transitions — states preserved verbatim, never re-interpreted.
            transitions = _cve_transitions(ma, mb)
            if transitions:
                out.append(_Change(CAT_CVE, "cve_match", f"{cve_id}@{dep}", CHANGE_CHANGED,
                                   baseline_value=f"{ma.version_state}/{ma.correlation_state}/{ma.reachability_state}",
                                   candidate_value=f"{mb.version_state}/{mb.correlation_state}/{mb.reachability_state}",
                                   confidence=mb.match_confidence, security_relevant=True, provenance="CVE_DATABASE",
                                   evidence={"transitions": transitions, "baseline": _cve_evidence(ma),
                                             "candidate": _cve_evidence(mb)}))
    return out


def _cve_transitions(ma, mb) -> list[str]:
    """Conservative CVE transition labels between two matches of the same
    (cve, dependency). Never asserts remediation or exploitability."""
    t: list[str] = []
    if ma.version_state != mb.version_state or ma.correlation_state != mb.correlation_state:
        t.append("STATE_CHANGED")
    if (ma.dependency.version or None) != (mb.dependency.version or None):
        t.append("VERSION_CHANGED")
    if ma.reachability_state != mb.reachability_state:
        t.append("REACHABILITY_CHANGED")
    if ma.signature_state != mb.signature_state:
        t.append("SIGNATURE_CHANGED")
    return t


def _cve_evidence(m) -> dict:
    return {"cve_id": m.cve_id, "dependency": m.dependency.name, "installed_version": m.dependency.version,
            "version_state": m.version_state, "correlation_state": m.correlation_state,
            "reachability_state": m.reachability_state, "signature_state": m.signature_state,
            "confidence": m.match_confidence, "severity": m.severity, "evidence": m.evidence}


def _diff_root_causes(ia, ib) -> list[_Change]:
    out: list[_Change] = []
    rem, add = _set_diff(set(ia["root_causes"]), set(ib["root_causes"]))
    for ident in sorted(rem):
        rc = ia["root_causes"][ident]
        out.append(_Change(CAT_ROOT_CAUSE, "root_cause", ident, CHANGE_REMOVED,
                           baseline_value=f"{rc.severity} {rc.category}", confidence=rc.confidence,
                           security_relevant=True, provenance="STATIC_RULE",
                           evidence={"category": rc.category, "severity": rc.severity, "disposition": "NO_LONGER_DETECTED"}))
    for ident in sorted(add):
        rc = ib["root_causes"][ident]
        out.append(_Change(CAT_ROOT_CAUSE, "root_cause", ident, CHANGE_ADDED,
                           candidate_value=f"{rc.severity} {rc.category}", confidence=rc.confidence,
                           security_relevant=True, provenance="STATIC_RULE",
                           evidence={"category": rc.category, "severity": rc.severity}))
    for ident in sorted(set(ia["root_causes"]) & set(ib["root_causes"])):
        ra, rb = ia["root_causes"][ident], ib["root_causes"][ident]
        if (ra.severity, ra.confidence, len(ra.findings)) != (rb.severity, rb.confidence, len(rb.findings)):
            out.append(_Change(CAT_ROOT_CAUSE, "root_cause", ident, CHANGE_CHANGED,
                               baseline_value=f"{ra.severity}/{ra.confidence}",
                               candidate_value=f"{rb.severity}/{rb.confidence}", confidence="MEDIUM",
                               provenance="STATIC_RULE",
                               evidence={"severity": [ra.severity, rb.severity],
                                         "findings": [len(ra.findings), len(rb.findings)]}))
    return out


def _diff_attack_surface(ia, ib) -> list[_Change]:
    out: list[_Change] = []
    rem, add = _set_diff(set(ia["as_nodes"]), set(ib["as_nodes"]))
    for k in sorted(rem):
        n = ia["as_nodes"][k]
        out.append(_Change(CAT_ATTACK_SURFACE, "as_node", k, CHANGE_REMOVED,
                           baseline_value=f"{n.exposure} risk={n.risk_score}",
                           confidence="HIGH" if n.node_type == "component" else "MEDIUM",
                           security_relevant=(n.exposure == "PUBLIC"), provenance="STATIC_RULE",
                           evidence={"exposure": n.exposure, "risk_score": n.risk_score, "node_type": n.node_type}))
    for k in sorted(add):
        n = ib["as_nodes"][k]
        out.append(_Change(CAT_ATTACK_SURFACE, "as_node", k, CHANGE_ADDED,
                           candidate_value=f"{n.exposure} risk={n.risk_score}",
                           confidence="HIGH" if n.node_type == "component" else "MEDIUM",
                           security_relevant=(n.exposure == "PUBLIC"), provenance="STATIC_RULE",
                           evidence={"exposure": n.exposure, "risk_score": n.risk_score, "node_type": n.node_type}))
    for k in sorted(set(ia["as_nodes"]) & set(ib["as_nodes"])):
        na, nb = ia["as_nodes"][k], ib["as_nodes"][k]
        if na.exposure != nb.exposure or na.risk_score != nb.risk_score:
            out.append(_Change(CAT_ATTACK_SURFACE, "as_node", k, CHANGE_CHANGED,
                               baseline_value=f"{na.exposure} risk={na.risk_score}",
                               candidate_value=f"{nb.exposure} risk={nb.risk_score}",
                               confidence="MEDIUM",
                               security_relevant=("PUBLIC" in (na.exposure, nb.exposure)),
                               provenance="STATIC_RULE",
                               evidence={"exposure": [na.exposure, nb.exposure],
                                         "risk_score": [na.risk_score, nb.risk_score]}))
    rem, add = _set_diff(ia["as_edges"], ib["as_edges"])
    for k in sorted(rem, key=str):
        out.append(_Change(CAT_ATTACK_SURFACE, "as_edge", str(k), CHANGE_REMOVED, confidence="MEDIUM",
                           provenance="STATIC_RULE", evidence={"edge": list(k)}))
    for k in sorted(add, key=str):
        out.append(_Change(CAT_ATTACK_SURFACE, "as_edge", str(k), CHANGE_ADDED, confidence="MEDIUM",
                           provenance="STATIC_RULE", evidence={"edge": list(k)}))
    return out


def _diff_runtime(ia, ib) -> list[_Change]:
    out: list[_Change] = []
    rem, add = _set_diff(ia["observations"], ib["observations"])
    for k in sorted(rem, key=str):
        out.append(_Change(CAT_RUNTIME, "observation", str(k), CHANGE_REMOVED, confidence="MEDIUM",
                           provenance="RUNTIME", evidence={"observation": list(k)}))
    for k in sorted(add, key=str):
        out.append(_Change(CAT_RUNTIME, "observation", str(k), CHANGE_ADDED, confidence="MEDIUM",
                           provenance="RUNTIME", evidence={"observation": list(k)}))
    return out


def _diff_obfuscation(baseline, candidate) -> list[_Change]:
    """Obfuscation diff by stable content-derived fingerprints (no line numbers /
    ids / timestamps). Increased obfuscation is never a SECURITY_REGRESSION on its
    own — obfuscation changes are marked not-security-relevant here."""
    from app.analysis.obfuscation import obfuscation_view
    va, vb = obfuscation_view(baseline), obfuscation_view(candidate)
    out: list[_Change] = []
    for key, etype in (("observations", "obf_observation"), ("anti_analysis", "anti_analysis"),
                       ("analysis_impacts", "analysis_impact")):
        a_idx = {x["fingerprint"]: x for x in va[key]}
        b_idx = {x["fingerprint"]: x for x in vb[key]}
        for fp in sorted(set(a_idx) - set(b_idx)):
            transition = "REMOVED_ANTI_ANALYSIS_INDICATOR" if etype == "anti_analysis" else "OBFUSCATION_DECREASED"
            out.append(_Change(CAT_OBFUSCATION, etype, fp, CHANGE_REMOVED, confidence="MEDIUM",
                               provenance="OBFUSCATION", security_relevant=False,
                               evidence={"transition": transition,
                                         "detail": a_idx[fp].get("indicator") or a_idx[fp].get("impact_category")}))
        for fp in sorted(set(b_idx) - set(a_idx)):
            transition = ("NEW_ANTI_ANALYSIS_INDICATOR" if etype == "anti_analysis"
                          else "ANALYSIS_IMPACT_CHANGED" if etype == "analysis_impact" else "OBFUSCATION_INCREASED")
            out.append(_Change(CAT_OBFUSCATION, etype, fp, CHANGE_ADDED, confidence="MEDIUM",
                               provenance="OBFUSCATION", security_relevant=False,
                               evidence={"transition": transition,
                                         "detail": b_idx[fp].get("indicator") or b_idx[fp].get("impact_category")}))
    # score transition
    delta = vb["score"]["score"] - va["score"]["score"]
    if delta != 0:
        out.append(_Change(CAT_OBFUSCATION, "score", "obfuscation_score", CHANGE_CHANGED,
                           baseline_value=str(va["score"]["score"]), candidate_value=str(vb["score"]["score"]),
                           confidence="MEDIUM", provenance="OBFUSCATION", security_relevant=False,
                           evidence={"transition": "OBFUSCATION_INCREASED" if delta > 0 else "OBFUSCATION_DECREASED",
                                     "delta": delta}))
    return out


def _diff_runtime_validation(baseline, candidate) -> list[_Change]:
    """Live runtime-behavior diff (prompt 21). Only compares when BOTH analyses
    carry LIVE runtime evidence; otherwise records RUNTIME_OBSERVATION_UNAVAILABLE.
    Removed behavior is NO_LONGER_OBSERVED (never FIXED); only a newly-observed
    reaching/invocation is security-relevant. Conservative by construction."""
    if not baseline.runtime_validation_runs and not candidate.runtime_validation_runs:
        return []
    from app.analysis.runtime_validation import runtime_validation_from_diff

    class _Cmp:  # lightweight adapter so we can reuse the engine's diff
        pass
    cmp = _Cmp(); cmp.baseline = baseline; cmp.candidate = candidate
    result = runtime_validation_from_diff(cmp)
    out: list[_Change] = []
    if result["status"] == "RUNTIME_OBSERVATION_UNAVAILABLE":
        out.append(_Change(CAT_RUNTIME, "runtime_behavior", "runtime_observation", CHANGE_CHANGED,
                           confidence="LOW", provenance="RUNTIME", security_relevant=False,
                           evidence={"transition": "RUNTIME_OBSERVATION_UNAVAILABLE",
                                     "baseline_mode": result["baseline_mode"],
                                     "candidate_mode": result["candidate_mode"]}))
        return out
    for ch in result["changes"]:
        change_type = CHANGE_REMOVED if ch["category"] == "RUNTIME_BEHAVIOR_REMOVED" else CHANGE_ADDED
        out.append(_Change(CAT_RUNTIME, "runtime_behavior", ch["detail"][:200], change_type,
                           confidence="MEDIUM", provenance="RUNTIME_FRIDA",
                           security_relevant=ch["security_relevant"],
                           evidence={"transition": ch["transition"], "detail": ch["detail"]}))
    return out


def _diff_native_deep(baseline, candidate) -> list[_Change]:
    """Deep-native diff by stable content-derived fingerprints (prompt 20). Address
    changes are metadata, not removal. Only a NEW reachable native API path
    (NATIVE_CALL_CHAIN_REACHES_API) is treated as security-relevant; a native
    function/symbol/binary appearing is not, and UNKNOWN_NATIVE_TARGET is preserved.
    Never asserts exploitability."""
    if not baseline.native_analysis_runs and not candidate.native_analysis_runs:
        return []
    from app.native.deep_native import native_deep_view, API_REACHED
    va, vb = native_deep_view(baseline), native_deep_view(candidate)
    out: list[_Change] = []

    for key, etype in (("binaries", "native_binary"), ("functions", "native_function"),
                       ("jni_bindings", "native_jni"), ("api_observations", "native_api")):
        a_idx = {x.get("fingerprint") or x.get("id"): x for x in va[key]}
        b_idx = {x.get("fingerprint") or x.get("id"): x for x in vb[key]}
        for fp in sorted(set(a_idx) - set(b_idx)):
            out.append(_Change(CAT_NATIVE_DEEP, etype, fp, CHANGE_REMOVED, confidence="MEDIUM",
                               provenance="GHIDRA", security_relevant=False,
                               evidence={"transition": "NO_LONGER_DETECTED",
                                         "detail": _native_change_detail(a_idx[fp])}))
        for fp in sorted(set(b_idx) - set(a_idx)):
            row = b_idx[fp]
            # Security-relevant ONLY for a newly reachable native API path.
            is_new_reachable = etype == "native_api" and row.get("state") == API_REACHED
            out.append(_Change(CAT_NATIVE_DEEP, etype, fp, CHANGE_ADDED, confidence="MEDIUM",
                               provenance="GHIDRA", security_relevant=is_new_reachable,
                               evidence={"transition": "NEW_REACHABLE_NATIVE_API_PATH" if is_new_reachable
                                         else "NATIVE_EVIDENCE_ADDED", "detail": _native_change_detail(row)}))
    return out


def _native_change_detail(row: dict) -> str:
    if "api" in row:
        return f"{row['api']} [{row.get('state')}]"
    if "java_method" in row:
        return f"{row.get('java_class')}.{row.get('java_method')} [{row.get('state')}]"
    if "name" in row:
        return f"{row['name']} ({row.get('function_type', '')})"
    return row.get("filename") or row.get("fingerprint") or "native"


# ---------------------------------------------------------------------------
# Finding diff (fingerprint + semantic relink)
# ---------------------------------------------------------------------------


def _finding_semantic_key(f) -> tuple:
    return (f.rule_id, f.component or f.primary_target or "")


def _finding_snapshot(f, rc_map) -> dict:
    return {"rule_id": f.rule_id, "severity": f.severity, "confidence": f.confidence, "status": f.status,
            "component": f.component, "fingerprint": f.fingerprint, "runtime_status": f.runtime_status,
            "validation_state": f.validation_state,
            "root_cause": rc_map.get(f.root_cause_id) if f.root_cause_id else None,
            "evidence": sorted(f"{e.source}:{e.location}" for e in f.evidence)}


def _diff_findings(ia, ib) -> tuple[list[dict], list[_Change]]:
    rca, rcb = ia["rc_by_id"], ib["rc_by_id"]
    fa = {f.fingerprint or _finding_semantic_key(f): f for f in ia["findings"]}
    fb = {f.fingerprint or _finding_semantic_key(f): f for f in ib["findings"]}
    matched_a, matched_b = set(), set()
    finding_rows: list[dict] = []

    # 1) exact fingerprint matches -> UNCHANGED or CHANGED
    for fp in set(fa) & set(fb):
        a, b = fa[fp], fb[fp]
        dims = _changed_dimensions(a, b, rca, rcb)
        matched_a.add(fp); matched_b.add(fp)
        if dims:
            finding_rows.append(_finding_row(CHANGE_CHANGED, a, b, dims, rca, rcb))
    unchanged = len((set(fa) & set(fb))) - sum(1 for r in finding_rows if r["change_type"] == CHANGE_CHANGED)

    # 2) semantic relink of leftovers (one removed + one added in same (rule,component)) -> CHANGED
    left_a = {fp: f for fp, f in fa.items() if fp not in matched_a}
    left_b = {fp: f for fp, f in fb.items() if fp not in matched_b}
    from collections import defaultdict
    groups_a, groups_b = defaultdict(list), defaultdict(list)
    for fp, f in left_a.items():
        groups_a[_finding_semantic_key(f)].append((fp, f))
    for fp, f in left_b.items():
        groups_b[_finding_semantic_key(f)].append((fp, f))
    for key in set(groups_a) & set(groups_b):
        if len(groups_a[key]) == 1 and len(groups_b[key]) == 1:
            (fpa, a), (fpb, b) = groups_a[key][0], groups_b[key][0]
            matched_a.add(fpa); matched_b.add(fpb)
            dims = _changed_dimensions(a, b, rca, rcb) or ["target/evidence"]
            finding_rows.append(_finding_row(CHANGE_CHANGED, a, b, dims, rca, rcb))

    # 3) leftovers -> REMOVED (NO_LONGER_DETECTED) / ADDED
    for fp, f in fa.items():
        if fp not in matched_a:
            finding_rows.append(_finding_row(CHANGE_REMOVED, f, None, [], rca, rcb))
    for fp, f in fb.items():
        if fp not in matched_b:
            finding_rows.append(_finding_row(CHANGE_ADDED, None, f, [], rca, rcb))

    finding_rows_sorted = sorted(finding_rows, key=lambda r: (r["change_type"], r["rule_id"], r.get("component") or ""))
    changes = [_finding_to_change(r) for r in finding_rows_sorted]
    for r in finding_rows_sorted:
        r["_unchanged_total"] = unchanged
    return finding_rows_sorted, changes


def _changed_dimensions(a, b, rca, rcb) -> list[str]:
    dims = []
    for attr in ("severity", "confidence", "status", "runtime_status", "validation_state", "component"):
        if getattr(a, attr) != getattr(b, attr):
            dims.append(attr)
    # Compare by the root cause's stable identifier, never its per-analysis UUID.
    if rca.get(a.root_cause_id) != rcb.get(b.root_cause_id):
        dims.append("root_cause")
    ea = sorted(f"{e.source}:{e.location}:{e.detail}" for e in a.evidence)
    eb = sorted(f"{e.source}:{e.location}:{e.detail}" for e in b.evidence)
    if ea != eb:
        dims.append("evidence")
    return dims


def _finding_row(change_type, a, b, dims, rca, rcb) -> dict:
    src = b or a
    return {"change_type": change_type, "rule_id": src.rule_id,
            "component": src.component,
            "baseline_fingerprint": a.fingerprint if a else None,
            "candidate_fingerprint": b.fingerprint if b else None,
            "changed_dimensions": list(dims),
            "confidence": (src.confidence or "medium").upper(),
            "security_relevant": _finding_security_relevant(change_type, a, b),
            "baseline_value": _finding_snapshot(a, rca) if a else {},
            "candidate_value": _finding_snapshot(b, rcb) if b else {},
            "disposition": "NO_LONGER_DETECTED" if change_type == CHANGE_REMOVED else None}


def _finding_security_relevant(change_type, a, b) -> bool:
    f = b or a
    if change_type == CHANGE_ADDED:
        return f.status == "CONFIRMED_BY_STATIC_ANALYSIS" or f.category in ("reachability", "cve", "native")
    if change_type == CHANGE_REMOVED:
        return f.status == "CONFIRMED_BY_STATIC_ANALYSIS"
    return True  # CHANGED


def _finding_to_change(r) -> _Change:
    ident = f"{r['rule_id']}@{r.get('component') or ''}"
    ev = {"changed_dimensions": r["changed_dimensions"]}
    if r["change_type"] == CHANGE_REMOVED:
        ev["disposition"] = "NO_LONGER_DETECTED"
    return _Change(CAT_FINDING := "finding", "finding", ident, r["change_type"],
                   baseline_value=str(r["baseline_value"].get("status")) if r["baseline_value"] else None,
                   candidate_value=str(r["candidate_value"].get("status")) if r["candidate_value"] else None,
                   confidence=r["confidence"], security_relevant=r["security_relevant"],
                   provenance="STATIC", evidence=ev)


CAT_FINDING = "finding"


# ---------------------------------------------------------------------------
# Risk delta
# ---------------------------------------------------------------------------


def _overall_risk(analysis):
    return next((r for r in analysis.risk_assessments if r.scope == "overall"), None)


def _risk_delta(baseline, candidate) -> dict:
    ra, rb = _overall_risk(baseline), _overall_risk(candidate)
    a_score = ra.overall_score if ra else 0
    b_score = rb.overall_score if rb else 0
    a_sev = ra.severity if ra else "info"
    b_sev = rb.severity if rb else "info"
    a_conf = ra.confidence if ra else "UNKNOWN"
    b_conf = rb.confidence if rb else "UNKNOWN"
    fa = {f.name for f in (ra.factors if ra else []) if f.direction == "positive"}
    fb = {f.name for f in (rb.factors if rb else []) if f.direction == "positive"}
    return {"baseline_score": a_score, "candidate_score": b_score, "delta": b_score - a_score,
            "baseline_severity": a_sev, "candidate_severity": b_sev,
            "severity_transition": f"{a_sev} → {b_sev}" if a_sev != b_sev else a_sev,
            "baseline_confidence": a_conf, "candidate_confidence": b_conf,
            "confidence_transition": f"{a_conf} → {b_conf}" if a_conf != b_conf else a_conf,
            "factor_changes": {"added": sorted(fb - fa), "removed": sorted(fa - fb)}}


# ---------------------------------------------------------------------------
# Security-impact classification (conservative)
# ---------------------------------------------------------------------------


def _classify_security_impact(changes: list[_Change], finding_rows: list[dict], risk: dict) -> dict:
    regressions: list[dict] = []
    improvements: list[dict] = []
    ambiguous: list[dict] = []

    def sig(bucket, desc, confidence, evidence):
        bucket.append({"description": desc, "confidence": confidence, "evidence": evidence})

    for c in changes:
        # --- regression signals (positive security evidence required) ---
        if c.category == CAT_ATTACK_SURFACE and c.entity_type == "as_node" and c.change_type == CHANGE_ADDED \
                and c.evidence.get("exposure") == "PUBLIC":
            sig(regressions, f"new PUBLIC attack-surface node {c.identity}", c.confidence, c.identity)
        if c.category == CAT_MANIFEST and c.entity_type == "component" and c.change_type == CHANGE_CHANGED:
            ch = c.evidence.get("changed", {})
            exp = ch.get("effective_exported") or ch.get("exposure")
            if ch.get("effective_exported") == [False, True]:
                sig(regressions, f"component {c.identity} became exported", "HIGH", c.identity)
            elif ch.get("effective_exported") == [True, False]:
                sig(improvements, f"component {c.identity} no longer exported", "HIGH", c.identity)
            elif exp and ("UNKNOWN" in exp):
                sig(ambiguous, f"component {c.identity} exposure involves UNKNOWN", "LOW", c.identity)
        if c.category == CAT_REACHABILITY and c.change_type == CHANGE_ADDED and c.evidence.get("status") == "REACHABLE":
            sig(regressions, f"new reachable path {c.evidence.get('from')} → {c.evidence.get('to')}", c.confidence, c.identity)
        if c.category == CAT_REACHABILITY and c.change_type == CHANGE_REMOVED and c.evidence.get("status") == "REACHABLE":
            sig(ambiguous, f"reachable path no longer detected {c.identity}", "LOW", c.identity)
        if c.category == CAT_CVE:
            base = (c.evidence.get("baseline") or {}) if c.change_type == CHANGE_CHANGED else {}
            cand = (c.evidence.get("candidate") or c.evidence) if c.change_type != CHANGE_REMOVED else {}
            cand_corr = cand.get("correlation_state")
            base_corr = base.get("correlation_state")
            if c.change_type == CHANGE_ADDED and cand.get("correlation_state") == "AFFECTED_REACHABLE":
                sig(regressions, f"new reachable AFFECTED CVE {c.identity}", c.confidence, c.identity)
            elif cand_corr == "AFFECTED_REACHABLE" and base_corr != "AFFECTED_REACHABLE":
                sig(regressions, f"CVE became reachable-and-affected {c.identity}", c.confidence, c.identity)
            elif base_corr == "AFFECTED_REACHABLE" and cand_corr and cand_corr != "AFFECTED_REACHABLE":
                sig(improvements, f"CVE no longer reachable-and-affected {c.identity}", "MEDIUM", c.identity)
            elif "POSSIBLY_AFFECTED" in (c.candidate_value or "") or "POSSIBLY_AFFECTED" in (c.baseline_value or ""):
                sig(ambiguous, f"CVE POSSIBLY_AFFECTED transition {c.identity} (version uncertain)", "LOW", c.identity)
        if c.category == CAT_MANIFEST and c.entity_type == "permission" and c.change_type == CHANGE_ADDED \
                and c.evidence.get("dangerous"):
            sig(ambiguous, f"dangerous permission added {c.identity}", "MEDIUM", c.identity)
        if c.category == CAT_MANIFEST and c.entity_type == "permission" and c.change_type == CHANGE_REMOVED \
                and c.evidence.get("dangerous"):
            sig(improvements, f"dangerous permission removed {c.identity}", "MEDIUM", c.identity)

    for r in finding_rows:
        if r["change_type"] == CHANGE_ADDED and (r["candidate_value"].get("status") == "CONFIRMED_BY_STATIC_ANALYSIS"):
            sig(regressions, f"new confirmed static finding {r['rule_id']}", "HIGH", r["rule_id"])
        elif r["change_type"] == CHANGE_ADDED and r["security_relevant"]:
            sig(ambiguous, f"new (potential) finding {r['rule_id']} — not auto-classified exploitable", "LOW", r["rule_id"])
        elif r["change_type"] == CHANGE_REMOVED and (r["baseline_value"].get("status") == "CONFIRMED_BY_STATIC_ANALYSIS"):
            # NO_LONGER_DETECTED, not FIXED, unless component also removed.
            sig(ambiguous, f"confirmed finding {r['rule_id']} NO_LONGER_DETECTED (not proven fixed)", "LOW", r["rule_id"])

    # Risk score movement is a supporting signal only (per the configured model).
    if risk["delta"] > 0 and risk["factor_changes"]["added"]:
        sig(regressions, f"risk score increased {risk['baseline_score']}→{risk['candidate_score']} "
            f"(configured scoring model)", "MEDIUM", "risk")
    elif risk["delta"] < 0 and risk["factor_changes"]["removed"]:
        sig(improvements, f"risk score decreased {risk['baseline_score']}→{risk['candidate_score']} "
            f"(configured scoring model)", "MEDIUM", "risk")

    total_changes = len(changes) + len(finding_rows)
    if regressions and improvements:
        verdict = IMPACT_MIXED
    elif regressions:
        verdict = IMPACT_REGRESSION
    elif improvements:
        verdict = IMPACT_IMPROVEMENT
    elif ambiguous:
        verdict = IMPACT_INCONCLUSIVE
    else:
        verdict = IMPACT_NONE

    deciding = regressions + improvements if verdict in (IMPACT_REGRESSION, IMPACT_IMPROVEMENT, IMPACT_MIXED) \
        else (ambiguous if verdict == IMPACT_INCONCLUSIVE else [])
    confidence = "UNKNOWN"
    if deciding:
        confidence = max((s["confidence"] for s in deciding), key=lambda c: _CONF_RANK.get(c, -1))
    elif verdict == IMPACT_NONE:
        confidence = "HIGH" if total_changes == 0 else "MEDIUM"

    return {"verdict": verdict, "confidence": confidence,
            "regression_signals": regressions, "improvement_signals": improvements,
            "ambiguous_signals": ambiguous}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def compare_analyses(db, baseline, candidate, requested_by: str = "cli") -> AnalysisComparison:
    """Compare baseline (A) → candidate (B). Returns a persisted (flushed)
    AnalysisComparison; the caller commits. Neither analysis is mutated."""
    started = time.monotonic()
    snap_a, snap_b = _latest_snapshot(baseline), _latest_snapshot(candidate)
    fp = comparison_fingerprint(baseline, candidate, snap_a.digest if snap_a else None,
                                snap_b.digest if snap_b else None)
    comparison = AnalysisComparison(
        baseline_analysis_id=baseline.id, candidate_analysis_id=candidate.id,
        snapshot_a_id=snap_a.id if snap_a else None, snapshot_b_id=snap_b.id if snap_b else None,
        fingerprint=fp, requested_by=requested_by, created_at=_now())
    db.add(comparison)

    # Snapshot integrity — refuse to compare a corrupted/stale snapshot.
    for side, analysis, snap in (("baseline", baseline, snap_a), ("candidate", candidate, snap_b)):
        if snap is not None:
            ok, err = _verify_snapshot(analysis, snap)
            if not ok:
                comparison.status = STATUS_FAILED
                comparison.error = f"{side}: {err}"
                comparison.completed_at = _now()
                db.flush()
                return comparison

    if snap_a and snap_b:
        comparison.snapshot_mode = MODE_SNAPSHOT
    elif snap_a or snap_b:
        comparison.snapshot_mode = MODE_MIXED
    else:
        comparison.snapshot_mode = MODE_RECONSTRUCTED

    ia, ib = _index(baseline), _index(candidate)
    bound = settings.diff_max_changes_per_category

    changes: list[_Change] = []
    changes += _diff_manifest(ia, ib)
    changes += _diff_semantics(ia, ib)
    changes += _diff_code(ia, ib)
    changes += _diff_native(ia, ib)
    changes += _diff_dependencies(ia, ib)
    changes += _diff_cve(ia, ib)
    changes += _diff_root_causes(ia, ib)
    changes += _diff_attack_surface(ia, ib)
    changes += _diff_reachability(ia, ib)
    changes += _diff_runtime(ia, ib)
    changes += _diff_obfuscation(baseline, candidate)
    changes += _diff_native_deep(baseline, candidate)
    changes += _diff_runtime_validation(baseline, candidate)

    finding_rows, finding_changes = _diff_findings(ia, ib)
    unchanged_findings = finding_rows[0]["_unchanged_total"] if finding_rows else \
        len(set(f.fingerprint for f in ia["findings"]) & set(f.fingerprint for f in ib["findings"]))

    risk = _risk_delta(baseline, candidate)
    impact = _classify_security_impact(changes + finding_changes, finding_rows, risk)

    # --- persist changes (bounded per category) ---
    per_cat_count: dict[str, int] = {}
    truncated: dict[str, int] = {}
    all_changes = changes + finding_changes
    for c in all_changes:
        n = per_cat_count.get(c.category, 0)
        if n >= bound:
            truncated[c.category] = truncated.get(c.category, 0) + 1
            continue
        per_cat_count[c.category] = n + 1
        comparison.changes.append(ComparisonChange(
            category=c.category, entity_type=c.entity_type, entity_identity=c.identity[:1024],
            change_type=c.change_type, baseline_value=c.baseline_value, candidate_value=c.candidate_value,
            confidence=c.confidence, security_relevant=c.security_relevant, provenance=c.provenance,
            evidence=c.evidence))

    # --- persist finding-change detail rows ---
    for r in finding_rows:
        comparison.finding_changes.append(ComparisonFinding(
            change_type=r["change_type"], rule_id=r["rule_id"],
            baseline_fingerprint=r["baseline_fingerprint"], candidate_fingerprint=r["candidate_fingerprint"],
            component=r["component"], changed_dimensions=r["changed_dimensions"], confidence=r["confidence"],
            security_relevant=r["security_relevant"], baseline_value=r["baseline_value"],
            candidate_value=r["candidate_value"]))

    # --- risk delta ---
    comparison.risk_delta = ComparisonRiskDelta(
        baseline_score=risk["baseline_score"], candidate_score=risk["candidate_score"], delta=risk["delta"],
        baseline_severity=risk["baseline_severity"], candidate_severity=risk["candidate_severity"],
        severity_transition=risk["severity_transition"], baseline_confidence=risk["baseline_confidence"],
        candidate_confidence=risk["candidate_confidence"], confidence_transition=risk["confidence_transition"],
        factor_changes=risk["factor_changes"])

    # --- per-category summaries (counts incl. unchanged where meaningful) ---
    _build_summaries(comparison, all_changes, finding_rows, unchanged_findings)

    comparison.security_impact = impact["verdict"]
    comparison.impact_confidence = impact["confidence"]
    comparison.status = STATUS_PARTIAL if truncated else STATUS_COMPLETE
    comparison.completed_at = _now()
    comparison.summary = {
        "total_changes": len(all_changes),
        "security_relevant_changes": sum(1 for c in all_changes if c.security_relevant),
        "by_category": per_cat_count,
        "truncated": truncated,
        "finding_delta": {"added": sum(1 for r in finding_rows if r["change_type"] == CHANGE_ADDED),
                          "removed": sum(1 for r in finding_rows if r["change_type"] == CHANGE_REMOVED),
                          "changed": sum(1 for r in finding_rows if r["change_type"] == CHANGE_CHANGED),
                          "unchanged": unchanged_findings},
        "risk": risk,
        "security_impact": impact,
        "snapshot_mode": comparison.snapshot_mode,
        "direction": {"baseline": str(baseline.id), "candidate": str(candidate.id)},
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    db.flush()
    return comparison


def _build_summaries(comparison, all_changes, finding_rows, unchanged_findings) -> None:
    from collections import defaultdict
    counts: dict[str, dict] = defaultdict(lambda: {"added": 0, "removed": 0, "changed": 0, "unchanged": 0, "sec": 0})
    for c in all_changes:
        bucket = counts[c.category]
        bucket[{"ADDED": "added", "REMOVED": "removed", "CHANGED": "changed"}.get(c.change_type, "changed")] += 1
        if c.security_relevant:
            bucket["sec"] += 1
    if CAT_FINDING in counts:
        counts[CAT_FINDING]["unchanged"] = unchanged_findings
    for category, b in sorted(counts.items()):
        comparison.category_summaries.append(ComparisonSummary(
            category=category, added=b["added"], removed=b["removed"], changed=b["changed"],
            unchanged=b["unchanged"], security_relevant=b["sec"]))

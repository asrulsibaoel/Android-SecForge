"""Knowledge-graph projection over the EXISTING canonical model (prompt 14).

This does NOT introduce a second graph. The canonical graph remains
``code_nodes`` / ``code_edges`` (plus semantic + reachability edges). Here we
*project* the already-persisted database entities — APK, manifest, permissions,
components, entry points, code, native/JNI, dependencies, CVE matches, findings,
evidence, root causes, attack surface, security boundaries, runtime
devices/sessions/observations — into a single unified, read-only node/edge view.

Every projected node and edge carries provenance tracing it back to the evidence
that produced it, and every edge has a deterministic fingerprint so the same
persisted analysis always projects to the same identities (and the same snapshot
hash). We never invent an edge from name similarity, never upgrade confidence,
and never collapse UNKNOWN/POSSIBLY_AFFECTED/NOT_REACHABLE states.

Performance: the projection is bounded (max nodes/edges) and built with an
adjacency index; code-method nodes referenced by findings/paths/entry points are
always kept so evidence chains stay traversable even under truncation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from app.core.config import settings

GRAPH_VERSION = "kg/1"

# --- canonical node categories --------------------------------------------
N_APK = "APK"
N_MANIFEST = "MANIFEST"
N_PERMISSION = "PERMISSION"
N_COMPONENT = "COMPONENT"
N_ANDROID_ENTRY_POINT = "ANDROID_ENTRY_POINT"
N_CODE_CLASS = "CODE_CLASS"
N_CODE_METHOD = "CODE_METHOD"
N_CODE_FIELD = "CODE_FIELD"
N_NATIVE_LIBRARY = "NATIVE_LIBRARY"
N_NATIVE_FUNCTION = "NATIVE_FUNCTION"
N_JNI_BINDING = "JNI_BINDING"
N_DEPENDENCY = "DEPENDENCY"
N_CVE = "CVE"
N_FINDING = "FINDING"
N_EVIDENCE = "EVIDENCE"
N_ROOT_CAUSE = "ROOT_CAUSE"
N_ATTACK_SURFACE_NODE = "ATTACK_SURFACE_NODE"
N_SECURITY_BOUNDARY = "SECURITY_BOUNDARY"
N_RUNTIME_DEVICE = "RUNTIME_DEVICE"
N_RUNTIME_SESSION = "RUNTIME_SESSION"
N_RUNTIME_PROCESS = "RUNTIME_PROCESS"
N_RUNTIME_OBSERVATION = "RUNTIME_OBSERVATION"
N_RUNTIME_CORRELATION = "RUNTIME_CORRELATION"  # opt-in runtime-validation projection (prompt 21)
# Projected wrappers for canonical code-graph node types that are not classes/
# methods/fields (sources, sinks, entry stubs, framework, boundary stubs).
N_SOURCE = "SOURCE"
N_SINK = "SECURITY_SINK"
# Vulnerability-intelligence projected nodes (prompt 16).
N_CVE_ALIAS = "CVE_ALIAS"
N_CVE_IDENTITY = "CVE_IDENTITY"
N_CVE_SIGNATURE = "CVE_SIGNATURE"
N_REFERENCE = "REFERENCE"
N_REMEDIATION_ITEM = "REMEDIATION_ITEM"
N_VALIDATION_CLAIM = "VALIDATION_CLAIM"
N_VALIDATION_BLOCKER = "VALIDATION_BLOCKER"
N_VALIDATION_EVIDENCE = "VALIDATION_EVIDENCE"
N_OBFUSCATION_OBSERVATION = "OBFUSCATION_OBSERVATION"
N_ANTI_ANALYSIS_INDICATOR = "ANTI_ANALYSIS_INDICATOR"
N_ANALYSIS_IMPACT = "ANALYSIS_IMPACT"
# Deep native / Ghidra projected nodes (prompt 20).
N_NATIVE_ANALYSIS = "NATIVE_ANALYSIS"
N_NATIVE_BINARY = "NATIVE_BINARY"
N_NATIVE_DEEP_FUNCTION = "NATIVE_FUNCTION_DEEP"
N_NATIVE_API = "NATIVE_API"
N_NATIVE_DEEP_JNI = "JNI_BINDING_DEEP"

# --- canonical edge types --------------------------------------------------
E_CONTAINS = "CONTAINS"
E_DECLARES = "DECLARES"
E_REQUESTS = "REQUESTS"
E_EXPORTS = "EXPORTS"
E_DISPATCHES_TO = "DISPATCHES_TO"
E_CALLS = "CALLS"
E_FLOWS_TO = "FLOWS_TO"
E_BINDS_TO = "BINDS_TO"
E_DEPENDS_ON = "DEPENDS_ON"
E_MATCHES_CVE = "MATCHES_CVE"
E_SUPPORTS = "SUPPORTS"
E_CAUSED_BY = "CAUSED_BY"
E_EVIDENCE_FOR = "EVIDENCE_FOR"
E_EXPOSES = "EXPOSES"
E_REACHES = "REACHES"
E_LEADS_TO = "LEADS_TO"
E_CROSSES = "CROSSES"
E_OBSERVED_AT = "OBSERVED_AT"
E_OBSERVED_ON = "OBSERVED_ON"
E_CORROBORATES = "CORROBORATES"
E_CORRELATES_WITH = "CORRELATES_WITH"
E_ROOT_CAUSE_OF = "ROOT_CAUSE_OF"
E_AFFECTS = "AFFECTS"
E_RELATED_TO = "RELATED_TO"
E_HAS_ALIAS = "HAS_ALIAS"
E_HAS_IDENTITY = "HAS_IDENTITY"
E_HAS_SIGNATURE = "HAS_SIGNATURE"
E_HAS_REFERENCE = "HAS_REFERENCE"
E_SIGNATURE_OF = "SIGNATURE_OF"
# Remediation projection edges (prompt 17).
E_REMEDIATES = "REMEDIATES"
E_ADDRESSES = "ADDRESSES"
E_SUPPORTED_BY = "SUPPORTED_BY"
E_BLOCKED_BY = "BLOCKED_BY"
E_TARGETS = "TARGETS"
P_REMEDIATION = "REMEDIATION"
# Validation projection edges (prompt 18).
E_VALIDATES = "VALIDATES"
E_CORROBORATES = "CORROBORATES"
E_REQUIRES_EVIDENCE = "REQUIRES_EVIDENCE"
P_VALIDATION = "VALIDATION"
# Obfuscation projection edges (prompt 19).
E_INDICATES_OBFUSCATION = "INDICATES_OBFUSCATION"
E_INDICATES_ANTI_ANALYSIS = "INDICATES_ANTI_ANALYSIS"
E_AFFECTS_ANALYSIS = "AFFECTS_ANALYSIS"
E_OBSCURES = "OBSCURES"
P_OBFUSCATION = "OBFUSCATION"
# Deep native / Ghidra projection edges (prompt 20).
E_ANALYZED_BY = "ANALYZED_BY"
E_NATIVE_CALLS = "NATIVE_CALLS"
E_REACHES_NATIVE_API = "REACHES_NATIVE_API"
E_IMPORTS = "IMPORTS"
P_GHIDRA = "GHIDRA"
# Live runtime-validation projection edges (prompt 21; opt-in). LIVE marker + a
# RUNTIME_ADB / RUNTIME_FRIDA provenance on every edge.
E_RUNTIME_CONFIRMS = "RUNTIME_CONFIRMS"
E_RUNTIME_CORROBORATES = "RUNTIME_CORROBORATES"
E_RUNTIME_REACHES = "RUNTIME_REACHES"
E_RUNTIME_INVOCATION = "RUNTIME_INVOCATION"

# Provenance source types.
P_MANIFEST = "MANIFEST"
P_DEX = "DEX"
P_JADX = "JADX"
P_SMALI = "SMALI"
P_ELF = "ELF"
P_JNI = "JNI"
P_GHIDRA = "GHIDRA"
P_STATIC_RULE = "STATIC_RULE"
P_REACHABILITY = "REACHABILITY"
P_SEMANTICS = "SEMANTICS"
P_CVE_DATABASE = "CVE_DATABASE"
P_RUNTIME_ADB = "RUNTIME_ADB"
P_RUNTIME_FRIDA = "RUNTIME_FRIDA"
P_USER_NOTE = "USER_NOTE"

# Map canonical code-graph node_type -> projected KG node type.
_CODE_NODE_TYPE = {
    "JAVA_METHOD": N_CODE_METHOD,
    "COMPONENT": N_COMPONENT,
    "NATIVE_LIBRARY": N_NATIVE_LIBRARY,
    "NATIVE_FUNCTION": N_NATIVE_FUNCTION,
    "JNI_BINDING": N_JNI_BINDING,
    "SECURITY_SINK": N_SINK,
    "SOURCE": N_SOURCE,
    "ENTRY_POINT": N_ANDROID_ENTRY_POINT,
    "ANDROID_FRAMEWORK": "ANDROID_FRAMEWORK",
    "SECURITY_BOUNDARY": N_SECURITY_BOUNDARY,
    "RUNTIME_OBSERVATION": N_RUNTIME_OBSERVATION,
}

# Map canonical code/semantic edge_type -> provenance source.
_EDGE_PROVENANCE = {
    "CALLS": P_JADX, "INVOKES": P_JADX, "DECLARES": P_JADX, "ACQUIRES": P_JADX,
    "FLOWS_TO": P_REACHABILITY, "BINDS_TO": P_JNI, "LOADS_LIBRARY": P_JNI, "DEPENDS_ON": P_ELF,
    "FRAMEWORK_DISPATCH": P_SEMANTICS, "IPC_CALL": P_SEMANTICS, "INTENT_FLOW": P_SEMANTICS,
    "SECURITY_BOUNDARY": P_SEMANTICS, "DEEP_LINK": P_SEMANTICS, "WEBVIEW_BRIDGE": P_SEMANTICS,
    "REFLECTION_TARGET": P_SEMANTICS, "DYNAMIC_LOAD": P_SEMANTICS,
    "RUNTIME_OBSERVED": P_RUNTIME_FRIDA,
}


@dataclass(frozen=True)
class Provenance:
    source_type: str
    source_artifact: str | None = None
    file_path: str | None = None
    source_line: int | None = None
    location: str | None = None  # class/method or component
    evidence_id: str | None = None
    confidence: str = "UNKNOWN"
    timestamp: str | None = None

    def to_dict(self) -> dict:
        return {
            "source_type": self.source_type, "source_artifact": self.source_artifact,
            "file_path": self.file_path, "source_line": self.source_line, "location": self.location,
            "evidence_id": self.evidence_id, "confidence": self.confidence, "timestamp": self.timestamp,
        }


@dataclass
class KGNode:
    id: str
    node_type: str
    label: str
    analysis_id: str | None = None
    source_entity_id: str | None = None
    confidence: str = "UNKNOWN"
    status: str | None = None
    provenance: list[Provenance] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "type": self.node_type, "label": self.label,
            "analysis_id": self.analysis_id, "source_entity_id": self.source_entity_id,
            "confidence": self.confidence, "status": self.status,
            "provenance": [p.to_dict() for p in self.provenance], "metadata": self.metadata,
        }


@dataclass
class KGEdge:
    src: str
    dst: str
    edge_type: str
    analysis_id: str | None = None
    confidence: str = "UNKNOWN"
    provenance: list[Provenance] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    created_at: str | None = None
    _fingerprint: str | None = None

    @property
    def fingerprint(self) -> str:
        if self._fingerprint is None:
            ev = ";".join(sorted(self.evidence_refs))
            raw = f"{self.analysis_id}|{self.src}|{self.edge_type}|{self.dst}|{ev}"
            self._fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:24]
        return self._fingerprint

    def identity_key(self) -> str:
        """Analysis-agnostic edge identity (fingerprint minus analysis_id) — used
        to compare edges *across* analyses in the diff graph-delta projection."""
        ev = ";".join(sorted(self.evidence_refs))
        raw = f"{self.src}|{self.edge_type}|{self.dst}|{ev}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def to_dict(self) -> dict:
        return {
            "id": self.fingerprint, "source": self.src, "target": self.dst, "type": self.edge_type,
            "analysis_id": self.analysis_id, "confidence": self.confidence,
            "provenance": [p.to_dict() for p in self.provenance], "evidence_refs": self.evidence_refs,
            "created_at": self.created_at, "fingerprint": self.fingerprint,
        }


@dataclass
class KnowledgeGraph:
    analysis_id: str
    nodes: dict[str, KGNode] = field(default_factory=dict)
    edges: list[KGEdge] = field(default_factory=list)
    adjacency: dict[str, list[KGEdge]] = field(default_factory=dict)
    reverse: dict[str, list[KGEdge]] = field(default_factory=dict)
    truncated: bool = False
    _edge_keys: set = field(default_factory=set)

    def add_node(self, node: KGNode) -> KGNode:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        # Merge provenance without duplication (keeps identity stable).
        for p in node.provenance:
            if p not in existing.provenance:
                existing.provenance.append(p)
        return existing

    def add_edge(self, edge: KGEdge) -> bool:
        # Never connect nodes that are not both present (prevents phantom links).
        if edge.src not in self.nodes or edge.dst not in self.nodes:
            return False
        key = edge.fingerprint
        if key in self._edge_keys:
            return False
        self._edge_keys.add(key)
        self.edges.append(edge)
        self.adjacency.setdefault(edge.src, []).append(edge)
        self.reverse.setdefault(edge.dst, []).append(edge)
        return True

    def neighbors(self, node_id: str) -> list[dict]:
        out = []
        for e in self.adjacency.get(node_id, []):
            out.append({"direction": "out", "type": e.edge_type, "node": e.dst,
                        "label": self.nodes[e.dst].label, "confidence": e.confidence})
        for e in self.reverse.get(node_id, []):
            out.append({"direction": "in", "type": e.edge_type, "node": e.src,
                        "label": self.nodes[e.src].label, "confidence": e.confidence})
        return out


# ---------------------------------------------------------------------------
# ID helpers (stable, deterministic, content-derived)
# ---------------------------------------------------------------------------


def apk_id(analysis) -> str:
    return f"APK:{analysis.apk_sha256}"


def _finding_ref(f) -> str:
    return f"FINDING:{f.fingerprint or (f.rule_id + ':' + (f.component or ''))}"


def _dep_ref(d) -> str:
    return f"DEP:{d.ecosystem}:{d.name}:{d.version or 'UNKNOWN'}"


def _component_ref(name: str | None) -> str:
    return f"COMPONENT:{name or 'UNKNOWN'}"


def _entry_ref(component: str, method: str) -> str:
    return f"ANDROID_ENTRY_POINT:{component}.{method}"


def _rc_ref(rc) -> str:
    return f"ROOT_CAUSE:{rc.identifier}"


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


def build_knowledge_graph(analysis, max_nodes: int | None = None, max_edges: int | None = None,
                          include_code: bool = True, include_remediation: bool = False,
                          include_validation: bool = False, include_obfuscation: bool = False,
                          include_native_deep: bool = False, include_runtime_validation: bool = False) -> KnowledgeGraph:
    """Project the persisted analysis into a unified knowledge graph.

    ``include_remediation`` / ``include_validation`` / ``include_obfuscation`` /
    ``include_native_deep`` / ``include_runtime_validation`` are off by default so
    graph snapshots / APK-diff integrity are unaffected; enable them for the
    dedicated views."""
    node_cap = max_nodes if max_nodes is not None else settings.graph_max_projected_nodes
    edge_cap = max_edges if max_edges is not None else settings.graph_max_projected_edges
    aid = str(analysis.id)
    created = _iso(analysis.started_at)
    kg = KnowledgeGraph(analysis_id=aid)

    # --- APK + manifest --------------------------------------------------
    apk = KGNode(apk_id(analysis), N_APK, analysis.apk_sha256[:16], aid, str(analysis.apk_id),
                 confidence="HIGH", status=analysis.status,
                 provenance=[Provenance(P_DEX, source_artifact=analysis.apk_sha256, confidence="HIGH", timestamp=created)],
                 metadata={"sha256": analysis.apk_sha256, "profile": analysis.profile})
    kg.add_node(apk)

    manifest = analysis.manifest
    if manifest is not None:
        mref = f"MANIFEST:{manifest.package or aid}"
        kg.add_node(KGNode(mref, N_MANIFEST, manifest.package or "AndroidManifest.xml", aid, str(manifest.id),
                           confidence="HIGH", status=manifest.status,
                           provenance=[Provenance(P_MANIFEST, source_artifact="AndroidManifest.xml",
                                                  confidence="HIGH", timestamp=created)],
                           metadata={"package": manifest.package, "min_sdk": manifest.min_sdk,
                                     "target_sdk": manifest.target_sdk}))
        _edge(kg, apk.id, mref, E_CONTAINS, aid, "HIGH", P_MANIFEST, ["AndroidManifest.xml"], created)

        for perm in analysis.permissions:
            pref = f"PERMISSION:{perm.name}"
            kg.add_node(KGNode(pref, N_PERMISSION, perm.name.rsplit(".", 1)[-1], aid, str(perm.id),
                               confidence="HIGH", status=perm.protection_level,
                               provenance=[Provenance(P_MANIFEST, location=perm.name, confidence="HIGH", timestamp=created)],
                               metadata={"protection_level": perm.protection_level, "dangerous": perm.is_dangerous,
                                         "custom": perm.is_custom}))
            _edge(kg, mref, pref, E_REQUESTS, aid, "HIGH", P_MANIFEST, [perm.name], created)

    # --- components ------------------------------------------------------
    for comp in analysis.components:
        cref = _component_ref(comp.name)
        kg.add_node(KGNode(cref, N_COMPONENT, (comp.name or "UNKNOWN").rsplit(".", 1)[-1], aid, str(comp.id),
                           confidence="HIGH", status=comp.exposure,
                           provenance=[Provenance(P_MANIFEST, location=comp.name, confidence="HIGH", timestamp=created)],
                           metadata={"kind": comp.kind, "exposure": comp.exposure,
                                     "effective_exported": comp.effective_exported, "permission": comp.permission}))
        if manifest is not None:
            mref = f"MANIFEST:{manifest.package or aid}"
            _edge(kg, mref, cref, E_DECLARES, aid, "HIGH", P_MANIFEST, [comp.name or ""], created)
            if comp.effective_exported:
                _edge(kg, apk.id, cref, E_EXPORTS, aid, "HIGH", P_MANIFEST,
                      [f"{comp.name} exposure={comp.exposure}"], created)

    # --- android entry points -------------------------------------------
    for ep in analysis.android_entry_points:
        eref = _entry_ref(ep.component, ep.method)
        kg.add_node(KGNode(eref, N_ANDROID_ENTRY_POINT, f"{ep.component.rsplit('.', 1)[-1]}.{ep.method}", aid,
                           str(ep.id), confidence=ep.confidence, status="EXPORTED" if ep.exported else "INTERNAL",
                           provenance=[Provenance(P_SEMANTICS, location=f"{ep.component}.{ep.method}",
                                                  evidence_id=None, confidence=ep.confidence, timestamp=created)],
                           metadata={"component_type": ep.component_type, "lifecycle_event": ep.lifecycle_event,
                                     "exported": ep.exported, "node_key": ep.node_key}))
        _edge(kg, _component_ref(ep.component), eref, E_DECLARES, aid, ep.confidence, P_SEMANTICS,
              [ep.evidence or f"{ep.component}.{ep.method}"], created)

    # --- code graph (canonical nodes/edges), bounded --------------------
    referenced = _referenced_code_keys(analysis)
    if include_code:
        _project_code(kg, analysis, aid, created, node_cap, referenced)

    # --- native libs / functions / jni ----------------------------------
    for lib in analysis.native_libraries:
        lref = f"NATIVE_LIBRARY:{lib.archive_path}"
        kg.add_node(KGNode(lref, N_NATIVE_LIBRARY, lib.filename, aid, str(lib.id),
                           confidence="HIGH", status=lib.status,
                           provenance=[Provenance(P_ELF, source_artifact=lib.archive_path, confidence="HIGH",
                                                  timestamp=created)],
                           metadata={"abi": lib.abi, "architecture": lib.architecture, "stripped": lib.stripped,
                                     "soname": lib.soname}))
        _edge(kg, apk.id, lref, E_CONTAINS, aid, "HIGH", P_ELF, [lib.archive_path], created)

    for jni in analysis.jni_bindings:
        jref = f"JNI_BINDING:{jni.id}"
        label = f"{(jni.java_class or '').rsplit('.', 1)[-1]}.{jni.java_method}" if jni.java_class else (jni.native_function or "jni")
        kg.add_node(KGNode(jref, N_JNI_BINDING, label, aid, str(jni.id), confidence=jni.confidence,
                           status=jni.source,
                           provenance=[Provenance(P_JNI, source_artifact=jni.library_name, location=jni.java_class,
                                                  confidence=jni.confidence, timestamp=created)],
                           metadata={"java_class": jni.java_class, "java_method": jni.java_method,
                                     "native_function": jni.native_function, "library": jni.library_name}))
        if jni.library_name:
            for lib in analysis.native_libraries:
                if lib.filename == jni.library_name:
                    _edge(kg, jref, f"NATIVE_LIBRARY:{lib.archive_path}", E_BINDS_TO, aid, jni.confidence, P_JNI,
                          [jni.evidence or ""], created)
                    break

    # --- dependencies + CVE ---------------------------------------------
    for dep in analysis.dependencies:
        dref = _dep_ref(dep)
        kg.add_node(KGNode(dref, N_DEPENDENCY, f"{dep.name} {dep.version or 'UNKNOWN'}", aid, str(dep.id),
                           confidence=dep.identity_confidence, status=dep.version_confidence,
                           provenance=[Provenance(P_STATIC_RULE, source_artifact=dep.artifact, location=dep.name,
                                                  confidence=dep.identity_confidence, timestamp=created)],
                           metadata={"ecosystem": dep.ecosystem, "kind": dep.kind, "version": dep.version,
                                     "bundled": dep.bundled}))
        _edge(kg, apk.id, dref, E_DEPENDS_ON, aid, dep.identity_confidence, P_STATIC_RULE, [dep.name], created)

    for match in analysis.vulnerability_matches:
        cref = f"CVE:{match.cve_id}"
        kg.add_node(KGNode(cref, N_CVE, match.cve_id, aid, str(match.vulnerability_id) if match.vulnerability_id else None,
                           confidence=match.match_confidence, status=match.correlation_state,
                           provenance=[Provenance(P_CVE_DATABASE, source_artifact=match.cve_id,
                                                  confidence=match.match_confidence, timestamp=created)],
                           metadata={"version_state": match.version_state, "correlation_state": match.correlation_state,
                                     "reachability_state": match.reachability_state, "severity": match.severity}))
        dref = _dep_ref(match.dependency)
        if dref in kg.nodes:
            # version_state (AFFECTED / POSSIBLY_AFFECTED / UNKNOWN) is preserved verbatim.
            _edge(kg, dref, cref, E_MATCHES_CVE, aid, match.match_confidence, P_CVE_DATABASE,
                  [f"{match.version_state}/{match.correlation_state}"], created)
            _edge(kg, cref, dref, E_AFFECTS, aid, match.match_confidence, P_CVE_DATABASE,
                  [match.version_state], created)
        _project_cve_intel(kg, match, cref, aid, created)

    # --- security boundaries --------------------------------------------
    for b in analysis.security_boundaries:
        bref = f"SECURITY_BOUNDARY:{b.boundary_type}:{b.node_key}"
        kg.add_node(KGNode(bref, N_SECURITY_BOUNDARY, f"{b.boundary_type}", aid, str(b.id), confidence=b.confidence,
                           status=b.boundary_type,
                           provenance=[Provenance(P_SEMANTICS, location=b.component, confidence=b.confidence,
                                                  timestamp=created)],
                           metadata={"boundary_type": b.boundary_type, "component": b.component, "node_key": b.node_key}))
        if b.component:
            _edge(kg, _component_ref(b.component), bref, E_CROSSES, aid, b.confidence, P_SEMANTICS,
                  [b.evidence or b.boundary_type], created)

    # --- findings + evidence + correlation ------------------------------
    _project_findings(kg, analysis, aid, created, referenced)

    # --- root causes -----------------------------------------------------
    for rc in analysis.root_causes:
        rref = _rc_ref(rc)
        kg.add_node(KGNode(rref, N_ROOT_CAUSE, rc.title, aid, str(rc.id), confidence=rc.confidence,
                           status=rc.severity,
                           provenance=[Provenance(P_STATIC_RULE, location=rc.category, confidence=rc.confidence,
                                                  timestamp=created)],
                           metadata={"category": rc.category, "severity": rc.severity,
                                     "components": rc.affected_components}))
        for rcf in rc.findings:
            f = next((x for x in analysis.findings if x.id == rcf.finding_id), None)
            if f is not None:
                fref = _finding_ref(f)
                if fref in kg.nodes:
                    _edge(kg, rref, fref, E_ROOT_CAUSE_OF, aid, rc.confidence, P_STATIC_RULE, [rc.identifier], created)
                    _edge(kg, fref, rref, E_CAUSED_BY, aid, rc.confidence, P_STATIC_RULE, [rc.identifier], created)
        for comp in rc.affected_components or []:
            cref = _component_ref(comp)
            if cref in kg.nodes:
                _edge(kg, rref, cref, E_AFFECTS, aid, rc.confidence, P_STATIC_RULE, [rc.identifier], created)

    # --- attack surface --------------------------------------------------
    for asn in analysis.attack_surface_nodes:
        aref = f"ATTACK_SURFACE_NODE:{asn.node_key}"
        kg.add_node(KGNode(aref, N_ATTACK_SURFACE_NODE, asn.name, aid, str(asn.id),
                           confidence="MEDIUM", status=asn.exposure,
                           provenance=[Provenance(P_STATIC_RULE, location=asn.component, confidence="MEDIUM",
                                                  timestamp=created)],
                           metadata={"exposure": asn.exposure, "risk_score": asn.risk_score,
                                     "node_type": asn.node_type, "component": asn.component}))
        if asn.component:
            cref = _component_ref(asn.component)
            if cref in kg.nodes:
                _edge(kg, aref, cref, E_EXPOSES, aid, "MEDIUM", P_STATIC_RULE, [asn.evidence or asn.exposure], created)

    # --- runtime ---------------------------------------------------------
    _project_runtime(kg, analysis, aid, referenced)

    # --- remediation (opt-in; only persisted plan items) ----------------
    if include_remediation:
        _project_remediation(kg, analysis, aid, created)

    # --- validation (opt-in; only persisted validation claims) ----------
    if include_validation:
        _project_validation(kg, analysis, aid, created)

    # --- obfuscation (opt-in; only persisted observations) --------------
    if include_obfuscation:
        _project_obfuscation(kg, analysis, aid, created)

    # --- deep native / Ghidra (opt-in; only persisted native-deep rows) -
    if include_native_deep:
        _project_native_deep(kg, analysis, aid, created)

    # --- live runtime validation (opt-in; only persisted correlations) --
    if include_runtime_validation:
        _project_runtime_validation(kg, analysis, aid, created)

    # --- enforce edge cap (nodes already bounded) -----------------------
    if len(kg.edges) > edge_cap:
        kg.edges = kg.edges[:edge_cap]
        kg.truncated = True
    return kg


def _edge(kg, src, dst, etype, aid, confidence, provenance_source, evidence_refs, created):
    edge = KGEdge(src=src, dst=dst, edge_type=etype, analysis_id=aid, confidence=confidence,
                  provenance=[Provenance(provenance_source, confidence=confidence, timestamp=created)],
                  evidence_refs=[e for e in evidence_refs if e], created_at=created)
    return kg.add_edge(edge)


def _referenced_code_keys(analysis) -> set[str]:
    """Code-graph node keys referenced by findings/paths/entry points/boundaries
    — always projected so evidence chains stay traversable under truncation."""
    keys: set[str] = set()
    for ep in analysis.android_entry_points:
        keys.add(ep.node_key)
    for b in analysis.security_boundaries:
        keys.add(b.node_key)
    for p in analysis.reachability_paths:
        for n in (p.nodes or []):
            if n.get("key"):
                keys.add(n["key"])
    for s in analysis.dataflow_sources:
        keys.add(s.node_key)
    for s in analysis.security_sinks:
        keys.add(s.node_key)
    return keys


def _project_code(kg, analysis, aid, created, node_cap, referenced) -> None:
    budget = max(0, node_cap - len(kg.nodes))
    projected = 0
    keep: dict = {}
    # Referenced nodes first (unbounded — small set), then the rest up to budget.
    ordered = sorted(analysis.code_nodes, key=lambda n: (n.node_key not in referenced, n.node_key))
    for cn in ordered:
        if cn.node_key not in referenced:
            if projected >= budget:
                kg.truncated = True
                continue
            projected += 1
        ntype = _CODE_NODE_TYPE.get(cn.node_type, N_CODE_METHOD)
        prov = P_JADX if cn.node_type == "JAVA_METHOD" else _EDGE_PROVENANCE.get(cn.node_type, P_REACHABILITY)
        kg.add_node(KGNode(cn.node_key, ntype, cn.label, aid, str(cn.id), confidence=cn.confidence,
                           provenance=[Provenance(prov, file_path=cn.source_file, source_line=cn.line,
                                                  location=cn.class_name, confidence=cn.confidence, timestamp=created)],
                           metadata={"class": cn.class_name, "method": cn.method_name}))
        keep[cn.node_key] = True
    # Canonical code edges + semantic edges (only between projected nodes).
    for ce in analysis.code_edges:
        if ce.src_key in kg.nodes and ce.dst_key in kg.nodes:
            prov = _EDGE_PROVENANCE.get(ce.edge_type, P_REACHABILITY)
            _edge(kg, ce.src_key, ce.dst_key, ce.edge_type, aid, ce.confidence, prov,
                  [ce.evidence or ce.edge_type], created)
    for se in analysis.semantic_edges:
        if se.src_key in kg.nodes and se.dst_key in kg.nodes:
            prov = _EDGE_PROVENANCE.get(se.edge_type, P_SEMANTICS)
            _edge(kg, se.src_key, se.dst_key, se.edge_type, aid, se.confidence, prov,
                  [se.evidence or se.edge_type], created)
    # Wire android entry points to their code method node (DISPATCHES_TO).
    for ep in analysis.android_entry_points:
        if ep.node_key in kg.nodes:
            _edge(kg, _entry_ref(ep.component, ep.method), ep.node_key, E_DISPATCHES_TO, aid, ep.confidence,
                  P_SEMANTICS, [ep.evidence or ""], created)


def _project_findings(kg, analysis, aid, created, referenced) -> None:
    for f in analysis.findings:
        fref = _finding_ref(f)
        kg.add_node(KGNode(fref, N_FINDING, f.title, aid, str(f.id), confidence=f.confidence, status=f.status,
                           provenance=[Provenance(_finding_provenance(f), location=f.component,
                                                  confidence=f.confidence, timestamp=created)],
                           metadata={"rule_id": f.rule_id, "category": f.category, "severity": f.severity,
                                     "is_duplicate": f.is_duplicate, "runtime_status": f.runtime_status,
                                     "validation_state": f.validation_state}))
        # Attach the finding to its component when known.
        if f.component:
            cref = _component_ref(f.component)
            if cref in kg.nodes:
                _edge(kg, cref, fref, E_RELATED_TO, aid, f.confidence, _finding_provenance(f), [f.rule_id], created)
        # Evidence nodes + EVIDENCE_FOR edges (evidence -> finding).
        for i, ev in enumerate(f.evidence):
            eref = f"EVIDENCE:{f.fingerprint or f.rule_id}:{i}"
            kg.add_node(KGNode(eref, N_EVIDENCE, (ev.detail or ev.location or "")[:80], aid, str(ev.id),
                               confidence=f.confidence, status=ev.source,
                               provenance=[Provenance(_source_provenance(ev.source), file_path=None,
                                                      source_line=ev.line, location=ev.location,
                                                      evidence_id=str(ev.id), confidence=f.confidence,
                                                      timestamp=created)],
                               metadata={"source": ev.source, "location": ev.location, "class": ev.class_name,
                                         "method": ev.method_name, "line": ev.line}))
            _edge(kg, eref, fref, E_EVIDENCE_FOR, aid, f.confidence, _source_provenance(ev.source),
                  [ev.detail or ev.location or ""], created)
    # CORRELATES_WITH edges between findings sharing a correlation dimension.
    from collections import defaultdict
    groups: dict[tuple, list] = defaultdict(list)
    id_to_finding = {x.id: x for x in analysis.findings}
    for corr in analysis.finding_correlations:
        groups[(corr.dimension, corr.correlation_key)].append(corr.finding_id)
    for (dim, key), fids in groups.items():
        refs = [_finding_ref(id_to_finding[i]) for i in fids if i in id_to_finding]
        refs = [r for r in refs if r in kg.nodes]
        for a in range(len(refs)):
            for b in range(a + 1, len(refs)):
                _edge(kg, refs[a], refs[b], E_CORRELATES_WITH, aid, "MEDIUM", P_STATIC_RULE, [f"{dim}:{key}"], created)


def _project_runtime(kg, analysis, aid, referenced) -> None:
    for s in analysis.runtime_sessions:
        sref = f"RUNTIME_SESSION:{s.id}"
        adapter = (s.metadata_ or {}).get("adapter", "unknown")
        kg.add_node(KGNode(sref, N_RUNTIME_SESSION, f"session {str(s.id)[:8]}", aid, str(s.id),
                           confidence="HIGH", status=s.session_state,
                           provenance=[Provenance(P_RUNTIME_ADB, source_artifact=s.device_serial,
                                                  confidence="HIGH", timestamp=_iso(s.started_at))],
                           metadata={"state": s.session_state, "adapter": adapter, "device": s.device_serial}))
        _edge(kg, apk_id(analysis), sref, E_RELATED_TO, aid, "HIGH", P_RUNTIME_ADB, [str(s.id)], _iso(s.started_at))
        if s.device_serial:
            dref = f"RUNTIME_DEVICE:{s.device_serial}"
            kg.add_node(KGNode(dref, N_RUNTIME_DEVICE, s.device_serial, aid, None, confidence="HIGH",
                               status="CONNECTED",
                               provenance=[Provenance(P_RUNTIME_ADB, source_artifact=s.device_serial,
                                                      confidence="HIGH", timestamp=_iso(s.started_at))],
                               metadata={"serial": s.device_serial}))
            _edge(kg, sref, dref, E_OBSERVED_ON, aid, "HIGH", P_RUNTIME_ADB, [s.device_serial], _iso(s.started_at))
        for proc in s.processes:
            pref = f"RUNTIME_PROCESS:{s.id}:{proc.pid}"
            kg.add_node(KGNode(pref, N_RUNTIME_PROCESS, f"{proc.name} ({proc.pid})", aid, str(proc.id),
                               confidence="HIGH", status="RUNNING",
                               provenance=[Provenance(P_RUNTIME_ADB, confidence="HIGH", timestamp=_iso(s.started_at))],
                               metadata={"pid": proc.pid, "name": proc.name}))
            _edge(kg, sref, pref, E_CONTAINS, aid, "HIGH", P_RUNTIME_ADB, [str(proc.pid)], _iso(s.started_at))
        for obs in s.observations:
            oref = f"RUNTIME_OBSERVATION:{obs.id}"
            label = f"{(obs.class_name or '').rsplit('.', 1)[-1]}.{obs.method_name}" if obs.class_name else (obs.symbol or "obs")
            src = P_RUNTIME_FRIDA if obs.source == "FRIDA" else P_RUNTIME_ADB
            kg.add_node(KGNode(oref, N_RUNTIME_OBSERVATION, label, aid, str(obs.id), confidence=obs.confidence,
                               status="OBSERVED",
                               provenance=[Provenance(src, evidence_id=str(obs.id), location=obs.class_name,
                                                      confidence=obs.confidence, timestamp=_iso(obs.timestamp))],
                               metadata={"type": obs.observation_type, "class": obs.class_name,
                                         "method": obs.method_name, "symbol": obs.symbol}))
            _edge(kg, sref, oref, E_OBSERVED_AT, aid, obs.confidence, src, [str(obs.id)], _iso(obs.timestamp))


def _project_cve_intel(kg, match, cref, aid, created) -> None:
    """Project vulnerability-intelligence relationships for a matched CVE. Only
    runs when a global Vulnerability record is linked — analyses without linked
    intelligence keep an identical snapshot. Every edge carries CVE_DATABASE
    provenance. Signature nodes link to a code method / native symbol node when
    one exists (never fabricated)."""
    vuln = getattr(match, "vulnerability", None)
    if vuln is None:
        return
    for alias in sorted({a.alias for a in vuln.aliases}):
        aref = f"CVE_ALIAS:{alias}"
        kg.add_node(KGNode(aref, N_CVE_ALIAS, alias, aid, None, confidence="HIGH", status="alias",
                           provenance=[Provenance(P_CVE_DATABASE, source_artifact=alias, confidence="HIGH",
                                                  timestamp=created)]))
        _edge(kg, cref, aref, E_HAS_ALIAS, aid, "HIGH", P_CVE_DATABASE, [alias], created)
    for ident in vuln.identities:
        if ident.identity_type == "CWE":
            continue
        iref = f"CVE_IDENTITY:{ident.identity_type}:{ident.value}"
        kg.add_node(KGNode(iref, N_CVE_IDENTITY, f"{ident.identity_type}:{ident.value}", aid, str(ident.id),
                           confidence=ident.confidence, status=ident.identity_type,
                           provenance=[Provenance(P_CVE_DATABASE, location=ident.value, confidence=ident.confidence,
                                                  timestamp=created)]))
        _edge(kg, cref, iref, E_HAS_IDENTITY, aid, ident.confidence, P_CVE_DATABASE, [ident.value], created)
    for sig in vuln.signatures:
        label = f"{sig.class_name or sig.package or sig.native_symbol or ''}.{sig.method or ''}".strip(".")
        sref = f"CVE_SIGNATURE:{match.cve_id}:{sig.kind}:{label}"
        kg.add_node(KGNode(sref, N_CVE_SIGNATURE, f"{sig.kind}:{label}", aid, str(sig.id),
                           confidence=sig.confidence, status=sig.kind,
                           provenance=[Provenance(P_CVE_DATABASE, location=label, confidence=sig.confidence,
                                                  timestamp=created)],
                           metadata={"kind": sig.kind, "provider": sig.provider}))
        _edge(kg, cref, sref, E_HAS_SIGNATURE, aid, sig.confidence, P_CVE_DATABASE, [label], created)
        # Link the signature to a matching canonical code/native node when present.
        target = _signature_target_node(kg, sig)
        if target is not None:
            _edge(kg, sref, target, E_SIGNATURE_OF, aid, sig.confidence, P_CVE_DATABASE, [label], created)
    for ref in list(vuln.references)[:5]:
        rref = f"REFERENCE:{ref.url}"
        kg.add_node(KGNode(rref, N_REFERENCE, ref.url[:80], aid, None, confidence="HIGH", status="reference",
                           provenance=[Provenance(P_CVE_DATABASE, source_artifact=ref.url, confidence="HIGH",
                                                  timestamp=created)]))
        _edge(kg, cref, rref, E_HAS_REFERENCE, aid, "HIGH", P_CVE_DATABASE, [ref.url], created)


def _project_remediation(kg, analysis, aid, created) -> None:
    """Project persisted remediation items into the existing KG. Only persisted
    entities are projected; every edge carries REMEDIATION provenance. The
    canonical graph is unchanged as the source graph."""
    plans = list(analysis.remediation_plans)
    if not plans:
        return
    plan = max(plans, key=lambda p: p.created_at or datetime.min.replace(tzinfo=timezone.utc))
    fp_to_ref: dict[str, str] = {}
    for item in plan.items:
        rref = f"REMEDIATION_ITEM:{item.fingerprint}"
        fp_to_ref[item.fingerprint] = rref
        kg.add_node(KGNode(rref, N_REMEDIATION_ITEM, f"{item.action}:{item.target or ''}".strip(":"), aid,
                           str(item.id), confidence=item.confidence, status=item.status,
                           provenance=[Provenance(P_REMEDIATION, location=item.target, confidence=item.confidence,
                                                  timestamp=created)],
                           metadata={"action": item.action, "priority": item.priority, "fixability": item.fixability}))
        # TARGETS: link to the remediated dependency / component / native node.
        target_ref = _remediation_target_ref(kg, item)
        if target_ref:
            _edge(kg, rref, target_ref, E_TARGETS, aid, item.confidence, P_REMEDIATION, [item.target or ""], created)
            _edge(kg, rref, target_ref, E_REMEDIATES, aid, item.confidence, P_REMEDIATION, [item.action], created)
        # ADDRESSES / SUPPORTED_BY: link to finding / cve evidence nodes.
        for ev in item.evidence:
            if ev.source_type == "FINDING":
                fref = f"FINDING:{ev.source_id}"
                if fref in kg.nodes:
                    _edge(kg, rref, fref, E_ADDRESSES, aid, ev.confidence, P_REMEDIATION, [ev.source_id or ""], created)
            elif ev.source_type == "CVE" and ev.source_id:
                cref = f"CVE:{ev.source_id}"
                if cref in kg.nodes:
                    _edge(kg, rref, cref, E_ADDRESSES, aid, ev.confidence, P_REMEDIATION, [ev.source_id], created)
                    _edge(kg, rref, cref, E_SUPPORTED_BY, aid, ev.confidence, P_REMEDIATION, [ev.source_id], created)
    # BLOCKED_BY between items.
    for dep in plan.dependencies:
        src = next((f"REMEDIATION_ITEM:{i.fingerprint}" for i in plan.items if i.id == dep.from_item_id), None)
        dst = next((f"REMEDIATION_ITEM:{i.fingerprint}" for i in plan.items if i.id == dep.to_item_id), None)
        if src and dst and src in kg.nodes and dst in kg.nodes:
            _edge(kg, src, dst, E_BLOCKED_BY, aid, "MEDIUM", P_REMEDIATION, [dep.relation], created)


def _project_validation(kg, analysis, aid, created) -> None:
    """Project persisted validation claims/blockers into the existing KG. Only
    persisted entities are projected; every edge carries VALIDATION provenance."""
    for claim in analysis.validation_claims:
        cref = f"VALIDATION_CLAIM:{claim.fingerprint}"
        kg.add_node(KGNode(cref, N_VALIDATION_CLAIM, f"{claim.claim_type}:{claim.target or ''}".strip(":"), aid,
                           str(claim.id), confidence=str(claim.confidence), status=claim.validation_state,
                           provenance=[Provenance(P_VALIDATION, location=claim.target,
                                                  confidence=str(claim.confidence), timestamp=created)],
                           metadata={"claim_type": claim.claim_type, "validation_state": claim.validation_state,
                                     "independent_source_count": claim.independent_source_count}))
        # VALIDATES: link the claim to the finding it validates.
        if claim.finding_id is not None:
            f = next((x for x in analysis.findings if x.id == claim.finding_id), None)
            if f is not None:
                fref = _finding_ref(f)
                if fref in kg.nodes:
                    _edge(kg, cref, fref, E_VALIDATES, aid, str(claim.confidence), P_VALIDATION,
                          [claim.claim_type], created)
        # SUPPORTED_BY / CORROBORATES: distinct evidence families.
        for fam in sorted(claim.source_families or []):
            eref = f"VALIDATION_EVIDENCE:{claim.fingerprint}:{fam}"
            kg.add_node(KGNode(eref, N_VALIDATION_EVIDENCE, fam, aid, None, confidence="MEDIUM", status="evidence",
                               provenance=[Provenance(P_VALIDATION, source_artifact=fam, confidence="MEDIUM",
                                                      timestamp=created)]))
            etype = E_CORROBORATES if fam == "RUNTIME" else E_SUPPORTED_BY
            _edge(kg, cref, eref, etype, aid, "MEDIUM", P_VALIDATION, [fam], created)
        # BLOCKED_BY / REQUIRES_EVIDENCE: blockers.
        for b in claim.blockers:
            bref = f"VALIDATION_BLOCKER:{claim.fingerprint}:{b.blocker}"
            kg.add_node(KGNode(bref, N_VALIDATION_BLOCKER, b.blocker, aid, str(b.id), confidence="HIGH",
                               status="blocker",
                               provenance=[Provenance(P_VALIDATION, location=b.missing, confidence="HIGH",
                                                      timestamp=created)]))
            _edge(kg, cref, bref, E_BLOCKED_BY, aid, "HIGH", P_VALIDATION, [b.blocker], created)
            _edge(kg, cref, bref, E_REQUIRES_EVIDENCE, aid, "HIGH", P_VALIDATION, [b.missing], created)


def _project_obfuscation(kg, analysis, aid, created) -> None:
    """Project persisted obfuscation observations/indicators/impacts. Only
    persisted entities are projected; every edge carries OBFUSCATION provenance.
    The canonical graph is unchanged as the source graph."""
    for o in analysis.obfuscation_observations:
        oref = f"OBFUSCATION_OBSERVATION:{o.fingerprint}"
        kg.add_node(KGNode(oref, N_OBFUSCATION_OBSERVATION, f"{o.category}:{o.indicator}"[:80], aid, str(o.id),
                           confidence=o.confidence, status=o.state,
                           provenance=[Provenance(P_OBFUSCATION, location=o.target, confidence=o.confidence,
                                                  timestamp=created)],
                           metadata={"category": o.category, "state": o.state, "finding_type": o.finding_type}))
        # OBSCURES / INDICATES_OBFUSCATION: link to the code/native node it obscures.
        target = _obfuscation_target_ref(kg, o)
        if target is not None:
            _edge(kg, oref, target, E_OBSCURES, aid, o.confidence, P_OBFUSCATION, [o.indicator], created)
            _edge(kg, oref, target, E_INDICATES_OBFUSCATION, aid, o.confidence, P_OBFUSCATION, [o.category], created)
    for a in analysis.anti_analysis_indicators:
        aref = f"ANTI_ANALYSIS_INDICATOR:{a.fingerprint}"
        kg.add_node(KGNode(aref, N_ANTI_ANALYSIS_INDICATOR, f"{a.category}:{a.indicator}"[:80], aid, str(a.id),
                           confidence=a.confidence, status=a.evidence_level,
                           provenance=[Provenance(P_OBFUSCATION, location=a.target, confidence=a.confidence,
                                                  timestamp=created)],
                           metadata={"category": a.category, "evidence_level": a.evidence_level}))
        _edge(kg, aref, apk_id(analysis), E_INDICATES_ANTI_ANALYSIS, aid, a.confidence, P_OBFUSCATION,
              [a.indicator], created)
    for i in analysis.analysis_impacts:
        iref = f"ANALYSIS_IMPACT:{i.fingerprint}"
        kg.add_node(KGNode(iref, N_ANALYSIS_IMPACT, i.impact_category, aid, str(i.id), confidence=i.confidence,
                           status=i.impact_category,
                           provenance=[Provenance(P_OBFUSCATION, location=i.affected_target, confidence=i.confidence,
                                                  timestamp=created)],
                           metadata={"impact_category": i.impact_category}))
        _edge(kg, iref, apk_id(analysis), E_AFFECTS_ANALYSIS, aid, i.confidence, P_OBFUSCATION,
              [i.impact_category], created)
        if i.source_observation_fp:
            oref = f"OBFUSCATION_OBSERVATION:{i.source_observation_fp}"
            if oref in kg.nodes:
                _edge(kg, oref, iref, E_AFFECTS_ANALYSIS, aid, i.confidence, P_OBFUSCATION,
                      [i.impact_category], created)


def _project_native_deep(kg, analysis, aid, created) -> None:
    """Project persisted deep-native / Ghidra evidence (prompt 20). Opt-in only;
    every node/edge carries GHIDRA provenance and a source tag so this never
    silently replaces the canonical ELF NATIVE_LIBRARY/NATIVE_FUNCTION nodes.
    Node ids are namespaced with content fingerprints to avoid collision."""
    for run in analysis.native_analysis_runs:
        rref = f"NATIVE_ANALYSIS:{run.fingerprint}"
        kg.add_node(KGNode(rref, N_NATIVE_ANALYSIS, f"native:{run.mode}", aid, str(run.id),
                           confidence="HIGH", status=run.mode,
                           provenance=[Provenance(P_GHIDRA, source_artifact=run.mode, confidence="HIGH",
                                                  timestamp=created)],
                           metadata={"mode": run.mode, "ghidra_capability": run.ghidra_capability,
                                     "binaries": run.binaries_count, "functions": run.functions_count,
                                     "jni": run.jni_count, "call_edges": run.call_edge_count}))
        _edge(kg, apk_id(analysis), rref, E_ANALYZED_BY, aid, "HIGH", P_GHIDRA, [run.mode], created)

    for b in analysis.native_binaries:
        bref = f"NATIVE_BINARY:{b.fingerprint}"
        kg.add_node(KGNode(bref, N_NATIVE_BINARY, b.filename, aid, str(b.id), confidence="HIGH", status=b.source,
                           provenance=[Provenance(P_GHIDRA if b.source == "GHIDRA" else P_ELF,
                                                  source_artifact=b.sha256 or b.filename, confidence="HIGH",
                                                  timestamp=created)],
                           metadata={"abi": b.abi, "architecture": b.architecture, "stripped": b.stripped,
                                     "source": b.source, "sha256": b.sha256}))

    fp_to_node: dict[str, str] = {}
    for f in analysis.native_deep_functions:
        fref = f"NATIVE_FUNCTION_DEEP:{f.fingerprint}"
        fp_to_node[f.fingerprint] = fref
        prov = P_GHIDRA if f.source == "GHIDRA" else P_ELF
        kg.add_node(KGNode(fref, N_NATIVE_DEEP_FUNCTION, f.name[:80], aid, str(f.id),
                           confidence=f.confidence, status=f.function_type,
                           provenance=[Provenance(prov, location=f.entry_address, confidence=f.confidence,
                                                  timestamp=created)],
                           metadata={"function_type": f.function_type, "is_exported": f.is_exported,
                                     "is_imported": f.is_imported, "source": f.source, "binary_fp": f.binary_fp}))
        bref = f"NATIVE_BINARY:{f.binary_fp}"
        if bref in kg.nodes:
            etype = E_EXPORTS if f.is_exported else (E_IMPORTS if f.is_imported else E_CONTAINS)
            _edge(kg, bref, fref, etype, aid, f.confidence, prov, [f.name], created)

    for e in analysis.native_call_edges:
        src = fp_to_node.get(e.src_fp)
        dst = fp_to_node.get(e.dst_fp)
        if src and dst:
            _edge(kg, src, dst, E_NATIVE_CALLS, aid, e.confidence, P_GHIDRA, [f"{e.src_name}->{e.dst_name}"], created)

    for j in analysis.native_deep_jni_bindings:
        jref = f"JNI_BINDING_DEEP:{j.fingerprint}"
        kg.add_node(KGNode(jref, N_NATIVE_DEEP_JNI, f"{(j.java_class or '').rsplit('.', 1)[-1]}.{j.java_method}"[:80],
                           aid, str(j.id), confidence=j.confidence, status=j.state,
                           provenance=[Provenance(P_GHIDRA if j.source == "GHIDRA" else P_JNI,
                                                  location=j.native_symbol, confidence=j.confidence, timestamp=created)],
                           metadata={"registration_type": j.registration_type, "state": j.state,
                                     "native_symbol": j.native_symbol, "source": j.source}))
        target = fp_to_node.get(j.native_function_fp) if j.native_function_fp else None
        if target:
            _edge(kg, jref, target, E_BINDS_TO, aid, j.confidence, P_GHIDRA, [j.native_symbol or ""], created)

    for o in analysis.native_api_observations:
        oref = f"NATIVE_API:{o.fingerprint}"
        kg.add_node(KGNode(oref, N_NATIVE_API, f"{o.api}"[:80], aid, str(o.id), confidence=o.confidence,
                           status=o.state,
                           provenance=[Provenance(P_GHIDRA if o.source == "GHIDRA" else P_ELF,
                                                  location=o.api, confidence=o.confidence, timestamp=created)],
                           metadata={"api": o.api, "category": o.category, "state": o.state, "source": o.source}))
        target = fp_to_node.get(o.function_fp) if o.function_fp else None
        if target:
            # Only Ghidra-corroborated reachability uses REACHES_NATIVE_API; otherwise SUPPORTED_BY (presence).
            from app.native import deep_native as _D
            etype = E_REACHES_NATIVE_API if o.state == _D.API_REACHED else E_SUPPORTED_BY
            _edge(kg, target, oref, etype, aid, o.confidence, P_GHIDRA, [o.api], created)


def _project_runtime_validation(kg, analysis, aid, created) -> None:
    """Project persisted runtime correlations (prompt 21). Opt-in only; every edge
    carries RUNTIME_ADB / RUNTIME_FRIDA provenance, a LIVE/MOCKED marker, the
    session, observation id, timestamp, and confidence. The canonical graph stays
    authoritative — these are corroboration edges over existing evidence, never a
    second graph. Default snapshots are unchanged (this runs only when enabled)."""
    id_to_finding = {str(f.id): f for f in analysis.findings}
    edge_type = {"RUNTIME_CONFIRMS": E_RUNTIME_CONFIRMS, "RUNTIME_CORROBORATES": E_RUNTIME_CORROBORATES,
                 "RUNTIME_REACHES": E_RUNTIME_REACHES, "RUNTIME_INVOCATION": E_RUNTIME_INVOCATION}
    for c in analysis.runtime_correlations:
        prov = P_RUNTIME_FRIDA if c.provenance == "RUNTIME_FRIDA" else P_RUNTIME_ADB
        cref = f"RUNTIME_CORRELATION:{c.fingerprint}"
        kg.add_node(KGNode(cref, N_RUNTIME_CORRELATION, f"{c.correlation_type}:{c.taxonomy or ''}"[:80], aid,
                           str(c.id), confidence=c.confidence, status=c.mode,
                           provenance=[Provenance(prov, evidence_id=str(c.observation_id) if c.observation_id else None,
                                                  confidence=c.confidence, timestamp=created)],
                           metadata={"correlation_type": c.correlation_type, "taxonomy": c.taxonomy,
                                     "mode": c.mode, "live": c.mode == "LIVE", "session": str(c.session_id),
                                     "observation_id": str(c.observation_id) if c.observation_id else None}))
        subject = _runtime_subject_ref(kg, c, id_to_finding)
        etype = edge_type.get(c.correlation_type, E_RUNTIME_CORROBORATES)
        if subject is not None:
            _edge(kg, cref, subject, etype, aid, c.confidence, prov, [c.detail[:120]], created)
        else:
            # subject not projected (e.g. native-deep nodes disabled) — still attach
            # to the APK so the LIVE evidence is never silently dropped.
            _edge(kg, apk_id(analysis), cref, etype, aid, c.confidence, prov, [c.detail[:120]], created)


def _runtime_subject_ref(kg, c, id_to_finding) -> str | None:
    if c.subject_type == "FINDING":
        f = id_to_finding.get(c.subject_ref)
        ref = _finding_ref(f) if f is not None else None
    elif c.subject_type == "CODE_METHOD":
        ref = c.subject_ref
    elif c.subject_type == "NATIVE_FUNCTION":
        ref = f"NATIVE_FUNCTION_DEEP:{c.subject_ref}"
    elif c.subject_type == "NATIVE_API":
        ref = f"NATIVE_API:{c.subject_ref}"
    elif c.subject_type == "JNI_BINDING":
        ref = f"JNI_BINDING_DEEP:{c.subject_ref}"
    else:
        ref = c.subject_ref
    return ref if ref in kg.nodes else None


def _obfuscation_target_ref(kg, o) -> str | None:
    if not o.target:
        return None
    if o.target_type == "CODE_METHOD" and o.target in kg.nodes:
        return o.target
    if o.target_type in ("NATIVE_LIBRARY", "JNI_BINDING"):
        for nid, node in kg.nodes.items():
            if node.node_type == N_NATIVE_LIBRARY and (o.target or "").lower() in (node.label or "").lower():
                return nid
    return None


def _remediation_target_ref(kg, item) -> str | None:
    if item.target_type in ("DEPENDENCY", "NATIVE_LIBRARY"):
        for nid, node in kg.nodes.items():
            if node.node_type in (N_DEPENDENCY, N_NATIVE_LIBRARY) and \
                    (item.target or "").lower() in (node.label or "").lower():
                return nid
    if item.target_type == "COMPONENT" and item.target:
        cref = _component_ref(item.target)
        return cref if cref in kg.nodes else None
    return None


def _signature_target_node(kg, sig) -> str | None:
    if sig.kind in ("METHOD", "CLASS") and sig.class_name:
        simple = sig.class_name.rsplit(".", 1)[-1]
        for nid, node in kg.nodes.items():
            if node.node_type == N_CODE_METHOD and node.metadata.get("class") and \
                    node.metadata["class"].rsplit(".", 1)[-1] == simple and \
                    (sig.method is None or node.metadata.get("method") == sig.method):
                return nid
    if sig.kind in ("NATIVE_SYMBOL", "JNI") and sig.native_symbol:
        for nid, node in kg.nodes.items():
            if node.node_type == N_NATIVE_FUNCTION and sig.native_symbol in (node.label or ""):
                return nid
    return None


def _finding_provenance(f) -> str:
    return {"reachability": P_REACHABILITY, "semantic": P_SEMANTICS, "cve": P_CVE_DATABASE,
            "native": P_ELF}.get(f.category, P_STATIC_RULE)


def _source_provenance(source: str | None) -> str:
    m = {"manifest": P_MANIFEST, "dex": P_DEX, "jadx": P_JADX, "code": P_JADX, "elf": P_ELF,
         "native": P_ELF, "jni": P_JNI, "reachability": P_REACHABILITY, "semantic": P_SEMANTICS,
         "semantics": P_SEMANTICS, "cve": P_CVE_DATABASE, "runtime": P_RUNTIME_FRIDA}
    return m.get((source or "").lower(), P_STATIC_RULE)


def _iso(value) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


# ---------------------------------------------------------------------------
# Snapshot (deterministic)
# ---------------------------------------------------------------------------


def graph_digest(kg: KnowledgeGraph) -> str:
    """Deterministic content hash: sorted node identities + sorted edge
    fingerprints. Same persisted analysis -> same digest."""
    node_part = sorted(f"{n.node_type}\x1f{n.id}" for n in kg.nodes.values())
    edge_part = sorted(e.fingerprint for e in kg.edges)
    h = hashlib.sha256()
    for line in node_part:
        h.update(line.encode()); h.update(b"\n")
    h.update(b"--edges--\n")
    for line in edge_part:
        h.update(line.encode()); h.update(b"\n")
    return h.hexdigest()


def snapshot_counts(kg: KnowledgeGraph, analysis) -> dict:
    from collections import Counter
    node_types = Counter(n.node_type for n in kg.nodes.values())
    edge_types = Counter(e.edge_type for e in kg.edges)
    return {
        "node_count": len(kg.nodes),
        "edge_count": len(kg.edges),
        "finding_count": sum(1 for n in kg.nodes.values() if n.node_type == N_FINDING),
        "root_cause_count": sum(1 for n in kg.nodes.values() if n.node_type == N_ROOT_CAUSE),
        "runtime_observation_count": sum(1 for n in kg.nodes.values() if n.node_type == N_RUNTIME_OBSERVATION),
        "node_type_counts": dict(node_types),
        "edge_type_counts": dict(edge_types),
    }


def build_snapshot(analysis, now: datetime) -> "GraphSnapshot":
    """Build (and attach) a deterministic GraphSnapshot for the analysis."""
    from app.models.investigation import GraphSnapshot

    kg = build_knowledge_graph(analysis)
    counts = snapshot_counts(kg, analysis)
    snap = GraphSnapshot(
        graph_version=GRAPH_VERSION, digest=graph_digest(kg), created_at=now,
        node_count=counts["node_count"], edge_count=counts["edge_count"],
        finding_count=counts["finding_count"], root_cause_count=counts["root_cause_count"],
        runtime_observation_count=counts["runtime_observation_count"],
        node_type_counts=counts["node_type_counts"], edge_type_counts=counts["edge_type_counts"],
    )
    analysis.graph_snapshots.append(snap)
    return snap

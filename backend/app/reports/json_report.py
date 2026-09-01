"""Reproducible JSON report for a completed analysis.

Only JSON is implemented in this slice (no PDF/HTML). Output is deterministically
ordered so re-running analysis on the same APK with the same ruleset yields a
comparable report.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from app.models.analysis import Analysis
from app.models.apk import APKArtifact

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def build_report(analysis: Analysis, db: Session) -> dict:
    apk = db.get(APKArtifact, analysis.apk_id)
    manifest = analysis.manifest
    findings = sorted(
        analysis.findings,
        key=lambda finding: (_SEVERITY_ORDER.get(finding.severity, 9), finding.rule_id, finding.component or ""),
    )
    return {
        "schema": "androidsecforge.report/1",
        "analysis": {
            "id": str(analysis.id),
            "profile": analysis.profile,
            "status": analysis.status,
            "ruleset_version": analysis.ruleset_version,
            "started_at": _iso(analysis.started_at),
            "completed_at": _iso(analysis.completed_at),
            "stages": analysis.stages,
            "errors": analysis.errors,
        },
        "apk": _apk_section(apk),
        "capabilities": analysis.capabilities,
        "tool_versions": analysis.tool_versions,
        "manifest": _manifest_section(manifest),
        "permissions": [
            {
                "name": permission.name,
                "protection_level": permission.protection_level,
                "group": permission.permission_group,
                "is_dangerous": permission.is_dangerous,
                "is_custom": permission.is_custom,
            }
            for permission in sorted(analysis.permissions, key=lambda item: item.name)
        ],
        "components": [
            {
                "kind": component.kind,
                "name": component.name,
                "exported": component.exported,
                "explicit_exported": component.explicit_exported,
                "effective_exported": component.effective_exported,
                "exposure": component.exposure,
                "permission": component.permission,
                "authorities": component.authorities,
                "intent_filters": component.intent_filters,
            }
            for component in sorted(analysis.components, key=lambda item: (item.kind, item.name or ""))
        ],
        "dex_artifacts": [
            {
                "archive_path": dex.archive_path,
                "sha256": dex.sha256,
                "size_bytes": dex.size_bytes,
                "valid": dex.valid,
                "class_count": dex.class_count,
                "method_count": dex.method_count,
                "field_count": dex.field_count,
                "string_count": dex.string_count,
            }
            for dex in sorted(analysis.dex_artifacts, key=lambda item: item.archive_path)
        ],
        "code_analysis": {
            "status": analysis.capabilities.get("code_analysis", "UNAVAILABLE"),
            "class_count": sum(1 for entity in analysis.code_entities if entity.entity_type == "class"),
            "method_count": sum(1 for entity in analysis.code_entities if entity.entity_type == "method"),
            "field_count": sum(1 for entity in analysis.code_entities if entity.entity_type == "field"),
        },
        "native_libraries": [_native_library_section(lib) for lib in sorted(analysis.native_libraries, key=lambda item: item.archive_path)],
        "native_functions": _native_functions_summary(analysis),
        "native_dependencies": sorted(
            {(dep.library.filename, dep.needed) for lib in analysis.native_libraries for dep in lib.dependencies}
        ),
        "jni_bindings": [_jni_section(binding) for binding in analysis.jni_bindings],
        "native_findings": [_finding_section(f) for f in findings if f.category == "native"],
        "ghidra_status": analysis.capabilities.get("ghidra", "UNAVAILABLE"),
        "entry_points": [
            {"component": e.component, "kind": e.kind, "exported": e.exported,
             "permission": e.permission, "intent_filters": e.intent_filters}
            for e in analysis.entry_points
        ],
        "sources": [
            {"api": s.api, "type": s.source_type, "class": s.class_name, "method": s.method_name,
             "line": s.line, "confidence": s.confidence}
            for s in analysis.dataflow_sources
        ],
        "sinks": [
            {"api": s.api, "type": s.sink_type, "category": s.category, "class": s.class_name,
             "method": s.method_name, "line": s.line, "confidence": s.confidence}
            for s in analysis.security_sinks
        ],
        "code_edges": {
            "total": len(analysis.code_edges),
            "by_type": _edge_type_counts(analysis),
        },
        "reachability_paths": [
            {"rule_id": p.rule_id, "status": p.status, "confidence": p.confidence, "length": p.length,
             "nodes": p.nodes, "edges": p.edges}
            for p in sorted(analysis.reachability_paths, key=lambda item: item.length)
        ],
        "reachability_findings": [_finding_section(f) for f in findings if f.category == "reachability"],
        "android_entry_points": [
            {"component": e.component, "component_type": e.component_type, "method": e.method,
             "lifecycle_event": e.lifecycle_event, "exported": e.exported, "permission": e.permission,
             "confidence": e.confidence, "evidence": e.evidence}
            for e in analysis.android_entry_points
        ],
        "intents": [
            {"operation": i.operation, "action": i.action, "data_uri": i.data_uri,
             "target_component": i.target_component, "target_package": i.target_package,
             "class": i.class_name, "method": i.method_name, "confidence": i.confidence, "evidence": i.evidence}
            for i in analysis.intents
        ],
        "deep_links": [
            {"component": d.component, "scheme": d.scheme, "host": d.host, "port": d.port, "path": d.path,
             "path_prefix": d.path_prefix, "path_pattern": d.path_pattern, "mime_type": d.mime_type,
             "action": d.action, "category": d.category, "confidence": d.confidence, "evidence": d.evidence}
            for d in analysis.deep_links
        ],
        "ipc_transactions": [
            {"kind": t.kind, "class": t.class_name, "method": t.method_name, "interface": t.interface_name,
             "transaction_code": t.transaction_code, "confidence": t.confidence, "evidence": t.evidence}
            for t in analysis.ipc_transactions
        ],
        "security_boundaries": [
            {"boundary_type": b.boundary_type, "component": b.component, "confidence": b.confidence,
             "evidence": b.evidence}
            for b in analysis.security_boundaries
        ],
        "semantic_edges": {
            "total": len(analysis.semantic_edges),
            "by_type": _semantic_edge_counts(analysis),
        },
        "semantic_findings": [_finding_section(f) for f in findings if f.category == "semantic"],
        "dependencies": [
            {"name": d.name, "product": d.product, "ecosystem": d.ecosystem, "kind": d.kind,
             "version": d.version, "version_source": d.version_source, "version_confidence": d.version_confidence,
             "identity_confidence": d.identity_confidence, "bundled": d.bundled, "architecture": d.architecture,
             "artifact": d.artifact, "cpe": d.cpe,
             "evidence": [{"source": e.source, "detail": e.detail} for e in d.evidences]}
            for d in sorted(analysis.dependencies, key=lambda item: (item.kind, item.name))
        ],
        "vulnerability_matches": [
            {"cve_id": m.cve_id, "dependency": m.dependency.name, "match_method": m.match_method,
             "match_confidence": m.match_confidence, "version_state": m.version_state,
             "correlation_state": m.correlation_state, "reachability_state": m.reachability_state,
             "severity": m.severity, "evidence": m.evidence}
            for m in analysis.vulnerability_matches
        ],
        "vulnerability_findings": [_finding_section(f) for f in findings if f.category == "cve"],
        "cve_metadata": {
            "matches": len(analysis.vulnerability_matches),
            "states": _match_state_counts(analysis),
        },
        "root_causes": [_root_cause_section(rc) for rc in sorted(analysis.root_causes, key=_rc_sort)],
        "attack_surface": [_surface_section(n) for n in sorted(analysis.attack_surface_nodes, key=lambda n: -n.risk_score)],
        "correlated_findings": _correlation_groups(analysis),
        "evidence_paths": [_path_section(p) for p in analysis.reachability_paths if p.status == "REACHABLE"][:50],
        "risk": _risk_section(analysis),
        "runtime_summary": _runtime_summary(analysis),
        "runtime_sessions": [_runtime_session_section(s) for s in analysis.runtime_sessions],
        "runtime_observations": _runtime_observations(analysis),
        "runtime_correlations": _runtime_correlations(analysis, findings),
        "runtime_validation": _runtime_validation(analysis, findings),
        "knowledge_graph": _knowledge_graph_section(analysis),
        "vulnerability_intelligence": _vulnerability_intelligence(analysis, db),
        "remediation": _remediation_section(analysis),
        "validation": _validation_section(analysis),
        "obfuscation": _obfuscation_section(analysis),
        "native_deep_analysis": _native_deep_section(analysis),
        "assessment": _assessment_section(analysis),
        "findings": [_finding_section(finding) for finding in findings],
        "summary": _summary(analysis, findings),
    }


def _remediation_section(analysis) -> dict:
    """Deterministic remediation plan (computed in-memory; read-only)."""
    from app.reports.remediation_report import remediation_section

    return remediation_section(analysis)


def _validation_section(analysis) -> dict:
    """Security verification & validation intelligence (in-memory; read-only)."""
    from app.reports.validation_report import validation_section

    return validation_section(analysis)


def _obfuscation_section(analysis) -> dict:
    """Obfuscation & anti-analysis intelligence (in-memory; read-only)."""
    from app.reports.obfuscation_report import obfuscation_section

    return obfuscation_section(analysis)


def _native_deep_section(analysis) -> dict:
    """Deep native / Ghidra correlation (from persisted native-deep evidence)."""
    from app.reports.native_report import native_deep_section

    return native_deep_section(analysis)


def _assessment_section(analysis) -> dict:
    """Security assessment & decision intelligence (projection over persisted evidence)."""
    from app.reports.assessment_report import assessment_section

    return assessment_section(analysis)


def _vulnerability_intelligence(analysis, db) -> dict:
    """Provider-neutral vulnerability-intelligence view for this analysis. Reads
    the local intelligence DB; preserves UNKNOWN/POSSIBLY_AFFECTED and keeps
    KEV/EPSS separate from AndroidSecForge severity/risk."""
    from app.intel import conflicts as C, freshness as F
    from app.intel.explain import explain_match
    from app.models.cve import Vulnerability
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    from app.models.cve import AffectedProduct

    matches = list(analysis.vulnerability_matches)
    cve_ids = sorted({m.cve_id for m in matches})
    providers: set[str] = set()
    aliases: dict[str, list] = {}
    identities: dict[str, list] = {}
    signatures: dict[str, list] = {}
    scores: dict[str, list] = {}
    references: dict[str, list] = {}
    ranges: dict[str, list] = {}
    freshness: dict[str, str] = {}
    conflicts_out: dict[str, dict] = {}

    for cve_id in cve_ids:
        group = list(db.scalars(
            select(Vulnerability)
            .options(selectinload(Vulnerability.products).selectinload(AffectedProduct.ranges),
                     selectinload(Vulnerability.aliases), selectinload(Vulnerability.identities),
                     selectinload(Vulnerability.signatures), selectinload(Vulnerability.scores),
                     selectinload(Vulnerability.references))
            .where(Vulnerability.cve_id == cve_id)))
        if not group:
            continue
        for v in group:
            providers.add(v.source)
        resolution = C.resolve(group)
        conflicts_out[cve_id] = {"canonical_severity": resolution["canonical_severity"],
                                 "reason": resolution["resolution_reason"],
                                 "disagreements": resolution["disagreements"]}
        aliases[cve_id] = resolution["aliases"]
        freshness[cve_id] = F.freshness_status(group[0])
        identities[cve_id] = sorted({(i.identity_type, i.value, i.confidence) for v in group for i in v.identities
                                     if i.identity_type != "CWE"})
        signatures[cve_id] = [{"kind": s.kind, "class_name": s.class_name, "method": s.method,
                               "native_symbol": s.native_symbol, "confidence": s.confidence, "provider": s.provider}
                              for v in group for s in v.signatures]
        scores[cve_id] = [{"kind": s.kind, "provider": s.provider, "score": s.score, "severity": s.severity,
                           "percentile": s.percentile} for v in group for s in v.scores]
        references[cve_id] = sorted({r.url for v in group for r in v.references})
        ranges[cve_id] = sorted({r.raw or f"[{r.introduced},{r.fixed})" for v in group
                                 for p in v.products for r in p.ranges})

    versions = [{"dependency": m.dependency.name, "version": m.dependency.version or "UNKNOWN",
                 "version_source": m.dependency.version_source or "UNKNOWN",
                 "version_confidence": m.dependency.version_confidence} for m in matches]
    evidence_chains = [explain_match(analysis, m) for m in matches]

    return {
        "providers": sorted(providers),
        "aliases": aliases, "identities": {k: [list(t) for t in v] for k, v in identities.items()},
        "versions": versions, "ranges": ranges, "signatures": signatures, "scores": scores,
        "references": references, "freshness": freshness, "conflicts": conflicts_out,
        "cve_matches": [{"match_id": str(m.id), "cve_id": m.cve_id, "dependency": m.dependency.name,
                         "version_state": m.version_state, "correlation_state": m.correlation_state,
                         "reachability_state": m.reachability_state, "signature_state": m.signature_state,
                         "identity_confidence": m.identity_confidence, "earliest_fixed_version": m.earliest_fixed_version}
                        for m in matches],
        "cve_evidence_chains": evidence_chains,
        "note": "External intelligence (KEV/EPSS) is a separate axis from AndroidSecForge severity/risk; "
                "no result asserts exploitability.",
    }


def _knowledge_graph_section(analysis) -> dict:
    """Summary of the projected knowledge graph + latest snapshot. The full
    node/edge projection is available via the graph/investigation export APIs."""
    snapshots = sorted(analysis.graph_snapshots, key=lambda s: s.created_at)
    latest = snapshots[-1] if snapshots else None
    section = {
        "investigations": len(analysis.investigations),
        "snapshots": len(snapshots),
        "latest_snapshot": None if latest is None else {
            "graph_version": latest.graph_version, "digest": latest.digest,
            "node_count": latest.node_count, "edge_count": latest.edge_count,
            "finding_count": latest.finding_count, "root_cause_count": latest.root_cause_count,
            "runtime_observation_count": latest.runtime_observation_count,
            "node_type_counts": latest.node_type_counts, "edge_type_counts": latest.edge_type_counts,
        },
    }
    return section


def _runtime_summary(analysis) -> dict:
    sessions = analysis.runtime_sessions
    observations = [o for s in sessions for o in s.observations]
    live = any((s.metadata_ or {}).get("adapter") == "adb" and s.observations for s in sessions)
    mocked = any((s.metadata_ or {}).get("adapter") == "mock" and s.observations for s in sessions)
    mode = "LIVE" if live else ("MOCKED" if mocked else "UNAVAILABLE")
    return {
        "sessions": len(sessions),
        "observations": len(observations),
        "instrumented_sessions": sum(1 for s in sessions if s.instrumentation_enabled),
        "mode": mode,
    }


def _runtime_session_section(s) -> dict:
    return {"id": str(s.id), "state": s.session_state, "device": s.device_serial, "package": s.package_name,
            "instrumentation_enabled": s.instrumentation_enabled, "install_requested": s.install_requested,
            "launch_requested": s.launch_requested, "error": s.error,
            "observations": len(s.observations), "events": len(s.events),
            "audit_events": [{"operation": a.operation, "result": a.result, "device": a.device_serial}
                             for a in s.audit_events]}


def _runtime_observations(analysis, limit: int = 200) -> list[dict]:
    out = []
    for s in analysis.runtime_sessions:
        for o in s.observations:
            if len(out) >= limit:
                return out
            out.append({"type": o.observation_type, "class": o.class_name, "method": o.method_name,
                        "symbol": o.symbol, "native_library": o.native_library, "arguments": o.arguments_summary,
                        "return": o.return_summary, "source": o.source, "confidence": o.confidence,
                        "timestamp": o.timestamp.isoformat()})
    return out


def _runtime_correlations(analysis, findings) -> list[dict]:
    return [{"rule_id": f.rule_id, "component": f.component, "runtime_status": f.runtime_status,
             "validation_state": f.validation_state, "runtime_evidence_count": f.runtime_evidence_count}
            for f in findings if f.runtime_status and f.runtime_status != "STATIC_ONLY"]


def _runtime_validation(analysis, findings) -> dict:
    """Live runtime validation & behavioral corroboration section (prompt 21)."""
    from app.analysis.runtime_validation import runtime_validation_view
    view = runtime_validation_view(analysis)
    from collections import Counter
    sessions = analysis.runtime_sessions
    view["mode_legend"] = "LIVE = real device; MOCKED = offline test adapter; UNAVAILABLE = no runtime run"
    view["device_identity"] = next(({"serial": s.device_serial, "adapter": (s.metadata_ or {}).get("adapter")}
                                    for s in sessions if s.device_serial), {})
    view["runtime_finding_states"] = dict(Counter(f.runtime_validation_state for f in findings))
    view["corroborated_findings"] = [f.rule_id for f in findings
                                     if f.runtime_validation_state in ("CONFIRMED_RUNTIME_BEHAVIOR",
                                                                       "RUNTIME_CORROBORATED")]
    view["not_observed_note"] = "NOT_OBSERVED does not mean safe; absence of an observation is not proof of absence"
    return view


def _rc_sort(rc):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return (order.get(rc.severity, 9), rc.identifier)


def _root_cause_section(rc) -> dict:
    return {
        "identifier": rc.identifier, "category": rc.category, "title": rc.title, "description": rc.description,
        "severity": rc.severity, "confidence": rc.confidence, "severity_score": rc.severity_score,
        "confidence_score": rc.confidence_score, "affected_components": rc.affected_components,
        "affected_dependencies": rc.affected_dependencies, "boundaries": rc.boundaries,
        "findings": [f.rule_id for f in rc.findings], "paths": rc.paths,
        "evidence": [{"kind": e.kind, "detail": e.detail} for e in rc.evidence],
    }


def _surface_section(n) -> dict:
    return {"node_key": n.node_key, "type": n.node_type, "name": n.name, "exposure": n.exposure,
            "component": n.component, "permission": n.permission, "risk_score": n.risk_score, "evidence": n.evidence}


def _correlation_groups(analysis) -> list[dict]:
    from collections import defaultdict
    groups = defaultdict(list)
    for corr in analysis.finding_correlations:
        groups[(corr.dimension, corr.correlation_key)].append(str(corr.finding_id))
    return [{"dimension": dim, "key": key, "finding_ids": ids}
            for (dim, key), ids in sorted(groups.items()) if len(ids) > 1]


def _path_section(p) -> dict:
    return {"status": p.status, "confidence": p.confidence, "length": p.length, "rule_id": p.rule_id,
            "chain": [n.get("label") for n in (p.nodes or [])]}


def _risk_section(analysis) -> dict:
    overall = next((r for r in analysis.risk_assessments if r.scope == "overall"), None)
    entries = sorted((r for r in analysis.risk_assessments if r.scope != "overall"),
                     key=lambda r: -r.overall_score)
    if overall is None:
        return {}
    return {
        "overall_score": overall.overall_score, "severity": overall.severity, "confidence": overall.confidence,
        "severity_score": overall.severity_score, "confidence_score": overall.confidence_score,
        "factors": [{"name": f.name, "weight": f.weight, "direction": f.direction, "category": f.category,
                     "evidence": f.evidence} for f in overall.factors if f.direction == "positive"],
        "mitigations": [{"name": f.name, "weight": f.weight, "evidence": f.evidence}
                        for f in overall.factors if f.direction == "negative"],
        "high_risk_entry_points": [
            {"node_key": r.scope, "score": r.overall_score, "severity": r.severity,
             "component": (r.summary or {}).get("component")}
            for r in entries[:10]
        ],
    }


def _match_state_counts(analysis) -> dict:
    counts: dict[str, int] = {}
    for match in analysis.vulnerability_matches:
        counts[match.correlation_state] = counts.get(match.correlation_state, 0) + 1
    return counts


def _semantic_edge_counts(analysis) -> dict:
    counts: dict[str, int] = {}
    for edge in analysis.semantic_edges:
        counts[edge.edge_type] = counts.get(edge.edge_type, 0) + 1
    return counts


def _edge_type_counts(analysis) -> dict:
    counts: dict[str, int] = {}
    for edge in analysis.code_edges:
        counts[edge.edge_type] = counts.get(edge.edge_type, 0) + 1
    return counts


def _native_library_section(lib) -> dict:
    exported = sum(1 for f in lib.functions if f.kind == "exported")
    imported = sum(1 for f in lib.functions if f.kind == "imported")
    return {
        "archive_path": lib.archive_path,
        "abi": lib.abi,
        "filename": lib.filename,
        "size_bytes": lib.size_bytes,
        "sha256": lib.sha256,
        "elf_class": lib.elf_class,
        "architecture": lib.architecture,
        "endianness": lib.endianness,
        "elf_type": lib.elf_type,
        "entry_point": lib.entry_point,
        "soname": lib.soname,
        "stripped": lib.stripped,
        "symbols_available": lib.symbols_available,
        "status": lib.status,
        "error": lib.error,
        "exported_symbols": exported,
        "imported_symbols": imported,
        "needed": sorted(dep.needed for dep in lib.dependencies),
        "source": "ELF",
    }


def _native_functions_summary(analysis) -> dict:
    exported = [f for f in analysis.native_functions if f.kind == "exported"]
    imported = [f for f in analysis.native_functions if f.kind == "imported"]
    jni = [f for f in exported if f.is_jni]
    return {
        "total": len(analysis.native_functions),
        "exported": len(exported),
        "imported": len(imported),
        "jni_exports": sorted({f.name for f in jni}),
        "ghidra": sum(1 for f in analysis.native_functions if f.source == "Ghidra"),
    }


def _jni_section(binding) -> dict:
    return {
        "source": binding.source,
        "confidence": binding.confidence,
        "java_class": binding.java_class,
        "java_method": binding.java_method,
        "java_signature": binding.java_signature,
        "library": binding.library_name,
        "native_function": binding.native_function,
        "evidence": binding.evidence,
    }


def _apk_section(apk: APKArtifact | None) -> dict:
    if apk is None:
        return {}
    return {
        "id": str(apk.id),
        "original_filename": apk.original_filename,
        "artifact_type": apk.artifact_type,
        "sha256": apk.sha256,
        "sha1": apk.sha1,
        "md5": apk.md5,
        "size_bytes": apk.size_bytes,
        "package_name": apk.package_name,
        "version_name": apk.version_name,
        "version_code": apk.version_code,
    }


def _manifest_section(manifest) -> dict:
    if manifest is None:
        return {"status": "missing"}
    return {
        "status": manifest.status,
        "source_format": manifest.source_format,
        "package": manifest.package,
        "version_name": manifest.version_name,
        "version_code": manifest.version_code,
        "min_sdk": manifest.min_sdk,
        "target_sdk": manifest.target_sdk,
        "compile_sdk": manifest.compile_sdk,
        "debuggable": manifest.debuggable,
        "allow_backup": manifest.allow_backup,
        "uses_cleartext_traffic": manifest.uses_cleartext_traffic,
        "network_security_config": manifest.network_security_config,
    }


def _finding_section(finding) -> dict:
    return {
        # Additive identity/axis fields (prompt 22 UI) — never conflate these axes.
        "id": str(finding.id),
        "fingerprint": getattr(finding, "fingerprint", None),
        "rule_id": finding.rule_id,
        "title": finding.title,
        "category": finding.category,
        "severity": finding.severity,
        "severity_score": getattr(finding, "severity_score", None),
        "confidence": finding.confidence,
        "confidence_score": getattr(finding, "confidence_score", None),
        "status": finding.status,
        "component": finding.component,
        "root_cause_id": str(finding.root_cause_id) if getattr(finding, "root_cause_id", None) else None,
        "runtime_status": getattr(finding, "runtime_status", None),
        "runtime_validation_state": getattr(finding, "runtime_validation_state", "LIVE_UNAVAILABLE"),
        "evidence_count": len(finding.evidence),
        "description": finding.description,
        "remediation": finding.remediation,
        "references": finding.references,
        "validation": {
            "state": getattr(finding, "security_validation_state", "UNVERIFIED"),
            "confidence": getattr(finding, "validation_confidence", 0),
            "claim_count": getattr(finding, "validation_claim_count", 0),
            "evidence_count": getattr(finding, "validation_evidence_count", 0),
            "blocker_count": getattr(finding, "validation_blocker_count", 0),
            "summary": getattr(finding, "validation_summary", None),
        },
        "evidence": [
            {
                "source": item.source,
                "location": item.location,
                "detail": item.detail,
                "artifact": item.artifact,
                "class": item.class_name,
                "method": item.method_name,
                "line": item.line,
            }
            for item in finding.evidence
        ],
    }


def _summary(analysis: Analysis, findings) -> dict:
    counts = {level: 0 for level in _SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {
        "total_findings": len(findings),
        "severity": counts,
        "components": len(analysis.components),
        "exported_components": sum(1 for component in analysis.components if component.effective_exported),
        "permissions": len(analysis.permissions),
        "dangerous_permissions": sum(1 for permission in analysis.permissions if permission.is_dangerous),
        "dex_files": len(analysis.dex_artifacts),
        "native_libraries": len(analysis.native_libraries),
        "native_findings": sum(1 for f in findings if f.category == "native"),
        "jni_bindings": len(analysis.jni_bindings),
        "entry_points": len(analysis.entry_points),
        "sources": len(analysis.dataflow_sources),
        "sinks": len(analysis.security_sinks),
        "reachability_paths": len(analysis.reachability_paths),
        "reachable_paths": sum(1 for p in analysis.reachability_paths if p.status == "REACHABLE"),
        "reachability_findings": sum(1 for f in findings if f.category == "reachability"),
        "android_entry_points": len(analysis.android_entry_points),
        "deep_links": len(analysis.deep_links),
        "intents": len(analysis.intents),
        "ipc_transactions": len(analysis.ipc_transactions),
        "security_boundaries": len(analysis.security_boundaries),
        "semantic_edges": len(analysis.semantic_edges),
        "semantic_findings": sum(1 for f in findings if f.category == "semantic"),
        "dependencies": len(analysis.dependencies),
        "vulnerability_matches": len(analysis.vulnerability_matches),
        "vulnerability_findings": sum(1 for f in findings if f.category == "cve"),
        "confirmed_static_findings": sum(1 for f in findings if f.status == "CONFIRMED_BY_STATIC_ANALYSIS"),
        "potential_findings": sum(1 for f in findings if f.status == "POTENTIAL"),
        "duplicate_findings": sum(1 for f in findings if getattr(f, "is_duplicate", False)),
        "root_causes": len(analysis.root_causes),
        "attack_surface_nodes": len(analysis.attack_surface_nodes),
        "high_risk_entry_points": sum(1 for n in analysis.attack_surface_nodes if n.risk_score >= 70),
        "reachable_cves": sum(1 for m in analysis.vulnerability_matches if m.correlation_state == "AFFECTED_REACHABLE"),
        "unknown_cves": sum(1 for m in analysis.vulnerability_matches if m.correlation_state == "UNKNOWN"),
    }


def _iso(value) -> str | None:
    return value.isoformat() if value else None

"""Deterministic, explainable attack-surface risk scoring.

No ML, no opacity: the score is a bounded sum of documented factor weights, each
with an evidence string. Severity and confidence are separate axes. A score is
never translated into "exploitable".
"""

from __future__ import annotations

# Positive factor weights (documented; deterministic; adjust here to reconfigure).
RISK_WEIGHTS = {
    "exported_component": 15,
    "external_input": 15,
    "sensitive_sink_reachable": 20,
    "dangerous_permission": 8,
    "missing_permission_protection": 10,
    "webview_javascript": 10,
    "javascript_interface": 12,
    "reflection_external_input": 10,
    "dynamic_loading_external": 15,
    "jni_boundary": 8,
    "native_unsafe_api": 8,
    "reachable_cve": 20,
    "affected_cve_unreachable": 6,
    "possibly_affected_cve": 4,
    "unknown_dependency_version": 3,
    "weak_crypto": 6,
    "cleartext_network": 6,
    "security_boundary_crossed": 8,
    # External-intelligence factors (prompt 16). These are DISTINCT, documented
    # factors — external intelligence is never folded into severity/confidence,
    # and is applied only when a matched-and-affected CVE carries the signal.
    "external_kev_known_exploited": 12,
    "external_epss_high": 6,
}

# EPSS probability threshold above which the external factor applies (documented).
EPSS_HIGH_THRESHOLD = 0.5

# Mitigating factor weights (subtracted).
RISK_MITIGATIONS = {
    "permission_protected": 10,
    "internal_only": 8,
    "source_sink_not_reachable": 5,
    "dependency_not_affected": 3,
    "constant_only_reflection_or_dynload": 4,
    "disconnected_source_sink": 2,
}

_SEVERITY_BANDS = [(90, "critical"), (70, "high"), (40, "medium"), (20, "low"), (0, "info")]
_CONFIDENCE_SCORE = {"low": 30, "medium": 60, "high": 85, "confirmed": 95}


def _band(score: int) -> str:
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "info"


def _clamp(value: int) -> int:
    return max(0, min(100, value))


def assess_risk(analysis):
    """Compute the overall risk assessment plus per-entry-point assessments.
    Returns (overall_assessment, entrypoint_assessments)."""
    from app.models.correlation import RiskAssessment, RiskFactor

    factors = _overall_factors(analysis)
    positive = sum(f["weight"] for f in factors if f["direction"] == "positive")
    negative = sum(f["weight"] for f in factors if f["direction"] == "negative")
    score = _clamp(positive - negative)
    confidence, confidence_score = _overall_confidence(analysis)

    overall = RiskAssessment(
        scope="overall", overall_score=score, severity=_band(score), confidence=confidence,
        severity_score=score, confidence_score=confidence_score,
        summary={"positive": positive, "negative": negative,
                 "note": "deterministic factor sum; not an exploitability claim"})
    for f in factors:
        overall.factors.append(RiskFactor(name=f["name"], weight=f["weight"], direction=f["direction"],
                                          category=f.get("category", ""), evidence=f["evidence"]))
    analysis.risk_assessments.append(overall)

    entry_assessments = []
    for node in analysis.attack_surface_nodes:
        if node.exposure == "INTERNAL":
            continue
        ef = _entrypoint_factors(analysis, node)
        if not ef:
            continue
        pos = sum(f["weight"] for f in ef if f["direction"] == "positive")
        neg = sum(f["weight"] for f in ef if f["direction"] == "negative")
        escore = _clamp(pos - neg)
        node.risk_score = escore
        ra = RiskAssessment(scope=node.node_key, overall_score=escore, severity=_band(escore),
                            confidence=confidence, severity_score=escore, confidence_score=confidence_score,
                            summary={"component": node.component, "exposure": node.exposure})
        for f in ef:
            ra.factors.append(RiskFactor(name=f["name"], weight=f["weight"], direction=f["direction"],
                                         category=f.get("category", ""), evidence=f["evidence"]))
        analysis.risk_assessments.append(ra)
        entry_assessments.append(ra)
    return overall, entry_assessments


# ---------------------------------------------------------------------------
# Factor derivation (all from persisted evidence)
# ---------------------------------------------------------------------------


def _pos(name, evidence, category=""):
    return {"name": name, "weight": RISK_WEIGHTS[name], "direction": "positive", "category": category, "evidence": evidence}


def _neg(name, evidence, category=""):
    return {"name": name, "weight": RISK_MITIGATIONS[name], "direction": "negative", "category": category, "evidence": evidence}


def _rule_ids(analysis) -> set[str]:
    return {f.rule_id for f in analysis.findings if not f.is_duplicate}


def _overall_factors(analysis) -> list[dict]:
    factors: list[dict] = []
    rules = _rule_ids(analysis)
    exported = [n for n in analysis.attack_surface_nodes if n.exposure in ("PUBLIC", "PERMISSION_PROTECTED", "UNKNOWN")]
    reachable_paths = [p for p in analysis.reachability_paths if p.status == "REACHABLE"]

    if exported:
        factors.append(_pos("exported_component", f"{len(exported)} exported attack-surface node(s)", "component"))
    n_sources = len(analysis.dataflow_sources)
    if n_sources:
        factors.append(_pos("external_input", f"{n_sources} external input source(s) in code", "input"))
    elif any(n.node_type.startswith("EXPORTED") for n in exported):
        factors.append(_pos("external_input", "exported components accept external Intent/IPC input", "input"))
    if reachable_paths:
        factors.append(_pos("sensitive_sink_reachable", f"{len(reachable_paths)} reachable source->sink path(s)", "reachability"))
    if any(p.is_dangerous for p in analysis.permissions):
        n = sum(1 for p in analysis.permissions if p.is_dangerous)
        factors.append(_pos("dangerous_permission", f"{n} dangerous permission(s)", "permission"))
    if "ANDROID-COMPONENT-001" in rules:
        factors.append(_pos("missing_permission_protection", "exported component without permission guard", "component"))
    if "ANDROID-WEBVIEW-001" in rules:
        factors.append(_pos("webview_javascript", "WebView JavaScript enabled", "webview"))
    if "ANDROID-WEBVIEW-002" in rules or "ANDROID-SEMANTIC-004" in rules:
        factors.append(_pos("javascript_interface", "WebView JavaScript interface exposed", "webview"))
    if any(rc.category == "REFLECTION_EXTERNAL_INPUT" for rc in analysis.root_causes):
        factors.append(_pos("reflection_external_input", "external input reaches reflection", "reflection"))
    if any(rc.category == "DANGEROUS_DYNAMIC_LOADING" for rc in analysis.root_causes):
        factors.append(_pos("dynamic_loading_external", "external input reaches dynamic class loading", "dynamic_loading"))
    if any(b.boundary_type == "JNI" for b in analysis.security_boundaries):
        factors.append(_pos("jni_boundary", "JNI boundary present", "native"))
    if any(r.startswith("ASF-NATIVE-") for r in rules):
        factors.append(_pos("native_unsafe_api", "native library imports a dangerous C API", "native"))

    matches = analysis.vulnerability_matches
    if any(m.correlation_state == "AFFECTED_REACHABLE" for m in matches):
        factors.append(_pos("reachable_cve", "affected dependency with reachable vulnerable code", "cve"))
    if any(m.correlation_state in ("AFFECTED_NOT_REACHABLE", "PRESENT_AFFECTED") for m in matches):
        factors.append(_pos("affected_cve_unreachable", "affected dependency, reachability unresolved/not-reachable", "cve"))
    if any(m.correlation_state == "PRESENT_UNKNOWN_VERSION" for m in matches):
        factors.append(_pos("possibly_affected_cve", "dependency possibly affected (version uncertain)", "cve"))
    if any(d.version_confidence == "UNKNOWN" for d in analysis.dependencies):
        factors.append(_pos("unknown_dependency_version", "dependency with unknown version", "cve"))
    # External intelligence — separate axis, applied only for affected/present matches.
    _affected = [m for m in matches if m.correlation_state in
                 ("AFFECTED_REACHABLE", "AFFECTED_NOT_REACHABLE", "PRESENT_AFFECTED")]
    if any(getattr(m.vulnerability, "known_exploited", False) for m in _affected if m.vulnerability):
        factors.append(_pos("external_kev_known_exploited",
                            "external intelligence: provider marks an affected CVE known-exploited (KEV) — "
                            "this is external evidence, NOT an AndroidSecForge exploitability conclusion", "external_intel"))
    if any((getattr(m.vulnerability, "epss_score", None) or 0) >= EPSS_HIGH_THRESHOLD
           for m in _affected if m.vulnerability):
        factors.append(_pos("external_epss_high",
                            f"external intelligence: an affected CVE has EPSS >= {EPSS_HIGH_THRESHOLD} "
                            "(external prediction, separate from AndroidSecForge severity)", "external_intel"))
    if "ANDROID-CRYPTO-001" in rules:
        factors.append(_pos("weak_crypto", "weak cryptographic primitive", "crypto"))
    if "ANDROID-MANIFEST-003" in rules:
        factors.append(_pos("cleartext_network", "cleartext traffic enabled", "network"))
    if any(rc.boundaries for rc in analysis.root_causes):
        factors.append(_pos("security_boundary_crossed", "a root cause crosses a security boundary", "boundary"))

    # Mitigations
    if exported and all(n.exposure == "PERMISSION_PROTECTED" for n in exported):
        factors.append(_neg("permission_protected", "all exported surfaces are permission-protected", "component"))
    if (analysis.dataflow_sources or analysis.security_sinks) and not reachable_paths:
        factors.append(_neg("source_sink_not_reachable", "sources/sinks present but no reachable path", "reachability"))
    if any(m.version_state == "NOT_AFFECTED" for m in matches):
        factors.append(_neg("dependency_not_affected", "at least one dependency proven NOT_AFFECTED", "cve"))
    if _constant_only(analysis):
        factors.append(_neg("constant_only_reflection_or_dynload",
                            "reflection/dynamic-load uses constant targets (no external input)", "reflection"))
    return factors


def _constant_only(analysis) -> bool:
    has_reflect_or_dyn = any(e.edge_type in ("REFLECTION_TARGET", "DYNAMIC_LOAD") for e in analysis.semantic_edges)
    external = any(rc.category in ("REFLECTION_EXTERNAL_INPUT", "DANGEROUS_DYNAMIC_LOADING") for rc in analysis.root_causes)
    return has_reflect_or_dyn and not external


def _entrypoint_factors(analysis, node) -> list[dict]:
    factors: list[dict] = []
    if node.exposure == "PUBLIC":
        factors.append(_pos("exported_component", f"{node.node_type} publicly reachable ({node.name})", "component"))
    elif node.exposure in ("PERMISSION_PROTECTED", "UNKNOWN"):
        factors.append(_pos("exported_component", f"{node.node_type} exposed ({node.exposure})", "component"))
    if node.exposure == "PERMISSION_PROTECTED":
        factors.append(_neg("permission_protected", f"protected by {node.permission}", "component"))
    # root causes tied to this component
    for rc in analysis.root_causes:
        if node.component and node.component in (rc.affected_components or []):
            if rc.category == "UNSAFE_WEBVIEW_INPUT":
                factors.append(_pos("webview_javascript", f"reaches {rc.category}", "webview"))
            elif rc.category == "DANGEROUS_DYNAMIC_LOADING":
                factors.append(_pos("dynamic_loading_external", f"reaches {rc.category}", "dynamic_loading"))
            elif rc.category == "NATIVE_UNSAFE_API":
                factors.append(_pos("native_unsafe_api", f"reaches {rc.category}", "native"))
            elif rc.category == "DEPENDENCY_CVE":
                factors.append(_pos("reachable_cve", f"reaches {rc.category}", "cve"))
            else:
                factors.append(_pos("sensitive_sink_reachable", f"reaches {rc.category}", "reachability"))
    return factors


def _overall_confidence(analysis):
    contributing = [f for f in analysis.findings if not f.is_duplicate and f.confidence_score]
    if not contributing:
        return "low", 30
    avg = sum(f.confidence_score for f in contributing) // len(contributing)
    label = "high" if avg >= 80 else "medium" if avg >= 55 else "low"
    return label, avg

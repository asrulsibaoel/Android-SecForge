"""Finding correlation, root-cause aggregation, deduplication, and path
summarization.

Operates entirely on already-persisted evidence (findings, reachability paths,
boundaries, dependencies, CVE matches). It never merges findings by text
similarity, never fabricates evidence, and never claims exploitability. Root
causes are deterministic: identical inputs produce identical identifiers.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from app.models.analysis import FindingModel
from app.models.correlation import (
    AttackSurfaceNode,  # noqa: F401 (kept for type clarity in callers)
    FindingCorrelation,
    RootCause,
    RootCauseEvidence,
    RootCauseFinding,
)

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_SEVERITY_SCORE = {"info": 10, "low": 30, "medium": 55, "high": 80, "critical": 95}
_CONFIDENCE_SCORE = {"low": 30, "medium": 60, "high": 85, "confirmed": 95}
_CVE_RE = re.compile(r"(CVE[-\w]+|CVE-TEST-\d+)")


# ---------------------------------------------------------------------------
# Deduplication + fingerprints (Phase 8)
# ---------------------------------------------------------------------------


def _primary_target(finding: FindingModel) -> str:
    if finding.evidence:
        # the most specific evidence location is a good primary target
        located = [e for e in finding.evidence if e.location]
        if located:
            return located[0].location
    return finding.component or finding.rule_id


def fingerprint_finding(finding: FindingModel) -> str:
    target = _primary_target(finding)
    identity = "|".join(
        sorted(f"{e.source}:{e.location}" for e in finding.evidence)
    ) or (finding.component or "")
    raw = f"{finding.rule_id}|{finding.category}|{target}|{identity}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def deduplicate(analysis) -> int:
    """Assign stable fingerprints and flag exact duplicates (same rule + target +
    evidence identity within one analysis). Returns the number flagged."""
    seen: dict[str, FindingModel] = {}
    duplicates = 0
    for finding in sorted(analysis.findings, key=lambda f: str(f.id)):
        fp = fingerprint_finding(finding)
        finding.fingerprint = fp
        finding.primary_target = _primary_target(finding)
        if finding.severity_score is None:
            finding.severity_score = _SEVERITY_SCORE.get(finding.severity, 10)
        if finding.confidence_score is None:
            finding.confidence_score = _CONFIDENCE_SCORE.get(finding.confidence, 30)
        if fp in seen:
            finding.is_duplicate = True
            duplicates += 1
        else:
            finding.is_duplicate = False
            seen[fp] = finding
    return duplicates


# ---------------------------------------------------------------------------
# Correlation index (Phase 2)
# ---------------------------------------------------------------------------


def _cve_id(finding: FindingModel) -> str | None:
    match = _CVE_RE.search(finding.title or "")
    return match.group(1) if match else None


def _sink_label(finding: FindingModel) -> str | None:
    for evidence in reversed(finding.evidence):
        if "SECURITY_SINK" in (evidence.detail or ""):
            return evidence.detail.split("SECURITY_SINK", 1)[1].strip().split("(")[0].strip()
    return None


def finding_dimensions(finding: FindingModel) -> list[tuple[str, str]]:
    dims: list[tuple[str, str]] = []
    if finding.component:
        dims.append(("component", finding.component))
    if finding.category == "cve":
        cve = _cve_id(finding)
        if cve:
            dims.append(("cve", cve))
        if finding.component:
            dims.append(("dependency", finding.component))
    if finding.category == "native" and finding.component:
        dims.append(("native_library", finding.component))
    sink = _sink_label(finding)
    if sink:
        dims.append(("sink", sink))
    return dims


def correlate(analysis) -> int:
    """Persist a correlation index (finding -> shared dimension key). O(N) in
    findings x dimensions; no pairwise scan. Returns rows created."""
    count = 0
    for finding in analysis.findings:
        for dimension, key in finding_dimensions(finding):
            analysis.finding_correlations.append(
                FindingCorrelation(finding_id=finding.id, dimension=dimension, correlation_key=key[:512])
            )
            count += 1
    return count


def correlation_groups(analysis) -> dict:
    """Return {(dimension, key): [finding_ids]} groups with >1 member (for CLI)."""
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for corr in analysis.finding_correlations:
        groups[(corr.dimension, corr.correlation_key)].append(str(corr.finding_id))
    return {f"{dim}:{key}": ids for (dim, key), ids in groups.items() if len(ids) > 1}


# ---------------------------------------------------------------------------
# Root causes (Phase 3)
# ---------------------------------------------------------------------------

_RULE_ROOT_CAUSE = {
    "ANDROID-WEBVIEW-001": ("UNSAFE_WEBVIEW_INPUT", "Unsafe WebView configuration/input"),
    "ANDROID-WEBVIEW-002": ("UNSAFE_WEBVIEW_INPUT", "Unsafe WebView configuration/input"),
    "ANDROID-SEMANTIC-004": ("UNSAFE_WEBVIEW_INPUT", "Unsafe WebView configuration/input"),
    "ANDROID-COMPONENT-001": ("EXPORTED_COMPONENT_INPUT", "Exported component receives external input"),
    "ANDROID-SEMANTIC-001": ("EXPORTED_COMPONENT_INPUT", "Exported component receives external input"),
    "ANDROID-COMPONENT-002": ("IPC_EXPOSURE", "Exported IPC surface"),
    "ANDROID-SEMANTIC-003": ("IPC_EXPOSURE", "Exported IPC surface"),
    "ANDROID-SEMANTIC-005": ("DANGEROUS_DYNAMIC_LOADING", "External input reaches dynamic class loading"),
    "ANDROID-MANIFEST-003": ("INSECURE_NETWORK_CONFIGURATION", "Insecure network configuration"),
    "ANDROID-TLS-001": ("INSECURE_NETWORK_CONFIGURATION", "Insecure network configuration"),
    "ANDROID-TLS-002": ("INSECURE_NETWORK_CONFIGURATION", "Insecure network configuration"),
    "ANDROID-CRYPTO-001": ("WEAK_CRYPTO", "Weak cryptographic primitive"),
    "ANDROID-MANIFEST-001": ("DEBUGGABLE_BUILD", "Debuggable application build"),
    "ANDROID-MANIFEST-002": ("BACKUP_ENABLED", "Application backup enabled"),
}

# grouping keys: category-level constant vs per-component/dependency target
_CATEGORY_LEVEL = {
    "UNSAFE_WEBVIEW_INPUT", "DANGEROUS_DYNAMIC_LOADING", "INSECURE_NETWORK_CONFIGURATION",
    "WEAK_CRYPTO", "DEBUGGABLE_BUILD", "BACKUP_ENABLED", "REFLECTION_EXTERNAL_INPUT",
    "COMMAND_EXECUTION", "JNI_REACHABLE_SURFACE",
}


def _reach_root_cause(finding: FindingModel) -> tuple[str, str] | None:
    title = (finding.title or "").lower()
    if "webview" in title:
        return ("UNSAFE_WEBVIEW_INPUT", "Unsafe WebView configuration/input")
    if "reflection" in title:
        return ("REFLECTION_EXTERNAL_INPUT", "External input reaches reflection")
    if "dynamic class loading" in title:
        return ("DANGEROUS_DYNAMIC_LOADING", "External input reaches dynamic class loading")
    if "command execution" in title:
        return ("COMMAND_EXECUTION", "External input reaches command execution")
    if "jni/native boundary" in title:
        return ("JNI_REACHABLE_SURFACE", "Exported component reaches JNI/native boundary")
    if "native security-relevant" in title:
        return ("NATIVE_UNSAFE_API", "External input reaches native security-relevant API")
    return ("EXPORTED_COMPONENT_INPUT", "Exported component reaches security-relevant sink")


def _classify(finding: FindingModel) -> tuple[str, str] | None:
    rule = finding.rule_id
    if rule in _RULE_ROOT_CAUSE:
        return _RULE_ROOT_CAUSE[rule]
    if rule.startswith("ANDROID-REACH-"):
        return _reach_root_cause(finding)
    if rule.startswith("ASF-NATIVE-"):
        return ("NATIVE_UNSAFE_API", "Native library uses a dangerous C API")
    if rule.startswith("ANDROID-CVE-"):
        return ("DEPENDENCY_CVE", "Vulnerable dependency")
    if rule == "ANDROID-SECRET-001":
        return ("HARDCODED_SECRET", "Hardcoded secret indicator")
    return None


def _group_key(category: str, finding: FindingModel) -> str:
    if category in _CATEGORY_LEVEL:
        return category
    # per-component / per-dependency / per-library
    return finding.component or category


def build_root_causes(analysis) -> list[RootCause]:
    """Aggregate findings into deterministic root causes (only when supported)."""
    buckets: dict[tuple[str, str], dict] = {}
    for finding in analysis.findings:
        if finding.is_duplicate:
            continue
        classified = _classify(finding)
        if classified is None:
            continue
        category, title = classified
        key = (category, _group_key(category, finding))
        bucket = buckets.setdefault(key, {"title": title, "findings": []})
        bucket["findings"].append(finding)

    path_by_rule = _reachable_paths_by_rule(analysis)
    boundaries_by_component = _boundaries_by_component(analysis)
    root_causes: list[RootCause] = []
    for (category, group), bucket in sorted(buckets.items()):
        findings = bucket["findings"]
        severity = max((f.severity for f in findings), key=lambda s: _SEVERITY_ORDER.index(s) if s in _SEVERITY_ORDER else 0)
        confidence = max((f.confidence for f in findings), key=lambda c: _CONFIDENCE_SCORE.get(c, 0))
        components = sorted({f.component for f in findings if f.component})
        deps = sorted({f.component for f in findings if f.category == "cve" and f.component})
        rules = sorted({f.rule_id for f in findings})
        paths = []
        for f in findings:
            paths.extend(path_by_rule.get(f.rule_id, []))
        boundaries = sorted({b for c in components for b in boundaries_by_component.get(c, [])})
        identifier = "RC-" + category + "-" + hashlib.sha256(
            f"{analysis.apk_sha256}|{category}|{group}".encode()).hexdigest()[:10]

        rc = RootCause(
            identifier=identifier, category=category, title=bucket["title"],
            description=_describe(category, findings, paths, boundaries),
            severity=severity, confidence=confidence,
            severity_score=_SEVERITY_SCORE.get(severity, 10),
            confidence_score=_CONFIDENCE_SCORE.get(confidence, 30),
            affected_components=components, affected_dependencies=deps,
            affected_code_nodes=sorted({e.location for f in findings for e in f.evidence if e.location})[:20],
            boundaries=boundaries, paths=paths[:10])
        for f in findings:
            rc.findings.append(RootCauseFinding(finding_id=f.id, rule_id=f.rule_id))
            f.root_cause_id = None  # set after flush via relationship below
        rc.evidence.append(RootCauseEvidence(kind="rules", detail=f"supporting rules: {', '.join(rules)}"))
        for path in paths[:3]:
            rc.evidence.append(RootCauseEvidence(kind="path", detail=" -> ".join(path.get("chain", []))))
        analysis.root_causes.append(rc)
        root_causes.append(rc)
        # link findings -> root cause (relationship, set after rc has identity)
        rc._member_findings = findings  # transient, resolved in orchestrator after flush
    return root_causes


def link_root_cause_findings(analysis) -> None:
    """Set finding.root_cause_id after root causes have PKs (call post-flush)."""
    for rc in analysis.root_causes:
        for finding in getattr(rc, "_member_findings", []):
            finding.root_cause_id = rc.id


def _describe(category: str, findings, paths, boundaries) -> str:
    n = len(findings)
    parts = [f"{n} supporting finding(s)"]
    if paths:
        parts.append(f"{len(paths)} reachable path(s)")
    if boundaries:
        parts.append(f"boundaries crossed: {', '.join(boundaries)}")
    return f"{category}: " + "; ".join(parts)


def _reachable_paths_by_rule(analysis) -> dict:
    by_rule: dict[str, list] = defaultdict(list)
    for path in analysis.reachability_paths:
        if path.rule_id:
            by_rule[path.rule_id].append(summarize_path(path))
    return by_rule


def _boundaries_by_component(analysis) -> dict:
    by_component: dict[str, list] = defaultdict(list)
    for boundary in analysis.security_boundaries:
        if boundary.component:
            by_component[boundary.component].append(boundary.boundary_type)
    return by_component


# ---------------------------------------------------------------------------
# Path summarization (Phase 7)
# ---------------------------------------------------------------------------


def summarize_path(path) -> dict:
    """Concise deterministic chain from a persisted reachability path, preserving
    UNKNOWN markers (native/IPC targets are never filled in)."""
    nodes = path.nodes or []
    chain = [n.get("label", "?") for n in nodes]
    note = None
    if nodes:
        terminal = nodes[-1]
        if terminal.get("type") == "NATIVE_FUNCTION":
            note = "UNKNOWN_NATIVE_TARGET"  # native call graph beyond the boundary is not resolved
    return {
        "status": path.status, "confidence": path.confidence, "length": path.length,
        "chain": chain, "note": note, "rule_id": path.rule_id,
    }

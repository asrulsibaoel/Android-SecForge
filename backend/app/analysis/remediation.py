"""Deterministic, evidence-backed remediation planning (prompt 17).

A remediation plan is a *projection* over the already-persisted analysis
evidence — findings, CVE matches, root causes, attack surface, reachability,
semantics, native/JNI, security boundaries, runtime observations. It never
mutates any source data or the canonical graph, never asserts exploitability,
never fabricates a fix, and preserves every uncertainty state verbatim
(UNKNOWN / POSSIBLY_AFFECTED / NOT_REACHABLE / NOT_OBSERVED / NO_LONGER_DETECTED).

Recommendations are review/fix *guidance*, not automatic patches. Priority is a
separate, documented axis from the risk engine. Two identical analyses produce
identical remediation output (stable content-derived fingerprints).

Complexity: each source is scanned once (O(findings + matches + boundaries +
attack-surface + ipc)); reachability reuses persisted paths. No N×M scans.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.models.remediation import (
    FIX_ARCH_REVIEW, FIX_CODE_REVIEW, FIX_CONDITIONAL, FIX_CONFIG_REVIEW, FIX_DIRECT,
    FIX_ENVIRONMENTAL, FIX_UNKNOWN,
    PRIORITY_CRITICAL, PRIORITY_HIGH, PRIORITY_INFO, PRIORITY_LOW, PRIORITY_MEDIUM, PRIORITY_UNDETERMINED,
    STATUS_CONDITIONALLY_RECOMMENDED, STATUS_INCONCLUSIVE, STATUS_NEW_REMEDIATION_REQUIRED,
    STATUS_NO_LONGER_DETECTED, STATUS_RECOMMENDED, STATUS_REMEDIATED, STATUS_REVIEW_REQUIRED,
    STATUS_VERSION_UNVERIFIED,
    RemediationAction, RemediationDependency, RemediationEvidence, RemediationItem, RemediationPlan,
)

# --- Actions (recommendations, NOT automatic fixes) ------------------------
A_UPDATE_DEPENDENCY = "UPDATE_DEPENDENCY"
A_REMOVE_DEPENDENCY = "REMOVE_DEPENDENCY"
A_REPLACE_DEPENDENCY = "REPLACE_DEPENDENCY"
A_VERIFY_DEPENDENCY_VERSION = "VERIFY_DEPENDENCY_VERSION"
A_REVIEW_DEPENDENCY = "REVIEW_DEPENDENCY_VERSION"
A_UPDATE_NATIVE_LIBRARY = "UPDATE_NATIVE_LIBRARY"
A_REVIEW_CODE_PATH = "REVIEW_CODE_PATH"
A_REVIEW_EXPORTED_COMPONENT = "REVIEW_EXPORTED_COMPONENT"
A_REVIEW_INTENT_INPUT = "REVIEW_INTENT_INPUT"
A_REVIEW_DEEP_LINK_INPUT = "REVIEW_DEEP_LINK_INPUT"
A_REVIEW_WEBVIEW_CONFIGURATION = "REVIEW_WEBVIEW_CONFIGURATION"
A_REVIEW_WEBVIEW_BRIDGE = "REVIEW_WEBVIEW_BRIDGE"
A_REVIEW_REFLECTION = "REVIEW_REFLECTION"
A_REVIEW_DYNAMIC_LOADING = "REVIEW_DYNAMIC_LOADING"
A_REVIEW_IPC_BOUNDARY = "REVIEW_IPC_BOUNDARY"
A_REVIEW_JNI_BOUNDARY = "REVIEW_NATIVE_JNI_BOUNDARY"
A_REVIEW_NATIVE_API_USAGE = "REVIEW_NATIVE_API_USAGE"
A_REVIEW_TLS_CONFIGURATION = "REVIEW_TLS_CONFIGURATION"
A_REVIEW_CRYPTO_CONFIGURATION = "REVIEW_CRYPTO_CONFIGURATION"
A_REVIEW_STORAGE = "REVIEW_STORAGE"
A_REVIEW_PROCESS_EXECUTION_PATH = "REVIEW_PROCESS_EXECUTION_PATH"
A_REMOVE_HARDCODED_SECRET = "REMOVE_HARDCODED_SECRET"
A_REVIEW_RUNTIME_BEHAVIOR = "REVIEW_RUNTIME_BEHAVIOR"

# --- Documented priority weights (separate axis from the risk engine) ------
PRIORITY_WEIGHTS = {
    "affected_reachable": 40,
    "affected_present": 25,
    "possibly_affected": 12,
    "identity_confirmed": 10,        # EXACT/HIGH identity match
    "reachable": 15,
    "not_reachable": -10,
    "external_exposure": 15,         # exported component / PUBLIC attack surface
    "fixed_version_available": 8,
    "kev_known_exploited": 20,       # external intelligence signal
    "epss_high": 10,                 # external intelligence signal
    "runtime_corroborated": 12,
    "native_jni_boundary": 6,
    "root_cause_critical": 15,
    "root_cause_high": 10,
    "confirmed_static_finding": 12,
    "finding_high_severity": 10,
    "finding_medium_severity": 5,
    "finding_low_severity": 2,
    "unknown_native_target": 0,      # neutral — uncertainty is never inflated
}
EPSS_HIGH_THRESHOLD = 0.5
# Score -> band thresholds (documented; deterministic).
_BANDS = [(70, PRIORITY_CRITICAL), (45, PRIORITY_HIGH), (25, PRIORITY_MEDIUM), (10, PRIORITY_LOW), (1, PRIORITY_INFO)]

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class RItem:
    action: str
    status: str
    fixability: str
    source_category: str
    target: str | None
    target_type: str
    title: str
    description: str
    current_state: str | None = None
    recommended_state: str | None = None
    confidence: str = "MEDIUM"
    uncertainties: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)
    factors: list[dict] = field(default_factory=list)
    priority_score: int = 0
    priority: str = PRIORITY_UNDETERMINED
    prereqs: list[str] = field(default_factory=list)  # fingerprints of prerequisite items

    @property
    def fingerprint(self) -> str:
        raw = f"{self.action}|{self.target_type}|{(self.target or '').lower()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Priority scoring (documented, deterministic, separate from risk)
# ---------------------------------------------------------------------------


def _factor(item: RItem, name: str, reason: str) -> None:
    weight = PRIORITY_WEIGHTS[name]
    item.factors.append({"name": name, "weight": weight, "reason": reason})


def _finalize_priority(item: RItem) -> None:
    score = sum(f["weight"] for f in item.factors)
    item.priority_score = max(0, score)
    if item.status in (STATUS_VERSION_UNVERIFIED,) and item.priority_score <= 0:
        item.priority = PRIORITY_UNDETERMINED
        return
    for threshold, band in _BANDS:
        if item.priority_score >= threshold:
            item.priority = band
            return
    item.priority = PRIORITY_UNDETERMINED if item.status in (STATUS_VERSION_UNVERIFIED, STATUS_REVIEW_REQUIRED) \
        else PRIORITY_INFO


def _runtime_evidence_tag(finding) -> str:
    vs = getattr(finding, "validation_state", None)
    rs = getattr(finding, "runtime_status", None)
    # Prompt-21 LIVE runtime-validation axis takes precedence when present. Only a
    # genuinely LIVE observation corroborates; MOCKED/inconclusive never does, and
    # runtime corroboration NEVER marks a remediation REMEDIATED on its own.
    rvs = getattr(finding, "runtime_validation_state", None)
    if rvs in ("CONFIRMED_RUNTIME_BEHAVIOR", "RUNTIME_CORROBORATED"):
        return "RUNTIME_CORROBORATED"
    if rvs == "NOT_OBSERVED":
        return "RUNTIME_NOT_OBSERVED"
    if rs in ("STATIC_RUNTIME_CONFIRMED", "RUNTIME_SUPPORTS_STATIC_PATH") or vs == "OBSERVED":
        return "RUNTIME_CORROBORATED"
    if vs == "NOT_OBSERVED":
        return "RUNTIME_NOT_OBSERVED"
    if vs in (None, "NOT_RUN"):
        return "RUNTIME_UNAVAILABLE"
    return "STATIC_ONLY"


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------


def _reachable_components(analysis) -> set[str]:
    return {p.from_label for p in analysis.reachability_paths if p.status == "REACHABLE"}


def _public_components(analysis) -> set[str]:
    return {n.component for n in analysis.attack_surface_nodes if n.exposure == "PUBLIC" and n.component}


def _cve_items(analysis) -> list[RItem]:
    out: list[RItem] = []
    reachable_states = {"AFFECTED_REACHABLE"}
    for m in analysis.vulnerability_matches:
        dep = m.dependency
        vuln = getattr(m, "vulnerability", None)
        fixed = m.earliest_fixed_version
        is_native = dep.kind == "native"
        # NOT_AFFECTED -> no remediation (do not emit).
        if m.version_state == "NOT_AFFECTED":
            continue

        if m.version_state == "AFFECTED":
            if fixed:
                action = A_UPDATE_NATIVE_LIBRARY if is_native else A_UPDATE_DEPENDENCY
                status = STATUS_RECOMMENDED
                fixability = FIX_DIRECT
                recommended = f">= {fixed}"
                actions = [{"order": 1, "action": action, "target": dep.name, "recommended_state": recommended,
                            "detail": f"Update {dep.name} to a fixed version ({recommended})."}]
                title = f"Update {dep.name} to a fixed version ({recommended})"
            else:
                action = A_REVIEW_DEPENDENCY
                status = STATUS_REVIEW_REQUIRED
                fixability = FIX_UNKNOWN
                recommended = None
                actions = [{"order": 1, "action": action, "target": dep.name, "recommended_state": None,
                            "detail": "Affected version detected but no fixed version was supplied by the "
                                      "intelligence source; review upstream advisories."}]
                title = f"Review {dep.name}: affected, no fixed version supplied"
        elif m.version_state == "POSSIBLY_AFFECTED":
            # version unknown -> NEVER assert AFFECTED
            action = A_VERIFY_DEPENDENCY_VERSION
            status = STATUS_CONDITIONALLY_RECOMMENDED if fixed else STATUS_VERSION_UNVERIFIED
            fixability = FIX_CONDITIONAL
            recommended = (f">= {fixed} (only after confirming the bundled version)") if fixed else None
            actions = [{"order": 1, "action": A_VERIFY_DEPENDENCY_VERSION, "target": dep.name,
                        "recommended_state": None,
                        "detail": "The dependency identity matches vulnerability intelligence, but the installed "
                                  "version could not be recovered from available APK metadata."}]
            if fixed:
                actions.append({"order": 2, "action": (A_UPDATE_NATIVE_LIBRARY if is_native else A_UPDATE_DEPENDENCY),
                                "target": dep.name, "recommended_state": recommended,
                                "detail": f"If the bundled version is < {fixed}, upgrade to >= {fixed}."})
            title = f"Verify {dep.name} version (identity matches {m.cve_id}; version unverified)"
        else:  # UNKNOWN
            action = A_REVIEW_DEPENDENCY
            status = STATUS_VERSION_UNVERIFIED
            fixability = FIX_CONDITIONAL
            recommended = None
            actions = [{"order": 1, "action": A_REVIEW_DEPENDENCY, "target": dep.name, "recommended_state": None,
                        "detail": "Version match is UNKNOWN (unparseable/absent); review manually."}]
            title = f"Review {dep.name} ({m.cve_id}; version state UNKNOWN)"

        item = RItem(action=action, status=status, fixability=fixability, source_category="cve",
                     target=dep.name, target_type="NATIVE_LIBRARY" if is_native else "DEPENDENCY",
                     title=title, description=_cve_description(m, dep, fixed),
                     current_state=f"version={dep.version or 'UNKNOWN'} ({m.version_state})",
                     recommended_state=recommended, confidence=m.identity_confidence, actions=actions)
        # evidence
        item.evidence.append({"source_type": "CVE", "source_id": m.cve_id, "confidence": m.identity_confidence,
                              "detail": f"{m.cve_id} version_state={m.version_state} "
                                        f"correlation={m.correlation_state} reachability={m.reachability_state}",
                              "evidence_json": {"cve_id": m.cve_id, "version_state": m.version_state,
                                                "correlation_state": m.correlation_state,
                                                "reachability_state": m.reachability_state,
                                                "signature_state": m.signature_state,
                                                "identity_confidence": m.identity_confidence,
                                                "fixed_versions": m.fixed_versions}})
        item.evidence.append({"source_type": "DEPENDENCY", "source_id": dep.name, "confidence": dep.identity_confidence,
                              "detail": f"{dep.name} ({dep.ecosystem}/{dep.kind}) version={dep.version or 'UNKNOWN'} "
                                        f"version_source={dep.version_source or 'UNKNOWN'}",
                              "evidence_json": {"version_source": dep.version_source,
                                                "version_confidence": dep.version_confidence}})
        # uncertainties
        if m.version_state == "POSSIBLY_AFFECTED":
            item.uncertainties.append("installed version could not be recovered; AFFECTED is not asserted")
        if m.reachability_state == "UNKNOWN":
            item.uncertainties.append("reachability of the vulnerable code is UNKNOWN")
        # factors
        if m.correlation_state == "AFFECTED_REACHABLE":
            _factor(item, "affected_reachable", "affected dependency with reachable vulnerable code")
        elif m.correlation_state in ("PRESENT_AFFECTED", "AFFECTED_NOT_REACHABLE"):
            _factor(item, "affected_present", f"affected dependency ({m.correlation_state})")
        elif m.version_state == "POSSIBLY_AFFECTED":
            _factor(item, "possibly_affected", "identity matches; version unverified")
        if m.identity_confidence in ("EXACT", "HIGH"):
            _factor(item, "identity_confirmed", f"identity confidence {m.identity_confidence}")
        if m.reachability_state == "REACHABLE":
            _factor(item, "reachable", "vulnerable code reachable from an entry point")
        elif m.reachability_state == "NOT_REACHABLE":
            _factor(item, "not_reachable", "vulnerable code not reachable")
        if fixed:
            _factor(item, "fixed_version_available", f"fixed version available (>= {fixed})")
        if vuln is not None and getattr(vuln, "known_exploited", False):
            _factor(item, "kev_known_exploited", "external intelligence: CVE marked known-exploited (KEV)")
        if vuln is not None and (getattr(vuln, "epss_score", None) or 0) >= EPSS_HIGH_THRESHOLD:
            _factor(item, "epss_high", f"external intelligence: EPSS >= {EPSS_HIGH_THRESHOLD}")
        out.append(item)
    return out


def _cve_description(m, dep, fixed) -> str:
    if m.version_state == "AFFECTED" and fixed:
        return (f"Dependency {dep.name} matches {m.cve_id} and the installed version {dep.version} falls in the "
                f"affected range. A fixed version (>= {fixed}) exists; updating is recommended.")
    if m.version_state == "POSSIBLY_AFFECTED":
        base = (f"Dependency {dep.name} identity matches {m.cve_id} (confidence {m.identity_confidence}), but the "
                f"installed version could not be recovered from APK metadata, so AFFECTED is not asserted.")
        return base + (f" A fixed version (>= {fixed}) exists — upgrade conditionally after confirming the bundled "
                       f"version." if fixed else "")
    return f"Dependency {dep.name} correlates with {m.cve_id} (state {m.version_state}/{m.correlation_state})."


_FINDING_ACTION = {
    "ANDROID-WEBVIEW-001": (A_REVIEW_WEBVIEW_CONFIGURATION, FIX_CONFIG_REVIEW, "WEBVIEW"),
    "ANDROID-WEBVIEW-002": (A_REVIEW_WEBVIEW_BRIDGE, FIX_CODE_REVIEW, "WEBVIEW"),
    "ANDROID-CRYPTO-001": (A_REVIEW_CRYPTO_CONFIGURATION, FIX_CONFIG_REVIEW, "CODE_PATH"),
    "ANDROID-TLS-001": (A_REVIEW_TLS_CONFIGURATION, FIX_CONFIG_REVIEW, "CODE_PATH"),
    "ANDROID-TLS-002": (A_REVIEW_TLS_CONFIGURATION, FIX_CONFIG_REVIEW, "CODE_PATH"),
    "ANDROID-SECRET-001": (A_REMOVE_HARDCODED_SECRET, FIX_CODE_REVIEW, "CODE_PATH"),
    "ANDROID-MANIFEST-003": (A_REVIEW_TLS_CONFIGURATION, FIX_CONFIG_REVIEW, "MANIFEST"),
    "ANDROID-COMPONENT-001": (A_REVIEW_EXPORTED_COMPONENT, FIX_CONFIG_REVIEW, "COMPONENT"),
    "ANDROID-REACH-002": (A_REVIEW_PROCESS_EXECUTION_PATH, FIX_CODE_REVIEW, "CODE_PATH"),
    "ANDROID-REACH-003": (A_REVIEW_JNI_BOUNDARY, FIX_CODE_REVIEW, "JNI_BINDING"),
    "ANDROID-SEMANTIC-001": (A_REVIEW_INTENT_INPUT, FIX_CODE_REVIEW, "COMPONENT"),
    "ANDROID-SEMANTIC-002": (A_REVIEW_DEEP_LINK_INPUT, FIX_CODE_REVIEW, "DEEP_LINK"),
    "ANDROID-SEMANTIC-003": (A_REVIEW_IPC_BOUNDARY, FIX_ARCH_REVIEW, "IPC"),
    "ANDROID-SEMANTIC-004": (A_REVIEW_WEBVIEW_BRIDGE, FIX_CODE_REVIEW, "WEBVIEW"),
    "ANDROID-SEMANTIC-005": (A_REVIEW_DYNAMIC_LOADING, FIX_CODE_REVIEW, "CODE_PATH"),
}


def _finding_action(finding) -> tuple[str, str, str]:
    rid = finding.rule_id
    if rid in _FINDING_ACTION:
        return _FINDING_ACTION[rid]
    text = " ".join([finding.title or ""] + [e.detail or "" for e in finding.evidence]).lower()
    if rid == "ANDROID-REACH-001" or finding.category == "reachability":
        if "class.forname" in text or "reflect" in text:
            return A_REVIEW_REFLECTION, FIX_CODE_REVIEW, "CODE_PATH"
        if "runtime.exec" in text or "processbuilder" in text or "exec" in text:
            return A_REVIEW_PROCESS_EXECUTION_PATH, FIX_CODE_REVIEW, "CODE_PATH"
        if "jni" in text or "native" in text:
            return A_REVIEW_JNI_BOUNDARY, FIX_CODE_REVIEW, "JNI_BINDING"
        return A_REVIEW_CODE_PATH, FIX_CODE_REVIEW, "CODE_PATH"
    if finding.category == "native" or rid.startswith("ASF-NATIVE-"):
        return A_REVIEW_NATIVE_API_USAGE, FIX_CODE_REVIEW, "NATIVE_LIBRARY"
    if finding.category == "webview":
        return A_REVIEW_WEBVIEW_CONFIGURATION, FIX_CONFIG_REVIEW, "WEBVIEW"
    if finding.category == "semantic":
        return A_REVIEW_CODE_PATH, FIX_CODE_REVIEW, "CODE_PATH"
    return A_REVIEW_CODE_PATH, FIX_CODE_REVIEW, "CODE_PATH"


def _finding_items(analysis) -> list[RItem]:
    reachable = _reachable_components(analysis)
    public = _public_components(analysis)
    rc_by_id = {rc.id: rc for rc in analysis.root_causes}
    out: list[RItem] = []
    for f in analysis.findings:
        if f.is_duplicate:
            continue
        if f.category == "cve":
            continue  # dependency remediation handles CVE matches (richer evidence)
        action, fixability, target_type = _finding_action(f)
        target = f.component or f.primary_target or f.rule_id
        item = RItem(action=action, status=STATUS_REVIEW_REQUIRED, fixability=fixability,
                     source_category="finding", target=target, target_type=target_type,
                     title=f"{_action_title(action)}: {f.rule_id}",
                     description=f.description or f.title,
                     current_state=f"finding {f.rule_id} [{f.severity}/{f.confidence}] status={f.status}",
                     recommended_state="review the flagged code/configuration and constrain untrusted input",
                     confidence=(f.confidence or "medium").upper())
        # evidence: the finding + its evidence chain + root cause
        item.evidence.append({"source_type": "FINDING", "source_id": f.fingerprint or f.rule_id,
                              "confidence": (f.confidence or "medium").upper(),
                              "detail": f"{f.rule_id}: {f.title} @ {f.component or '-'}",
                              "evidence_json": {"rule_id": f.rule_id, "severity": f.severity, "status": f.status,
                                                "category": f.category}})
        for e in f.evidence[:6]:
            item.evidence.append({"source_type": "CODE", "source_id": e.location,
                                  "confidence": (f.confidence or "medium").upper(),
                                  "detail": e.detail,
                                  "evidence_json": {"source": e.source, "class": e.class_name,
                                                    "method": e.method_name, "line": e.line}})
        if f.root_cause_id and f.root_cause_id in rc_by_id:
            rc = rc_by_id[f.root_cause_id]
            item.evidence.append({"source_type": "ROOT_CAUSE", "source_id": rc.identifier, "confidence": rc.confidence,
                                  "detail": f"root cause {rc.identifier} ({rc.category}, {rc.severity})",
                                  "evidence_json": {"category": rc.category, "severity": rc.severity}})
        # runtime corroboration (never downgrades static truth)
        rt = _runtime_evidence_tag(f)
        item.evidence.append({"source_type": "RUNTIME", "source_id": None, "confidence": "MEDIUM",
                              "detail": rt, "evidence_json": {"validation_state": f.validation_state,
                                                              "runtime_status": f.runtime_status}})
        item.actions.append({"order": 1, "action": action, "target": target, "recommended_state": None,
                             "detail": item.recommended_state})
        # factors
        sev = _SEV_RANK.get((f.severity or "info").lower(), 0)
        if f.status == "CONFIRMED_BY_STATIC_ANALYSIS":
            _factor(item, "confirmed_static_finding", "confirmed by static analysis")
        if sev >= 3:
            _factor(item, "finding_high_severity", f"{f.severity} severity finding")
        elif sev == 2:
            _factor(item, "finding_medium_severity", f"{f.severity} severity finding")
        elif sev >= 0:
            _factor(item, "finding_low_severity", f"{f.severity} severity finding")
        if target in reachable or (f.component and any(f.component.rsplit('.', 1)[-1] in r for r in reachable)):
            _factor(item, "reachable", "component/path is reachable")
        if f.component in public:
            _factor(item, "external_exposure", "component is a PUBLIC attack-surface node")
        if rt == "RUNTIME_CORROBORATED":
            _factor(item, "runtime_corroborated", "corroborated by a runtime observation")
        if target_type in ("JNI_BINDING", "NATIVE_LIBRARY"):
            _factor(item, "native_jni_boundary", "involves a native/JNI boundary")
        if rt == "RUNTIME_NOT_OBSERVED":
            item.uncertainties.append("runtime instrumentation did not observe this — NOT_OBSERVED is not SAFE")
        out.append(item)
    return out


def _attack_surface_items(analysis) -> list[RItem]:
    """Exported components that carry a security finding OR a boundary."""
    finding_components = {f.component for f in analysis.findings if f.component and not f.is_duplicate}
    boundary_components = {b.component for b in analysis.security_boundaries if b.component}
    out: list[RItem] = []
    for n in analysis.attack_surface_nodes:
        if n.exposure != "PUBLIC" or not n.component:
            continue
        if n.component not in finding_components and n.component not in boundary_components:
            continue
        item = RItem(action=A_REVIEW_EXPORTED_COMPONENT, status=STATUS_REVIEW_REQUIRED,
                     fixability=FIX_ARCH_REVIEW, source_category="attack_surface", target=n.component,
                     target_type="COMPONENT",
                     title=f"Review exported component {n.component}",
                     description=("Review whether this component must remain externally accessible. If external "
                                  "exposure is unnecessary, restrict or disable its export."),
                     current_state=f"exposure={n.exposure} risk_score={n.risk_score}",
                     recommended_state="restrict export / add permission guard if external access is unnecessary",
                     confidence="HIGH")
        item.evidence.append({"source_type": "ATTACK_SURFACE", "source_id": n.node_key, "confidence": "HIGH",
                              "detail": f"{n.name} exposure={n.exposure} risk={n.risk_score}",
                              "evidence_json": {"exposure": n.exposure, "risk_score": n.risk_score}})
        _factor(item, "external_exposure", "PUBLIC exported attack-surface node")
        if n.component in {p.from_label for p in analysis.reachability_paths if p.status == "REACHABLE"}:
            _factor(item, "reachable", "reachable from an entry point")
        out.append(item)
    return out


def _ipc_items(analysis) -> list[RItem]:
    out: list[RItem] = []
    for t in analysis.ipc_transactions:
        target = t.class_name or t.interface_name or "IPC"
        item = RItem(action=A_REVIEW_IPC_BOUNDARY, status=STATUS_REVIEW_REQUIRED, fixability=FIX_ARCH_REVIEW,
                     source_category="semantic", target=target, target_type="IPC",
                     title=f"Review IPC/Binder boundary at {target}",
                     description=("Binder/IPC support is partial; the transaction target could not be resolved. "
                                  "Review the boundary manually — the target is UNKNOWN and is not inferred."),
                     current_state=f"kind={t.kind} transaction_code={t.transaction_code} target=UNKNOWN",
                     recommended_state="validate caller identity/permissions at the Binder boundary",
                     confidence=t.confidence)
        item.evidence.append({"source_type": "IPC", "source_id": target, "confidence": t.confidence,
                              "detail": f"{t.kind} {target}.{t.method_name or ''} code={t.transaction_code} "
                                        f"target=UNKNOWN",
                              "evidence_json": {"kind": t.kind, "transaction_code": t.transaction_code,
                                                "target_status": "UNKNOWN"}})
        item.uncertainties.append("Binder transaction target is UNKNOWN and is never inferred")
        _factor(item, "finding_low_severity", "IPC boundary requires review")
        out.append(item)
    return out


def _jni_items(analysis) -> list[RItem]:
    out: list[RItem] = []
    for b in analysis.security_boundaries:
        if (b.boundary_type or "").upper() != "JNI":
            continue
        target = b.component or b.node_key
        item = RItem(action=A_REVIEW_JNI_BOUNDARY, status=STATUS_REVIEW_REQUIRED, fixability=FIX_CODE_REVIEW,
                     source_category="native", target=target, target_type="JNI_BINDING",
                     title=f"Review native/JNI boundary at {target}",
                     description=("A JNI boundary crosses into native code. Downstream native reachability is not "
                                  "modeled without Ghidra; the native target remains UNKNOWN_NATIVE_TARGET. Review "
                                  "input validation at the boundary rather than asserting a vulnerable native path."),
                     current_state="JNI boundary present; native target UNKNOWN_NATIVE_TARGET",
                     recommended_state="review argument validation at the Java↔native boundary",
                     confidence=b.confidence)
        item.evidence.append({"source_type": "SECURITY_BOUNDARY", "source_id": b.node_key, "confidence": b.confidence,
                              "detail": f"JNI boundary {target}", "evidence_json": {"boundary_type": "JNI",
                                                                                    "native_target": "UNKNOWN_NATIVE_TARGET"}})
        item.uncertainties.append("UNKNOWN_NATIVE_TARGET preserved — native reachability is not modeled")
        _factor(item, "native_jni_boundary", "Java↔native boundary present")
        out.append(item)
    return out


def _native_deep_items(analysis) -> list[RItem]:
    """Recommendation-only review items backed by persisted deep-native evidence
    (prompt 20). Guarded: only when a native-deep run exists. Never asserts a
    vulnerable/exploitable native path; UNKNOWN_NATIVE_TARGET stays preserved.
    Distinct target_type keeps these from silently mutating existing JNI items."""
    if not analysis.native_analysis_runs:
        return []
    from app.core.config import settings
    from app.native.deep_native import API_REACHED
    out: list[RItem] = []
    fn_by_fp = {f.fingerprint: f for f in analysis.native_deep_functions}

    for j in list(analysis.native_deep_jni_bindings)[: settings.native_max_jni_bindings]:
        if j.state != "RESOLVED" or not j.native_symbol:
            continue
        target = f"{j.java_class}.{j.java_method}"
        item = RItem(action=A_REVIEW_JNI_BOUNDARY, status=STATUS_REVIEW_REQUIRED, fixability=FIX_CODE_REVIEW,
                     source_category="native", target=target, target_type="NATIVE_DEEP_JNI",
                     title=f"Review resolved native/JNI binding {target}",
                     description=("Deep-native correlation resolved this JNI binding to a native symbol. A resolved "
                                  "binding is not evidence that the native code is vulnerable or reachable from an "
                                  "attacker; review argument handling at the boundary."),
                     current_state=f"JNI {target} → {j.native_symbol} [{j.registration_type}] (RESOLVED)",
                     recommended_state="review argument validation across the resolved Java↔native boundary",
                     confidence=j.confidence)
        item.evidence.append({"source_type": "GHIDRA" if j.source == "GHIDRA" else "JNI", "source_id": j.native_symbol,
                              "confidence": j.confidence, "detail": f"JNI {target} resolved to {j.native_symbol}",
                              "evidence_json": {"registration_type": j.registration_type, "state": j.state}})
        _factor(item, "native_jni_boundary", "resolved Java↔native boundary present")
        out.append(item)

    for o in list(analysis.native_api_observations)[: settings.native_max_path_results]:
        if o.state != API_REACHED:
            continue
        fn = fn_by_fp.get(o.function_fp) if o.function_fp else None
        target = f"{o.api}@{fn.name if fn else '?'}"
        item = RItem(action=A_REVIEW_NATIVE_API_USAGE, status=STATUS_REVIEW_REQUIRED, fixability=FIX_CODE_REVIEW,
                     source_category="native", target=target, target_type="NATIVE_DEEP_API",
                     title=f"Review native API usage {o.api} reached via call chain",
                     description=("A Ghidra call chain reaches this native API. Reachability within native code is not "
                                  "the same as attacker-reachability or a vulnerability; review how inputs flow to "
                                  "this API. No exploitability is asserted."),
                     current_state=f"native API {o.api} ({o.category}) NATIVE_CALL_CHAIN_REACHES_API",
                     recommended_state="review input handling reaching this native API",
                     confidence=o.confidence)
        item.evidence.append({"source_type": "GHIDRA", "source_id": o.api, "confidence": o.confidence,
                              "detail": f"native call chain reaches {o.api}",
                              "evidence_json": {"category": o.category, "state": o.state}})
        item.uncertainties.append("native reachability ≠ attacker-reachability; no exploitability asserted")
        _factor(item, "native_jni_boundary", "native API reachable within native code (recommendation only)")
        out.append(item)

    return out


def _action_title(action: str) -> str:
    return action.replace("_", " ").title()


# ---------------------------------------------------------------------------
# Assembly + dedup + priority
# ---------------------------------------------------------------------------


def build_items(analysis) -> list[RItem]:
    """Deterministic list of remediation items (pure — no persistence)."""
    generated: list[RItem] = []
    generated += _cve_items(analysis)
    generated += _finding_items(analysis)
    generated += _attack_surface_items(analysis)
    generated += _ipc_items(analysis)
    generated += _jni_items(analysis)
    generated += _native_deep_items(analysis)

    # Deterministic dedup+merge by fingerprint (CASE 18: duplicate findings -> one item).
    merged: dict[str, RItem] = {}
    for item in generated:
        fp = item.fingerprint
        if fp in merged:
            _merge(merged[fp], item)
        else:
            merged[fp] = item
    items = list(merged.values())
    for item in items:
        _dedup_evidence(item)
        _finalize_priority(item)
    _link_dependencies(items)
    # Deterministic ordering: priority desc, then fingerprint.
    order = {PRIORITY_CRITICAL: 0, PRIORITY_HIGH: 1, PRIORITY_MEDIUM: 2, PRIORITY_LOW: 3,
             PRIORITY_INFO: 4, PRIORITY_UNDETERMINED: 5}
    items.sort(key=lambda i: (order.get(i.priority, 9), -i.priority_score, i.fingerprint))
    return items


# Status precedence for deterministic merge (higher = more actionable/informative).
_STATUS_RANK = {STATUS_REVIEW_REQUIRED: 0, STATUS_VERSION_UNVERIFIED: 1, STATUS_INCONCLUSIVE: 1,
                STATUS_CONDITIONALLY_RECOMMENDED: 2, STATUS_RECOMMENDED: 3}
_FIX_RANK = {FIX_UNKNOWN: 0, FIX_ENVIRONMENTAL: 1, FIX_ARCH_REVIEW: 2, FIX_CONFIG_REVIEW: 3,
             FIX_CODE_REVIEW: 3, FIX_CONDITIONAL: 4, FIX_DIRECT: 5}


def _merge(base: RItem, other: RItem) -> None:
    base.evidence.extend(other.evidence)
    base.actions.extend(other.actions)
    if other.uncertainties:
        base.uncertainties.extend(u for u in other.uncertainties if u not in base.uncertainties)
    for f in other.factors:
        if f["name"] not in {x["name"] for x in base.factors}:
            base.factors.append(f)
    # Adopt the more-informative status/fixability/recommended_state deterministically
    # (e.g. a CVE match with a fixed version outranks one without). Never weaken.
    if _STATUS_RANK.get(other.status, 0) > _STATUS_RANK.get(base.status, 0):
        base.status = other.status
        base.recommended_state = other.recommended_state or base.recommended_state
        base.title = other.title
        base.description = other.description
    if _FIX_RANK.get(other.fixability, 0) > _FIX_RANK.get(base.fixability, 0):
        base.fixability = other.fixability


def _dedup_evidence(item: RItem) -> None:
    seen, out = set(), []
    for e in item.evidence:
        key = (e["source_type"], e.get("source_id"), e["detail"])
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    item.evidence = out
    # stable action ordering
    item.actions.sort(key=lambda a: (a.get("order", 0), a.get("action", "")))


def _link_dependencies(items: list[RItem]) -> None:
    """A conditional dependency update is a prerequisite chain: VERIFY then UPDATE
    (represented as ordered actions inside the item). Cross-item prerequisites:
    an exported-component review precedes the input/reflection reviews on the
    same component."""
    by_component_reviews: dict[str, list[RItem]] = {}
    exported: dict[str, RItem] = {}
    for it in items:
        if it.action == A_REVIEW_EXPORTED_COMPONENT and it.target:
            exported[it.target] = it
    for it in items:
        if it.target and it.action in (A_REVIEW_INTENT_INPUT, A_REVIEW_DEEP_LINK_INPUT, A_REVIEW_REFLECTION,
                                       A_REVIEW_WEBVIEW_BRIDGE) and it.target in exported:
            it.prereqs.append(exported[it.target].fingerprint)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def build_plan(db, analysis, requested_by: str = "cli") -> RemediationPlan:
    """Build and persist a remediation plan. Read-only over source evidence."""
    items = build_items(analysis)
    from collections import Counter
    dist = Counter(i.priority for i in items)
    plan_fp = hashlib.sha256("|".join(sorted(i.fingerprint for i in items)).encode()).hexdigest()[:32]
    plan = RemediationPlan(
        analysis_id=analysis.id, fingerprint=plan_fp, status="COMPLETE", item_count=len(items),
        requested_by=requested_by, created_at=_now(), priority_distribution=dict(dist),
        summary=_summary(items))
    analysis.remediation_plans.append(plan)
    db.flush()

    fp_to_row: dict[str, RemediationItem] = {}
    for it in items:
        row = RemediationItem(
            plan_id=plan.id, analysis_id=analysis.id, fingerprint=it.fingerprint, action=it.action,
            status=it.status, priority=it.priority, priority_score=it.priority_score, fixability=it.fixability,
            source_category=it.source_category, target=it.target, target_type=it.target_type, title=it.title,
            description=it.description, current_state=it.current_state, recommended_state=it.recommended_state,
            confidence=it.confidence, uncertainties=it.uncertainties, priority_factors=it.factors)
        plan.items.append(row)
        for e in it.evidence:
            row.evidence.append(RemediationEvidence(
                source_type=e["source_type"], source_id=e.get("source_id"), confidence=e.get("confidence", "MEDIUM"),
                detail=e.get("detail", ""), evidence_json=e.get("evidence_json", {}), timestamp=_now()))
        for a in it.actions:
            row.actions.append(RemediationAction(order=a.get("order", 0), action=a["action"],
                                                 target=a.get("target"), recommended_state=a.get("recommended_state"),
                                                 detail=a.get("detail", "")))
        fp_to_row[it.fingerprint] = row
    db.flush()
    for it in items:
        for prereq_fp in it.prereqs:
            if prereq_fp in fp_to_row and prereq_fp != it.fingerprint:
                plan.dependencies.append(RemediationDependency(
                    from_item_id=fp_to_row[it.fingerprint].id, to_item_id=fp_to_row[prereq_fp].id,
                    relation="BLOCKED_BY"))
    db.flush()
    return plan


def _summary(items: list[RItem]) -> dict:
    from collections import Counter
    return {
        "total": len(items),
        "by_priority": dict(Counter(i.priority for i in items)),
        "by_status": dict(Counter(i.status for i in items)),
        "by_action": dict(Counter(i.action for i in items)),
        "by_fixability": dict(Counter(i.fixability for i in items)),
        "version_unverified": sum(1 for i in items if i.status == STATUS_VERSION_UNVERIFIED),
        "conditional": sum(1 for i in items if i.status == STATUS_CONDITIONALLY_RECOMMENDED),
        "recommended": sum(1 for i in items if i.status == STATUS_RECOMMENDED),
        "uncertainties": sorted({u for i in items for u in i.uncertainties}),
    }


def item_to_dict(it: RItem) -> dict:
    return {
        "id": it.fingerprint, "fingerprint": it.fingerprint, "status": it.status, "priority": it.priority,
        "priority_score": it.priority_score, "action": it.action, "fixability": it.fixability,
        "title": it.title, "description": it.description, "target": it.target, "target_type": it.target_type,
        "current_state": it.current_state, "recommended_state": it.recommended_state,
        "confidence": it.confidence, "source_category": it.source_category,
        "evidence": it.evidence, "actions": it.actions, "priority_factors": it.factors,
        "uncertainties": it.uncertainties, "prerequisites": it.prereqs,
    }


def plan_view(analysis) -> dict:
    """In-memory plan (no persistence) for the JSON report / read-only paths."""
    items = build_items(analysis)
    plan_fp = hashlib.sha256("|".join(sorted(i.fingerprint for i in items)).encode()).hexdigest()[:32]
    deps = [{"from": it.fingerprint, "to": p, "relation": "BLOCKED_BY"} for it in items for p in it.prereqs]
    return {
        "fingerprint": plan_fp,
        "summary": _summary(items),
        "priority_distribution": _summary(items)["by_priority"],
        "items": [item_to_dict(i) for i in items],
        "dependencies": deps,
        "uncertainties": _summary(items)["uncertainties"],
        "note": "Remediation priority is a separate axis from risk; no item asserts exploitability, and "
                "UNKNOWN/POSSIBLY_AFFECTED/NOT_REACHABLE/NOT_OBSERVED are preserved.",
    }


# ---------------------------------------------------------------------------
# Explanation engine
# ---------------------------------------------------------------------------


def explain_item(analysis, item) -> dict:
    """WHY_THIS_RECOMMENDATION_EXISTS — deterministic, evidence-attributed."""
    ev = {e.source_type if hasattr(e, "source_type") else e["source_type"]:
          (e.detail if hasattr(e, "detail") else e["detail"]) for e in _iter_ev(item)}
    action = item.action
    fixability = item.fixability
    status = item.status
    why: list[str] = []
    if "FINDING" in ev:
        why.append(f"A finding was reported: {ev['FINDING']}.")
    if "ROOT_CAUSE" in ev:
        why.append(f"It aggregates to {ev['ROOT_CAUSE']}.")
    if "CVE" in ev:
        why.append(f"Vulnerability intelligence: {ev['CVE']}.")
    if "DEPENDENCY" in ev:
        why.append(f"Dependency evidence: {ev['DEPENDENCY']}.")
    if "ATTACK_SURFACE" in ev:
        why.append(f"Attack surface: {ev['ATTACK_SURFACE']}.")
    if "IPC" in ev:
        why.append(f"IPC boundary: {ev['IPC']}.")
    if "SECURITY_BOUNDARY" in ev:
        why.append(f"Security boundary: {ev['SECURITY_BOUNDARY']}.")
    rt = ev.get("RUNTIME")
    if rt:
        why.append(f"Runtime evidence: {rt} (runtime never overwrites static truth).")
    why.append(f"Therefore the engine recommends {action} ({fixability}); status {status}.")
    uncertainties = list(item.uncertainties)
    return {
        "target": item.target, "action": action, "status": status, "priority": item.priority,
        "fixability": fixability, "confidence": item.confidence,
        "WHY_THIS_RECOMMENDATION_EXISTS": why,
        "evidence": [_ev_dict(e) for e in _iter_ev(item)],
        "priority_factors": _factors_of(item),
        "recommended_action": item.recommended_state,
        "uncertainties": uncertainties,
        "note": "This is remediation guidance, not an exploitability claim and not an automatic patch.",
    }


def _iter_ev(item):
    return item.evidence


def _ev_dict(e):
    if hasattr(e, "source_type"):
        return {"source_type": e.source_type, "source_id": e.source_id, "confidence": e.confidence,
                "detail": e.detail, "evidence_json": e.evidence_json}
    return e


def _factors_of(item):
    factors = item.priority_factors if hasattr(item, "priority_factors") else item.factors
    return factors


# ---------------------------------------------------------------------------
# Diff-aware remediation (on-the-fly; not persisted)
# ---------------------------------------------------------------------------


def remediation_from_diff(comparison) -> dict:
    """Map prompt-15 CVE/finding transitions to conservative remediation status.
    A removed CVE/finding is NEVER 'fixed' without positive evidence."""
    items: list[dict] = []
    for ch in comparison.changes:
        if ch.category != "cve":
            continue
        ev = ch.evidence or {}
        transition = ev.get("transition") or (",".join(ev.get("transitions", [])) if ev.get("transitions") else None)
        if ch.change_type == "ADDED":
            cand = ev
            status = STATUS_NEW_REMEDIATION_REQUIRED if cand.get("version_state") == "AFFECTED" else STATUS_INCONCLUSIVE
            items.append(_diff_item(ch, status, "NEW_MATCH", cand.get("version_state")))
        elif ch.change_type == "REMOVED":
            # removed match: only REMEDIATED with positive NOT_AFFECTED+version evidence (rare on removal).
            items.append(_diff_item(ch, STATUS_NO_LONGER_DETECTED, "REMOVED_MATCH", (ch.evidence or {}).get("version_state")))
        else:  # CHANGED
            base = (ev.get("baseline") or {})
            cand = (ev.get("candidate") or {})
            if base.get("version_state") == "AFFECTED" and cand.get("version_state") == "NOT_AFFECTED" \
                    and cand.get("installed_version"):
                status = STATUS_REMEDIATED  # proven: affected -> not-affected with positive version evidence
            elif cand.get("version_state") == "AFFECTED" and base.get("version_state") != "AFFECTED":
                status = STATUS_NEW_REMEDIATION_REQUIRED
            else:
                status = STATUS_INCONCLUSIVE
            items.append(_diff_item(ch, status, transition or "STATE_CHANGED", cand.get("version_state")))

    for f in comparison.finding_changes:
        if f.change_type == "REMOVED":
            items.append({"target": f"{f.rule_id}@{f.component or '-'}", "status": STATUS_NO_LONGER_DETECTED,
                          "transition": "REMOVED", "detail": "finding no longer detected — not proven remediated",
                          "security_relevant": f.security_relevant})
        elif f.change_type == "ADDED":
            items.append({"target": f"{f.rule_id}@{f.component or '-'}", "status": STATUS_NEW_REMEDIATION_REQUIRED,
                          "transition": "NEW", "detail": "new finding in candidate", "security_relevant": f.security_relevant})
    from collections import Counter
    return {"items": items, "summary": dict(Counter(i["status"] for i in items)),
            "note": "A removed CVE/finding is NO_LONGER_DETECTED, not 'fixed', unless a transition proves it."}


def _diff_item(ch, status, transition, version_state) -> dict:
    return {"target": ch.entity_identity, "status": status, "transition": transition,
            "version_state": version_state, "confidence": ch.confidence,
            "detail": f"{ch.change_type} {ch.entity_identity} ({transition})"}

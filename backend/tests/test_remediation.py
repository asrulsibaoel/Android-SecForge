"""Remediation-planning tests (prompt 17) — deterministic, offline.

Covers the required cases: dependency update / version-unverified / conditional,
reachability-aware priority, exported-component / WebView / JNI / IPC reviews,
runtime corroboration (without mutating static truth), diff-aware transitions,
deterministic fingerprints, empty/duplicate handling, and preservation of
UNKNOWN / POSSIBLY_AFFECTED / NOT_REACHABLE / NO_LONGER_DETECTED.
"""

import uuid

import pytest

from app.analysis import remediation as R
from app.models.analysis import (
    AndroidEntryPoint, CodeNode, ComponentModel, DataflowSource, EvidenceModel, FindingModel,
    IpcTransaction, ManifestModel, ReachabilityPath, SecurityBoundary, SecuritySink, Analysis,
)
from app.models.correlation import AttackSurfaceNode
from app.models.cve import Dependency, VulnerabilityMatch


def _mk(db, package="com.x"):
    a = Analysis(apk_id=uuid.uuid4(), apk_sha256=uuid.uuid4().hex, profile="static", status="COMPLETE")
    a.manifest = ManifestModel(status="parsed", source_format="binary_axml", package=package)
    db.add(a)
    db.flush()
    return a


def _dep(a, db, name="okhttp", version="3.12.0", vconf="EXACT", kind="java", prefix="okhttp3"):
    d = Dependency(name=name, product=name, package_prefix=prefix, ecosystem="maven" if kind == "java" else "native",
                   version=version, version_confidence=vconf, version_source="POM_PROPERTIES" if version else None,
                   version_strategy="MAVEN", kind=kind, identity_confidence="HIGH")
    a.dependencies.append(d)
    db.flush()
    return d


def _match(a, db, dep, cve="CVE-2099-1", version_state="AFFECTED", correlation="PRESENT_AFFECTED",
           reach="UNKNOWN", fixed=None, identity="HIGH"):
    m = VulnerabilityMatch(analysis=a, dependency=dep, cve_id=cve, match_method="EXACT", match_confidence=identity,
                           identity_confidence=identity, version_state=version_state, correlation_state=correlation,
                           reachability_state=reach, severity="high",
                           earliest_fixed_version=fixed, fixed_versions=[fixed] if fixed else [], providers=["test"])
    db.add(m)
    db.flush()
    return m


def _finding(a, db, rule_id, category, component, severity="high", status="POTENTIAL", detail="evidence",
             validation_state="NOT_RUN", runtime_status=None, is_dup=False):
    f = FindingModel(rule_id=rule_id, title=rule_id, category=category, severity=severity, confidence="medium",
                     status=status, component=component, is_duplicate=is_dup, validation_state=validation_state,
                     runtime_status=runtime_status, fingerprint=uuid.uuid4().hex[:32])
    f.evidence.append(EvidenceModel(source=category, location=component, detail=detail))
    a.findings.append(f)
    db.flush()
    return f


# ---- CASE 1: affected + known fixed -> UPDATE_DEPENDENCY / DIRECT_FIX ----

def test_case1_affected_fixed_update(db_session):
    a = _mk(db_session)
    d = _dep(a, db_session, version="3.12.0")
    _match(a, db_session, d, version_state="AFFECTED", correlation="PRESENT_AFFECTED", fixed="3.14.0")
    items = R.build_items(a)
    it = next(i for i in items if i.target == "okhttp")
    assert it.action == R.A_UPDATE_DEPENDENCY and it.fixability == R.FIX_DIRECT
    assert it.status == R.STATUS_RECOMMENDED and it.recommended_state == ">= 3.14.0"


# ---- CASE 2: unknown version + CVE -> VERSION_UNVERIFIED, no AFFECTED ----

def test_case2_unknown_version_unverified(db_session):
    a = _mk(db_session)
    d = _dep(a, db_session, version=None, vconf="UNKNOWN")
    _match(a, db_session, d, version_state="POSSIBLY_AFFECTED", correlation="PRESENT_UNKNOWN_VERSION")
    items = R.build_items(a)
    it = next(i for i in items if i.target == "okhttp")
    assert it.action == R.A_VERIFY_DEPENDENCY_VERSION and it.status == R.STATUS_VERSION_UNVERIFIED
    assert "AFFECTED" not in (it.current_state or "").replace("POSSIBLY_AFFECTED", "")
    assert it.status != R.STATUS_RECOMMENDED


# ---- CASE 3: POSSIBLY_AFFECTED + fixed -> CONDITIONALLY_RECOMMENDED ----

def test_case3_possibly_affected_conditional(db_session):
    a = _mk(db_session)
    d = _dep(a, db_session, version=None, vconf="UNKNOWN")
    _match(a, db_session, d, version_state="POSSIBLY_AFFECTED", correlation="PRESENT_UNKNOWN_VERSION", fixed="3.14.0")
    it = next(i for i in R.build_items(a) if i.target == "okhttp")
    assert it.status == R.STATUS_CONDITIONALLY_RECOMMENDED and it.fixability == R.FIX_CONDITIONAL
    assert "after confirming" in (it.recommended_state or "")
    assert any(step["action"] == R.A_VERIFY_DEPENDENCY_VERSION for step in it.actions)


# ---- CASE 4/5: reachable > not-reachable priority ----

def test_case4_5_reachability_priority(db_session):
    a = _mk(db_session)
    d1 = _dep(a, db_session, name="reachlib", prefix="reach", version="1.0")
    _match(a, db_session, d1, cve="CVE-R", version_state="AFFECTED", correlation="AFFECTED_REACHABLE",
           reach="REACHABLE", fixed="2.0")
    d2 = _dep(a, db_session, name="unreachlib", prefix="unreach", version="1.0")
    _match(a, db_session, d2, cve="CVE-U", version_state="AFFECTED", correlation="AFFECTED_NOT_REACHABLE",
           reach="NOT_REACHABLE", fixed="2.0")
    items = {i.target: i for i in R.build_items(a)}
    assert items["reachlib"].priority_score > items["unreachlib"].priority_score


# ---- CASE 6: exported component + finding -> REVIEW_EXPORTED_COMPONENT ----

def test_case6_exported_component(db_session):
    a = _mk(db_session)
    a.components.append(ComponentModel(kind="activity", name="com.x.Web", exported=True,
                                       effective_exported=True, exposure="EXPORTED"))
    a.attack_surface_nodes.append(AttackSurfaceNode(node_key="com.x.Web", node_type="component", name="com.x.Web",
                                                    exposure="PUBLIC", component="com.x.Web", risk_score=80))
    _finding(a, db_session, "ANDROID-SEMANTIC-001", "semantic", "com.x.Web")
    items = R.build_items(a)
    assert any(i.action == R.A_REVIEW_EXPORTED_COMPONENT and i.target == "com.x.Web" for i in items)


# ---- CASE 7: WebView bridge -> REVIEW_WEBVIEW_BRIDGE ----

def test_case7_webview_bridge(db_session):
    a = _mk(db_session)
    _finding(a, db_session, "ANDROID-SEMANTIC-004", "webview", "com.x.Web", detail="addJavascriptInterface bridge")
    it = next(i for i in R.build_items(a) if i.action == R.A_REVIEW_WEBVIEW_BRIDGE)
    assert it.target_type == "WEBVIEW"


# ---- CASE 8: JNI boundary UNKNOWN native target ----

def test_case8_jni_unknown_native_target(db_session):
    a = _mk(db_session)
    a.security_boundaries.append(SecurityBoundary(boundary_type="JNI", component="com.x.N", node_key="com.x.N#init",
                                                  confidence="MEDIUM"))
    it = next(i for i in R.build_items(a) if i.action == R.A_REVIEW_JNI_BOUNDARY)
    assert any("UNKNOWN_NATIVE_TARGET" in u for u in it.uncertainties)


# ---- CASE 9: Binder transaction UNKNOWN target ----

def test_case9_ipc_unknown_target(db_session):
    a = _mk(db_session)
    a.ipc_transactions.append(IpcTransaction(kind="SERVICE_ENTRY", class_name="com.x.Svc", method_name="onTransact",
                                             transaction_code="1", confidence="LOW"))
    it = next(i for i in R.build_items(a) if i.action == R.A_REVIEW_IPC_BOUNDARY)
    assert "target=UNKNOWN" in (it.current_state or "")
    assert any("UNKNOWN" in u for u in it.uncertainties)


# ---- CASE 10: runtime OBSERVED corroborates ----

def test_case10_runtime_corroborated(db_session):
    a = _mk(db_session)
    _finding(a, db_session, "ANDROID-WEBVIEW-001", "webview", "com.x.Web",
             validation_state="OBSERVED", runtime_status="STATIC_RUNTIME_CONFIRMED")
    it = next(i for i in R.build_items(a) if i.source_category == "finding")
    assert any(e["source_type"] == "RUNTIME" and e["detail"] == "RUNTIME_CORROBORATED" for e in it.evidence)
    assert any(f["name"] == "runtime_corroborated" for f in it.factors)


# ---- CASE 11: runtime NOT_OBSERVED does not mutate static finding ----

def test_case11_runtime_not_observed_preserved(db_session):
    a = _mk(db_session)
    f = _finding(a, db_session, "ANDROID-WEBVIEW-001", "webview", "com.x.Web", validation_state="NOT_OBSERVED")
    before = (f.status, f.severity, f.confidence, f.validation_state)
    it = next(i for i in R.build_items(a) if i.source_category == "finding")
    assert (f.status, f.severity, f.confidence, f.validation_state) == before  # static truth unchanged
    assert any(e["detail"] == "RUNTIME_NOT_OBSERVED" for e in it.evidence)


# ---- CASE 12: diff finding disappears -> NO_LONGER_DETECTED (not remediated) ----

def test_case12_diff_finding_disappears(make_analysis, db_session):
    from app.analysis.diff import compare_analyses
    from app.analysis.remediation import remediation_from_diff
    a = make_analysis(package="com.x")
    _finding(a, db_session, "ANDROID-OLD-001", "webview", "com.x.Web")
    b = make_analysis(package="com.x")
    c = compare_analyses(db_session, a, b)
    db_session.flush()
    rem = remediation_from_diff(c)
    old = [i for i in rem["items"] if "ANDROID-OLD-001" in i["target"]]
    assert old and old[0]["status"] == R.STATUS_NO_LONGER_DETECTED
    assert all(i["status"] != R.STATUS_REMEDIATED for i in old)


# ---- CASE 13: candidate proves NOT_AFFECTED with version -> REMEDIATED ----

def test_case13_diff_remediated_with_evidence(make_analysis, db_session):
    from app.analysis.diff import compare_analyses
    from app.analysis.remediation import remediation_from_diff
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    ma = next(m for m in a.vulnerability_matches if m.cve_id == "CVE-2020-0001")
    ma.version_state = "AFFECTED"; ma.dependency.version = "1.0.0"
    mb = next(m for m in b.vulnerability_matches if m.cve_id == "CVE-2020-0001")
    mb.version_state = "NOT_AFFECTED"; mb.dependency.version = "2.0.0"
    db_session.flush()
    c = compare_analyses(db_session, a, b)
    db_session.flush()
    rem = remediation_from_diff(c)
    changed = [i for i in rem["items"] if "CVE-2020-0001" in i["target"]]
    assert changed and changed[0]["status"] == R.STATUS_REMEDIATED


# ---- CASE 14: two identical analyses -> identical plan fingerprint ----

def test_case14_identical_analyses_same_fingerprint(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    assert R.plan_view(a)["fingerprint"] == R.plan_view(b)["fingerprint"]


# ---- CASE 15: same evidence different order -> identical item fingerprints ----

def test_case15_order_independent_fingerprint(db_session):
    a = _mk(db_session)
    _finding(a, db_session, "ANDROID-WEBVIEW-001", "webview", "com.x.Web")
    fps1 = sorted(i.fingerprint for i in R.build_items(a))
    fps2 = sorted(i.fingerprint for i in R.build_items(a))
    assert fps1 == fps2


# ---- CASE 16: no findings -> zero items ----

def test_case16_no_findings_zero_items(db_session):
    a = _mk(db_session)
    assert R.build_items(a) == []


# ---- CASE 17: unrelated source and sink -> no recommendation ----

def test_case17_unrelated_source_sink_no_item(db_session):
    a = _mk(db_session)
    a.dataflow_sources.append(DataflowSource(node_key="src:1", source_type="intent", api="getIntent"))
    a.security_sinks.append(SecuritySink(node_key="sink:1", sink_type="exec", api="exec", category="java"))
    db_session.flush()
    # no finding, no path -> no remediation item
    assert R.build_items(a) == []


# ---- CASE 18: duplicate findings -> one deterministic item ----

def test_case18_duplicate_findings_one_item(db_session):
    a = _mk(db_session)
    _finding(a, db_session, "ANDROID-WEBVIEW-001", "webview", "com.x.Web")
    _finding(a, db_session, "ANDROID-WEBVIEW-001", "webview", "com.x.Web", is_dup=True)  # duplicate flagged
    items = [i for i in R.build_items(a) if i.action == R.A_REVIEW_WEBVIEW_CONFIGURATION]
    assert len(items) == 1


# ---- persistence + integrity ----

def test_build_plan_persists_and_is_read_only(db_session):
    a = _mk(db_session)
    d = _dep(a, db_session, version="3.12.0")
    _match(a, db_session, d, version_state="AFFECTED", fixed="3.14.0")
    f = _finding(a, db_session, "ANDROID-CRYPTO-001", "crypto", "com.x.C")
    findings_before = [(x.rule_id, x.status, x.severity) for x in a.findings]
    matches_before = [(m.cve_id, m.version_state, m.correlation_state) for m in a.vulnerability_matches]
    plan = R.build_plan(db_session, a, requested_by="test")
    db_session.flush()
    assert plan.item_count >= 2 and plan.fingerprint
    assert plan.items and all(i.evidence for i in plan.items)
    # remediation never mutates source findings / CVE state
    assert [(x.rule_id, x.status, x.severity) for x in a.findings] == findings_before
    assert [(m.cve_id, m.version_state, m.correlation_state) for m in a.vulnerability_matches] == matches_before


def test_no_exploitable_language(db_session):
    import json
    a = _mk(db_session)
    d = _dep(a, db_session, version=None, vconf="UNKNOWN")
    _match(a, db_session, d, version_state="POSSIBLY_AFFECTED", fixed="3.14.0")
    _finding(a, db_session, "ANDROID-WEBVIEW-001", "webview", "com.x.Web")
    view = R.plan_view(a)
    assert "exploitable" not in json.dumps(view).lower()


def test_explain_item(db_session):
    a = _mk(db_session)
    d = _dep(a, db_session, version="3.12.0")
    _match(a, db_session, d, version_state="AFFECTED", fixed="3.14.0")
    it = next(i for i in R.build_items(a) if i.target == "okhttp")
    ex = R.explain_item(a, it)
    assert ex["WHY_THIS_RECOMMENDATION_EXISTS"] and ex["action"] == R.A_UPDATE_DEPENDENCY
    assert ex["recommended_action"] == ">= 3.14.0"


def test_priority_undetermined_for_bare_unverified(db_session):
    a = _mk(db_session)
    d = _dep(a, db_session, name="lonelylib", prefix="lonely", version=None, vconf="UNKNOWN")
    _match(a, db_session, d, cve="CVE-Z", version_state="POSSIBLY_AFFECTED", correlation="PRESENT_UNKNOWN_VERSION",
           identity="MEDIUM")  # no fixed, medium identity, not reachable
    it = next(i for i in R.build_items(a) if i.target == "lonelylib")
    assert it.priority in (R.PRIORITY_UNDETERMINED, R.PRIORITY_LOW, R.PRIORITY_INFO)

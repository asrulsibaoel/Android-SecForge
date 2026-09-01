"""Comparative APK-analysis (diff) tests — prompt 15.

Fully offline: both analyses are built from models via the `make_analysis`
fixture, then controlled synthetic differences are applied to the candidate.
These assert deterministic identity, per-category diffing, conservative
security-impact classification, snapshot integrity, and that analytical states
(UNKNOWN / POSSIBLY_AFFECTED / NOT_REACHABLE / NOT_OBSERVED) are preserved.
"""

from datetime import datetime, timezone

import pytest

from app.analysis.diff import comparison_fingerprint, compare_analyses
from app.analysis import knowledge_graph as KG
from app.models.analysis import (
    ComponentModel, EvidenceModel, FindingModel, JNIBinding, NativeLibrary,
    PermissionModel, ReachabilityPath, DeepLink,
)
from app.models.correlation import AttackSurfaceNode, RiskAssessment, RiskFactor
from app.models.runtime import RuntimeObservation, RuntimeSession


# ---- helpers ----

def _cmp(db, a, b):
    c = compare_analyses(db, a, b)
    db.flush()
    return c


def _add_component(db, a, name, exported=True, exposure="EXPORTED", kind="activity"):
    a.components.append(ComponentModel(kind=kind, name=name, exported=exported,
                                       effective_exported=exported, exposure=exposure))
    db.flush()


def _add_permission(db, a, name, dangerous=True):
    a.permissions.append(PermissionModel(name=name, protection_level="dangerous" if dangerous else "normal",
                                         is_dangerous=dangerous))
    db.flush()


def _add_finding(db, a, rule_id, category="reachability", component="com.x.Web", status="POTENTIAL",
                 severity="high", confidence="medium"):
    f = FindingModel(rule_id=rule_id, title=rule_id, category=category, severity=severity,
                     confidence=confidence, status=status, component=component, confidence_score=50)
    f.evidence.append(EvidenceModel(source=category, location=component, detail=f"{rule_id} evidence"))
    a.findings.append(f)
    db.flush()
    return f


def _set_risk(db, a, score, severity, confidence="medium", factors=("exported_component",)):
    ra = RiskAssessment(scope="overall", overall_score=score, severity=severity, confidence=confidence)
    for name in factors:
        ra.factors.append(RiskFactor(name=name, weight=10, direction="positive"))
    a.risk_assessments.append(ra)
    db.flush()


def _add_as_node(db, a, node_key, exposure="PUBLIC", risk=80):
    a.attack_surface_nodes.append(AttackSurfaceNode(node_key=node_key, node_type="component", name=node_key,
                                                    exposure=exposure, component=node_key, risk_score=risk))
    db.flush()


def _changes_by_category(c, category):
    return [ch for ch in c.changes if ch.category == category]


# ---- 1. identical -> NO_CHANGE ----

def test_identical_analyses_no_change(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    c = _cmp(db_session, a, b)
    assert c.status == "COMPLETE"
    assert c.summary["total_changes"] == 0
    assert c.security_impact == "NO_MATERIAL_SECURITY_CHANGE"
    assert c.impact_confidence == "HIGH"


# ---- 2/3. component added / removed ----

def test_component_added(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    _add_component(db_session, b, "com.x.NewActivity")
    c = _cmp(db_session, a, b)
    added = [ch for ch in _changes_by_category(c, "manifest")
             if ch.entity_type == "component" and ch.change_type == "ADDED"]
    assert any(ch.entity_identity == "com.x.NewActivity" for ch in added)


def test_component_removed(make_analysis, db_session):
    a = make_analysis(package="com.x")
    _add_component(db_session, a, "com.x.Gone", exported=False, exposure="INTERNAL")
    b = make_analysis(package="com.x")
    c = _cmp(db_session, a, b)
    removed = [ch for ch in _changes_by_category(c, "manifest")
               if ch.entity_type == "component" and ch.change_type == "REMOVED"]
    assert any(ch.entity_identity == "com.x.Gone" for ch in removed)


# ---- 4. exported state changed ----

def test_exported_state_changed(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    svc = next(comp for comp in b.components if comp.name == "com.x.Svc")
    svc.effective_exported = True
    svc.exposure = "EXPORTED"
    db_session.flush()
    c = _cmp(db_session, a, b)
    changed = [ch for ch in _changes_by_category(c, "manifest")
               if ch.change_type == "CHANGED" and ch.entity_identity == "com.x.Svc"]
    assert changed and changed[0].security_relevant
    assert c.security_impact == "SECURITY_REGRESSION"  # became exported (HIGH evidence)


# ---- 5. permission added ----

def test_permission_added(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    _add_permission(db_session, b, "android.permission.READ_SMS", dangerous=True)
    c = _cmp(db_session, a, b)
    perms = [ch for ch in _changes_by_category(c, "manifest")
             if ch.entity_type == "permission" and ch.change_type == "ADDED"]
    assert any(p.entity_identity == "android.permission.READ_SMS" and p.confidence == "HIGH" for p in perms)


# ---- 6. deep link added ----

def test_deep_link_added(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    b.deep_links.append(DeepLink(node_key="dl", component="com.x.Web", scheme="myapp", host="open",
                                 path="/pay", confidence="HIGH"))
    db_session.flush()
    c = _cmp(db_session, a, b)
    dls = [ch for ch in _changes_by_category(c, "manifest") if ch.entity_type == "deep_link"]
    assert any(ch.change_type == "ADDED" for ch in dls)


# ---- 7/8. JNI binding added / native library removed ----

def test_jni_binding_added(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    b.jni_bindings.append(JNIBinding(source="ELF_EXPORT", confidence="HIGH", java_class="com.x.N",
                                     java_method="init", native_function="Java_com_x_N_init",
                                     library_name="libx.so"))
    db_session.flush()
    c = _cmp(db_session, a, b)
    jni = [ch for ch in _changes_by_category(c, "native") if ch.entity_type == "jni_binding"]
    assert any(ch.change_type == "ADDED" for ch in jni)


def test_native_library_removed(make_analysis, db_session):
    a = make_analysis(package="com.x")
    a.native_libraries.append(NativeLibrary(archive_path="lib/arm64-v8a/libx.so", abi="arm64-v8a",
                                            filename="libx.so", size_bytes=100, sha256="a" * 64, status="COMPLETE"))
    b = make_analysis(package="com.x")
    db_session.flush()
    c = _cmp(db_session, a, b)
    libs = [ch for ch in _changes_by_category(c, "native") if ch.entity_type == "native_library"]
    assert any(ch.change_type == "REMOVED" and ch.confidence == "HIGH" for ch in libs)


# ---- 9. dependency version changed ----

def test_dependency_version_changed(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    dep = next(d for d in b.dependencies if d.name == "openssl")
    dep.version = "1.1.1"
    db_session.flush()
    c = _cmp(db_session, a, b)
    deps = [ch for ch in _changes_by_category(c, "dependency") if ch.change_type == "CHANGED"]
    assert deps and deps[0].evidence["classification"] == "VERSION_CHANGED"
    assert deps[0].evidence["version"] == ["1.0.2", "1.1.1"]


# ---- 10. CVE transition (states preserved) ----

def test_cve_transition_preserves_states(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    m = next(m for m in b.vulnerability_matches if m.cve_id == "CVE-2020-0001")
    m.version_state = "AFFECTED"
    m.correlation_state = "AFFECTED_REACHABLE"
    m.reachability_state = "REACHABLE"
    db_session.flush()
    c = _cmp(db_session, a, b)
    cve = [ch for ch in _changes_by_category(c, "cve") if ch.change_type == "CHANGED"]
    assert cve
    ev = cve[0].evidence
    assert ev["baseline"]["version_state"] == "POSSIBLY_AFFECTED"   # preserved verbatim
    assert ev["candidate"]["version_state"] == "AFFECTED"


def test_possibly_affected_not_upgraded(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    c = _cmp(db_session, a, b)
    # identical -> no cve change; POSSIBLY_AFFECTED never silently promoted
    assert not _changes_by_category(c, "cve")
    m = next(m for m in a.vulnerability_matches if m.cve_id == "CVE-2020-0001")
    assert m.version_state == "POSSIBLY_AFFECTED"


# ---- 11/12. finding added / removed (NO_LONGER_DETECTED) ----

def test_finding_added(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    _add_finding(db_session, b, "ANDROID-NEW-001", category="webview", component="com.x.Web")
    c = _cmp(db_session, a, b)
    added = [f for f in c.finding_changes if f.change_type == "ADDED"]
    assert any(f.rule_id == "ANDROID-NEW-001" for f in added)


def test_finding_removed_is_no_longer_detected(make_analysis, db_session):
    a = make_analysis(package="com.x")
    _add_finding(db_session, a, "ANDROID-OLD-001", category="webview", component="com.x.Web")
    b = make_analysis(package="com.x")
    c = _cmp(db_session, a, b)
    removed = [f for f in c.finding_changes if f.change_type == "REMOVED" and f.rule_id == "ANDROID-OLD-001"]
    assert removed
    # persisted change carries the NO_LONGER_DETECTED disposition, not "fixed"
    ch = next(ch for ch in _changes_by_category(c, "finding")
              if ch.entity_identity.startswith("ANDROID-OLD-001") and ch.change_type == "REMOVED")
    assert ch.evidence.get("disposition") == "NO_LONGER_DETECTED"


# ---- 13/14. risk increase / decrease ----

def test_risk_increase(make_analysis, db_session):
    a = make_analysis(package="com.x"); _set_risk(db_session, a, 60, "medium", factors=("f1",))
    b = make_analysis(package="com.x"); _set_risk(db_session, b, 84, "high", factors=("f1", "f2"))
    c = _cmp(db_session, a, b)
    assert c.risk_delta.delta == 24
    assert c.risk_delta.severity_transition == "medium → high"


def test_risk_decrease(make_analysis, db_session):
    a = make_analysis(package="com.x"); _set_risk(db_session, a, 84, "high", factors=("f1", "f2"))
    b = make_analysis(package="com.x"); _set_risk(db_session, b, 40, "medium", factors=("f1",))
    c = _cmp(db_session, a, b)
    assert c.risk_delta.delta == -44
    assert c.security_impact in ("SECURITY_IMPROVEMENT", "MIXED")


# ---- 15. security regression ----

def test_security_regression(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    _add_finding(db_session, b, "ANDROID-REACH-999", category="reachability", component="com.x.Web",
                 status="CONFIRMED_BY_STATIC_ANALYSIS")
    _add_as_node(db_session, b, "com.x.NewPublic", exposure="PUBLIC")
    c = _cmp(db_session, a, b)
    assert c.security_impact == "SECURITY_REGRESSION"
    assert c.impact_confidence in ("HIGH", "MEDIUM")


# ---- 16. security improvement ----

def test_security_improvement(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    web = next(comp for comp in b.components if comp.name == "com.x.Web")
    web.effective_exported = False
    web.exposure = "INTERNAL"
    db_session.flush()
    c = _cmp(db_session, a, b)
    assert c.security_impact == "SECURITY_IMPROVEMENT"


# ---- 17. inconclusive ----

def test_inconclusive_change(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    # a new POTENTIAL (not confirmed) finding on an existing component -> ambiguous only
    _add_finding(db_session, b, "ANDROID-POT-001", category="reachability", component="com.x.Web",
                 status="POTENTIAL")
    c = _cmp(db_session, a, b)
    assert c.security_impact == "INCONCLUSIVE"


# ---- 18/19. UNKNOWN + UNKNOWN_NATIVE_TARGET preserved ----

def test_unknown_reflection_target_preserved(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    # remove the reflection edge from candidate so it becomes a REMOVED change
    from app.models.analysis import SemanticEdge
    b.semantic_edges = [e for e in b.semantic_edges if e.edge_type != "REFLECTION_TARGET"]
    db_session.flush()
    c = _cmp(db_session, a, b)
    refl = [ch for ch in _changes_by_category(c, "semantics") if ch.entity_type == "reflection_target"]
    assert refl and refl[0].evidence["unknown_target"] is True  # UNKNOWN target preserved


def test_unknown_reachability_status_preserved(make_analysis, db_session):
    a = make_analysis(package="com.x")
    a.reachability_paths.append(ReachabilityPath(
        rule_id="ANDROID-REACH-003", from_key="entry:com.x.Web", from_label="Web", to_key="jni:UNKNOWN",
        to_label="UNKNOWN_NATIVE_TARGET", status="UNKNOWN", confidence="LOW", length=2,
        nodes=[{"key": "entry:com.x.Web", "label": "Web"}, {"key": "jni:UNKNOWN", "label": "UNKNOWN_NATIVE_TARGET"}],
        edges=[]))
    b = make_analysis(package="com.x")
    db_session.flush()
    c = _cmp(db_session, a, b)
    path = [ch for ch in _changes_by_category(c, "reachability") if ch.change_type == "REMOVED"]
    assert path and path[0].evidence["status"] == "UNKNOWN"  # not converted to NOT_REACHABLE
    assert path[0].security_relevant is False  # only REACHABLE is security-relevant


# ---- 20. snapshot mismatch rejected ----

def test_snapshot_mismatch_rejected(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    snap = KG.build_snapshot(a, datetime.now(timezone.utc))
    db_session.flush()
    snap.digest = "corrupted" + "0" * 55  # tamper
    db_session.flush()
    c = _cmp(db_session, a, b)
    assert c.status == "FAILED"
    assert "mismatch" in (c.error or "")


def test_valid_snapshots_verified(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    KG.build_snapshot(a, datetime.now(timezone.utc))
    KG.build_snapshot(b, datetime.now(timezone.utc))
    db_session.flush()
    c = _cmp(db_session, a, b)
    assert c.status == "COMPLETE" and c.snapshot_mode == "SNAPSHOT"


# ---- 21/22. deterministic fingerprint + repeated comparison ----

def test_deterministic_fingerprint(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    fp1 = comparison_fingerprint(a, b, None, None)
    fp2 = comparison_fingerprint(a, b, None, None)
    assert fp1 == fp2 and len(fp1) == 32


def test_repeated_comparison_deterministic(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    _add_component(db_session, b, "com.x.Added")
    c1 = _cmp(db_session, a, b)
    c2 = _cmp(db_session, a, b)
    assert c1.fingerprint == c2.fingerprint
    assert c1.summary["total_changes"] == c2.summary["total_changes"]
    assert c1.security_impact == c2.security_impact


# ---- 23. direction matters ----

def test_direction_matters(make_analysis, db_session):
    a = make_analysis(package="com.x")
    _add_component(db_session, a, "com.x.OnlyInA", exported=False, exposure="INTERNAL")
    b = make_analysis(package="com.x")
    fwd = comparison_fingerprint(a, b, None, None)
    rev = comparison_fingerprint(b, a, None, None)
    assert fwd != rev
    c_ab = _cmp(db_session, a, b)
    c_ba = _cmp(db_session, b, a)
    ab = [ch.change_type for ch in c_ab.changes if ch.entity_identity == "com.x.OnlyInA"]
    ba = [ch.change_type for ch in c_ba.changes if ch.entity_identity == "com.x.OnlyInA"]
    assert ab == ["REMOVED"] and ba == ["ADDED"]


# ---- 24. provenance preserved ----

def test_provenance_preserved(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    _add_permission(db_session, b, "android.permission.CAMERA")
    c = _cmp(db_session, a, b)
    perm = next(ch for ch in c.changes if ch.entity_type == "permission")
    assert perm.provenance == "MANIFEST" and perm.evidence.get("dangerous") is True


# ---- 25. runtime evidence transition ----

def test_runtime_observation_transition(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    sess = b.runtime_sessions[0]
    sess.observations.append(RuntimeObservation(observation_type="NATIVE", symbol="strcpy",
                                                source="FRIDA", confidence="MEDIUM"))
    db_session.flush()
    c = _cmp(db_session, a, b)
    rt = [ch for ch in _changes_by_category(c, "runtime") if ch.change_type == "ADDED"]
    assert any("strcpy" in ch.entity_identity for ch in rt)


# ---- 26. attack-surface delta ----

def test_attack_surface_delta(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    _add_as_node(db_session, b, "com.x.ExtraPublic", exposure="PUBLIC")
    c = _cmp(db_session, a, b)
    added = [ch for ch in _changes_by_category(c, "attack_surface")
             if ch.change_type == "ADDED" and ch.entity_type == "as_node"]
    assert any(ch.evidence.get("exposure") == "PUBLIC" for ch in added)


# ---- 27. reachability path delta ----

def test_reachability_path_delta(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    b.reachability_paths.append(ReachabilityPath(
        rule_id="ANDROID-REACH-002", from_key="entry:com.x.Web", from_label="Web", to_key="sink:exec",
        to_label="Runtime.exec", status="REACHABLE", confidence="MEDIUM", length=3,
        nodes=[{"key": "entry:com.x.Web", "label": "Web"}, {"key": "sink:exec", "label": "Runtime.exec"}], edges=[]))
    db_session.flush()
    c = _cmp(db_session, a, b)
    paths = [ch for ch in _changes_by_category(c, "reachability") if ch.change_type == "ADDED"]
    assert paths and paths[0].security_relevant is True  # new REACHABLE path


# ---- 28. bounded performance / truncation ----

def test_bounded_changes(make_analysis, db_session, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "diff_max_changes_per_category", 2)
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    from app.models.analysis import CodeEntity
    for i in range(10):
        b.code_entities.append(CodeEntity(entity_type="class", class_name=f"com.x.Gen{i}"))
    db_session.flush()
    c = _cmp(db_session, a, b)
    assert c.status == "PARTIAL"
    assert c.summary["truncated"].get("code", 0) > 0


# ---- graph-delta export ----

def test_graph_delta_export(make_analysis, db_session):
    from app.reports.comparison_report import export_comparison_graph
    import json
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    _add_component(db_session, b, "com.x.Added")
    c = _cmp(db_session, a, b)
    data = json.loads(export_comparison_graph(c, "json"))
    statuses = {n["status"] for n in data["nodes"]}
    assert statuses <= {"ADDED", "REMOVED", "UNCHANGED", "CHANGED"}
    assert any(n["status"] == "ADDED" for n in data["nodes"])
    assert export_comparison_graph(c, "dot").startswith("digraph")
    assert "<graphml" in export_comparison_graph(c, "graphml")


def test_no_cross_analysis_mutation(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    a_findings_before = len(a.findings)
    b_findings_before = len(b.findings)
    _cmp(db_session, a, b)
    # comparison never mutates either analysis
    assert len(a.findings) == a_findings_before and len(b.findings) == b_findings_before

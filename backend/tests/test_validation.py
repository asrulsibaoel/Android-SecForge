"""Security-validation tests (prompt 18) — deterministic, offline.

Covers static-supported/multi-source/blocked/unverified states, evidence-family
independence, runtime corroboration (LIVE vs MOCKED), UNKNOWN preservation,
CVE version validation, remediation validation, diff transitions, hypothesis
non-interference, deterministic fingerprints, and duplicate prevention.
"""

import uuid

import pytest

from app.analysis import validation as V
from app.models.analysis import (
    Analysis, ComponentModel, EvidenceModel, FindingModel, IpcTransaction, ManifestModel,
    ReachabilityPath, SecurityBoundary,
)
from app.models.cve import Dependency, VulnerabilityMatch
from app.models.runtime import RuntimeObservation, RuntimeSession


def _mk(db, package="com.x"):
    a = Analysis(apk_id=uuid.uuid4(), apk_sha256=uuid.uuid4().hex, profile="static", status="COMPLETE")
    a.manifest = ManifestModel(status="parsed", source_format="binary_axml", package=package)
    db.add(a)
    db.flush()
    return a


def _finding(a, db, rule_id, category, component, sources=(("code", "evidence"),), severity="high",
             status="POTENTIAL", runtime_status=None, is_dup=False):
    f = FindingModel(rule_id=rule_id, title=rule_id, category=category, severity=severity, confidence="medium",
                     status=status, component=component, is_duplicate=is_dup, runtime_status=runtime_status,
                     fingerprint=uuid.uuid4().hex[:32])
    for src, detail in sources:
        f.evidence.append(EvidenceModel(source=src, location=component, detail=detail))
    a.findings.append(f)
    db.flush()
    return f


def _dep(a, db, name="okhttp", version="3.12.0", vconf="EXACT", prefix="okhttp3"):
    d = Dependency(name=name, product=name, package_prefix=prefix, ecosystem="maven", version=version,
                   version_confidence=vconf, version_source="POM_PROPERTIES" if version else None,
                   version_strategy="MAVEN", kind="java", identity_confidence="HIGH")
    a.dependencies.append(d)
    db.flush()
    return d


def _match(a, db, dep, cve="CVE-1", version_state="AFFECTED", correlation="PRESENT_AFFECTED", reach="UNKNOWN",
           identity="HIGH", fixed=None):
    m = VulnerabilityMatch(analysis=a, dependency=dep, cve_id=cve, match_confidence=identity,
                           identity_confidence=identity, version_state=version_state, correlation_state=correlation,
                           reachability_state=reach, severity="high",
                           earliest_fixed_version=fixed, fixed_versions=[fixed] if fixed else [])
    db.add(m)
    db.flush()
    return m


def _runtime(a, db, class_name="android.webkit.WebView", method="loadUrl", symbol=None, adapter="adb"):
    s = RuntimeSession(session_state="RUNNING", instrumentation_enabled=True, device_serial="emulator-5554",
                       package_name="com.x", metadata_={"adapter": adapter})
    s.observations.append(RuntimeObservation(observation_type="JAVA" if class_name else "NATIVE",
                                             class_name=class_name, method_name=method, symbol=symbol,
                                             source="FRIDA", confidence="MEDIUM"))
    a.runtime_sessions.append(s)
    db.flush()
    return s


def _claims(a):
    return {c.claim_type: c for c in V.build_claims(a)}


# ---- 1. static supported ----

def test_case1_static_supported(db_session):
    a = _mk(db_session)
    _finding(a, db_session, "ANDROID-WEBVIEW-001", "webview", "com.x.Web", sources=(("code", "setJavaScriptEnabled"),))
    c = _claims(a)["WEBVIEW_BRIDGE_CONFIRMED"]
    assert c.state == V.VS_STATIC_SUPPORTED and c.independent_source_count == 1


# ---- 2. insufficient evidence -> UNVERIFIED (evidence only a MOCKED runtime) ----

def test_case2_unverified_when_no_independent_family(db_session):
    a = _mk(db_session)
    # finding with no static evidence rows, only a MOCKED runtime observation matching
    f = FindingModel(rule_id="ANDROID-WEBVIEW-001", title="WebView.loadUrl", category="webview",
                     severity="medium", confidence="low", status="POTENTIAL", component="com.x.Web",
                     fingerprint="fpX")
    a.findings.append(f)
    _runtime(a, db_session, adapter="mock")  # MOCKED
    db_session.flush()
    c = _claims(a)["WEBVIEW_BRIDGE_CONFIRMED"]
    assert c.state == V.VS_UNVERIFIED  # mock runtime does not count as independent


# ---- 3. missing version -> VALIDATION_BLOCKED ----

def test_case3_missing_version_blocked(db_session):
    a = _mk(db_session)
    d = _dep(a, db_session, version=None, vconf="UNKNOWN")
    _match(a, db_session, d, version_state="POSSIBLY_AFFECTED", correlation="PRESENT_UNKNOWN_VERSION")
    rem = next(c for c in V.build_claims(a) if c.claim_type == "REMEDIATION_STATE_SUPPORTED" and c.target == "okhttp")
    assert rem.state == V.VS_BLOCKED
    assert any(b["blocker"] == V.B_MISSING_VERSION for b in rem.blockers)


# ---- 4. independent evidence increases confidence / MULTI_SOURCE ----

def test_case4_independent_evidence_multi_source(db_session):
    a = _mk(db_session)
    _finding(a, db_session, "ANDROID-REACH-001", "reachability", "com.x.Web",
             sources=(("code", "OkHttpClient.run"), ("reachability", "[2] SECURITY_SINK loadUrl")))
    c = next(c for c in V.build_claims(a) if c.finding_id is not None)
    assert c.independent_source_count >= 2 and c.state == V.VS_MULTI_SOURCE


# ---- 5. same-family evidence not independent ----

def test_case5_same_family_not_independent(db_session):
    a = _mk(db_session)
    _finding(a, db_session, "ANDROID-CRYPTO-001", "crypto", "com.x.C",
             sources=(("code", "MD5"), ("code", "DES"), ("code", "ECB")))  # 3 rows, one family
    c = next(c for c in V.build_claims(a) if c.finding_id is not None)
    assert c.independent_source_count == 1 and c.state == V.VS_STATIC_SUPPORTED


# ---- 6/7/8. runtime corroboration: LIVE vs MOCKED vs mismatch ----

def test_case6_runtime_corroborated_live(db_session):
    a = _mk(db_session)
    _finding(a, db_session, "ANDROID-WEBVIEW-001", "webview", "com.x.Web",
             sources=(("code", "WebView.loadUrl called"),))
    _runtime(a, db_session, class_name="android.webkit.WebView", method="loadUrl", adapter="adb")  # LIVE
    c = _claims(a)["WEBVIEW_BRIDGE_CONFIRMED"]
    assert c.state in (V.VS_RUNTIME_CORROBORATED, V.VS_MULTI_SOURCE)
    assert any(e.family == "RUNTIME" and e.live for e in c.evidence)


def test_case7_mocked_stays_mocked(db_session):
    a = _mk(db_session)
    _finding(a, db_session, "ANDROID-WEBVIEW-001", "webview", "com.x.Web",
             sources=(("code", "WebView.loadUrl called"),))
    _runtime(a, db_session, class_name="android.webkit.WebView", method="loadUrl", adapter="mock")  # MOCKED
    c = _claims(a)["WEBVIEW_BRIDGE_CONFIRMED"]
    assert c.state == V.VS_STATIC_SUPPORTED  # mock never corroborates
    assert any(e.family == "RUNTIME" and not e.live for e in c.evidence)
    assert any("MOCKED" in u for u in c.uncertainty)


def test_case8_runtime_mismatch_no_corroboration(db_session):
    a = _mk(db_session)
    _finding(a, db_session, "ANDROID-WEBVIEW-001", "webview", "com.x.Web", sources=(("code", "loadUrl"),))
    _runtime(a, db_session, class_name="android.content.Intent", method="getStringExtra", adapter="adb")  # mismatch
    c = _claims(a)["WEBVIEW_BRIDGE_CONFIRMED"]
    assert not any(e.family == "RUNTIME" for e in c.evidence)
    assert c.state == V.VS_STATIC_SUPPORTED


# ---- 9/10. JNI boundary + UNKNOWN_NATIVE_TARGET ----

def test_case9_10_jni_boundary_unknown_native_target(db_session):
    a = _mk(db_session)
    a.security_boundaries.append(SecurityBoundary(boundary_type="JNI", component="com.x.N",
                                                  node_key="com.x.N#init", confidence="MEDIUM"))
    db_session.flush()
    c = _claims(a)["JNI_BOUNDARY_CONFIRMED"]
    assert c.state in (V.VS_STATIC_SUPPORTED, V.VS_MULTI_SOURCE)  # boundary present, not blocked
    assert any(b["blocker"] == V.B_UNKNOWN_NATIVE_TARGET for b in c.blockers)
    assert any("UNKNOWN" in u for u in c.uncertainty)


# ---- 11. unresolved Binder target -> blocked ----

def test_case11_ipc_unresolved_blocked(db_session):
    a = _mk(db_session)
    a.ipc_transactions.append(IpcTransaction(kind="SERVICE_ENTRY", class_name="com.x.Svc",
                                             transaction_code="1", confidence="LOW"))
    db_session.flush()
    c = _claims(a)["IPC_BOUNDARY_CONFIRMED"]
    assert c.state == V.VS_BLOCKED
    assert any(b["blocker"] == V.B_UNRESOLVED_IPC_TARGET for b in c.blockers)


# ---- 12. CVE affected-version validation requires version ----

def test_case12_cve_affected_requires_version(db_session):
    a = _mk(db_session)
    d = _dep(a, db_session, version="3.12.0")
    _match(a, db_session, d, version_state="AFFECTED", correlation="PRESENT_AFFECTED")
    c = next(c for c in V.build_claims(a) if c.claim_type == "CVE_VERSION_AFFECTED")
    assert any(r["requirement"] == "reliable_version" and r["satisfied"] for r in c.requirements)


# ---- 13. POSSIBLY_AFFECTED never becomes AFFECTED ----

def test_case13_possibly_affected_never_affected(db_session):
    a = _mk(db_session)
    d = _dep(a, db_session, version=None, vconf="UNKNOWN")
    _match(a, db_session, d, version_state="POSSIBLY_AFFECTED", correlation="PRESENT_UNKNOWN_VERSION")
    types = {c.claim_type for c in V.build_claims(a)}
    assert "CVE_VERSION_UNVERIFIED" in types and "CVE_VERSION_AFFECTED" not in types
    c = next(c for c in V.build_claims(a) if c.claim_type == "CVE_VERSION_UNVERIFIED")
    assert any("POSSIBLY_AFFECTED" in u for u in c.uncertainty)


# ---- 14. remediation validation ----

def test_case14_remediation_validation(db_session):
    a = _mk(db_session)
    _finding(a, db_session, "ANDROID-CRYPTO-001", "crypto", "com.x.C", sources=(("code", "MD5"),))
    rem = [c for c in V.build_claims(a) if c.claim_type == "REMEDIATION_STATE_SUPPORTED"]
    assert rem and all(c.state in (V.VS_STATIC_SUPPORTED, V.VS_MULTI_SOURCE, V.VS_BLOCKED) for c in rem)


# ---- 15. diff transition ----

def test_case15_diff_transition(make_analysis, db_session):
    from app.analysis.diff import compare_analyses
    a = make_analysis(package="com.x")
    _finding(a, db_session, "ANDROID-OLD-001", "webview", "com.x.Web")
    b = make_analysis(package="com.x")
    c = compare_analyses(db_session, a, b)
    db_session.flush()
    trans = V.validate_comparison(c)
    old = [t for t in trans["transitions"] if "ANDROID-OLD-001" in t["target"]]
    assert old and old[0]["candidate_state"] == "NO_LONGER_DETECTED"
    assert all("fixed" not in t["detail"].lower() or "not" in t["detail"].lower() for t in trans["transitions"])


# ---- 16. investigation hypothesis cannot alter validation ----

def test_case16_hypothesis_does_not_change_validation(make_analysis, db_session):
    from app.analysis import investigation as INV
    a = make_analysis(package="com.x")
    before = V.validation_view(a)["fingerprint"]
    states_before = {c["id"]: c["validation_state"] for c in V.validation_view(a)["claims"]}
    inv = INV.create_investigation(db_session, a)
    hyp = INV.add_hypothesis(db_session, inv, "this is real")
    INV.set_hypothesis_status(db_session, hyp, "SUPPORTED")
    db_session.flush()
    after = V.validation_view(a)["fingerprint"]
    states_after = {c["id"]: c["validation_state"] for c in V.validation_view(a)["claims"]}
    assert before == after and states_before == states_after  # researcher state never changes validation truth


# ---- 17. deterministic fingerprints ----

def test_case17_deterministic_fingerprints(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    assert V.validation_view(a)["fingerprint"] == V.validation_view(b)["fingerprint"]
    assert sorted(c.fingerprint for c in V.build_claims(a)) == sorted(c.fingerprint for c in V.build_claims(a))


# ---- 18. duplicate prevention (persist twice, no dupes) ----

def test_case18_duplicate_prevention(make_analysis, db_session):
    a = make_analysis(package="com.x")
    V.build_validation(db_session, a)
    n1 = len(a.validation_claims)
    V.build_validation(db_session, a)  # re-run
    db_session.flush()
    assert len(a.validation_claims) == n1  # idempotent, no duplicates


# ---- persistence + read-only + no exploitable ----

def test_build_validation_read_only(db_session):
    import json
    a = _mk(db_session)
    f = _finding(a, db_session, "ANDROID-WEBVIEW-001", "webview", "com.x.Web")
    before = (f.severity, f.confidence, f.status, f.runtime_status, f.validation_state)
    claims = V.build_validation(db_session, a)
    db_session.flush()
    assert claims
    # existing finding fields untouched; only additive security_validation_state written
    assert (f.severity, f.confidence, f.status, f.runtime_status, f.validation_state) == before
    assert f.security_validation_state != "" and f.validation_claim_count >= 1
    assert "exploitable" not in json.dumps(V.validation_view(a)).lower()


def test_explain_claim(db_session):
    a = _mk(db_session)
    _finding(a, db_session, "ANDROID-WEBVIEW-001", "webview", "com.x.Web")
    claim = V.build_claims(a)[0]
    ex = V.explain_claim(a, claim)
    header = next(k for k in ex if k.startswith("WHY_"))
    assert ex[header] and "exploitable" not in " ".join(ex[header]).lower()


def test_no_findings_minimal_claims(db_session):
    a = _mk(db_session)
    assert V.build_claims(a) == []

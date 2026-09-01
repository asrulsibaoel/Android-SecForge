"""Live runtime validation & behavioral corroboration tests (prompt 21).

Fully offline. LIVE is simulated by a session whose adapter metadata is 'adb'
(a real adapter would set this); MOCKED sessions use 'mock' and must never count
as LIVE corroboration. No test requires a device, emulator, ADB, or Frida.
"""

import uuid

import pytest

from app.analysis import runtime_validation as RV
from app.models.runtime import RuntimeObservation, RuntimeSession
from app.native import deep_native as D


def _session(db, analysis, adapter="adb", instrumented=True, observations=()):
    s = RuntimeSession(analysis_id=analysis.id, session_state="COMPLETED", device_serial="emulator-5554",
                       package_name=(analysis.manifest.package if analysis.manifest else "com.x"),
                       instrumentation_enabled=instrumented, metadata_={"adapter": adapter})
    analysis.runtime_sessions.append(s)
    db.flush()
    for spec in observations:
        s.observations.append(RuntimeObservation(source=spec.get("source", "FRIDA"), confidence="MEDIUM",
                                                 observation_type=spec["type"], class_name=spec.get("class"),
                                                 method_name=spec.get("method"), symbol=spec.get("symbol"),
                                                 arguments_summary=spec.get("args")))
    db.flush()
    return s


def _native(db, analysis):
    from app.models.analysis import JNIBinding, NativeFunction, NativeLibrary
    import hashlib
    lib = NativeLibrary(analysis_id=analysis.id, archive_path="lib/arm64-v8a/libnative.so", abi="arm64-v8a",
                        filename="libnative.so", size_bytes=4096,
                        sha256=hashlib.sha256(b"libnative").hexdigest(), architecture="arm64",
                        elf_type="ET_DYN", soname="libnative.so", stripped=False, symbols_available=True,
                        status="COMPLETE")
    analysis.native_libraries.append(lib)
    db.flush()
    lib.functions.append(NativeFunction(analysis_id=analysis.id, library_id=lib.id, name="Java_com_x_N_run",
                                        address=0x1000, kind="exported", is_jni=True, source="ELF", confidence="HIGH"))
    lib.functions.append(NativeFunction(analysis_id=analysis.id, library_id=lib.id, name="strcpy",
                                        address=0x0, kind="imported", source="ELF", confidence="HIGH"))
    analysis.jni_bindings.append(JNIBinding(analysis_id=analysis.id, source="JAVA_NATIVE", confidence="HIGH",
                                            java_class="com.x.N", java_method="run", java_signature="()V",
                                            library_name="libnative.so", native_function="Java_com_x_N_run",
                                            evidence="static naming"))
    db.flush()
    D.build_deep_native(db, analysis)


# ---------------------------------------------------------------------------
# LIVE vs MOCKED distinction
# ---------------------------------------------------------------------------


def test_live_confirms_finding(db_session, make_analysis):
    a = make_analysis()
    _session(db_session, a, adapter="adb", observations=[
        {"type": "JAVA", "class": "android.webkit.WebView", "method": "loadUrl"}])
    run = RV.build_runtime_validation(db_session, a)
    assert run.mode == "LIVE"
    reach = next(f for f in a.findings if f.rule_id == "ANDROID-REACH-001")
    assert reach.runtime_validation_state == "CONFIRMED_RUNTIME_BEHAVIOR"


def test_mocked_never_confirms(db_session, make_analysis):
    a = make_analysis()
    _session(db_session, a, adapter="mock", observations=[
        {"type": "JAVA", "class": "android.webkit.WebView", "method": "loadUrl"}])
    run = RV.build_runtime_validation(db_session, a)
    assert run.mode == "MOCKED"
    reach = next(f for f in a.findings if f.rule_id == "ANDROID-REACH-001")
    # MOCKED evidence is INCONCLUSIVE at best — never CONFIRMED.
    assert reach.runtime_validation_state == "RUNTIME_INCONCLUSIVE"
    assert all(c.mode == "MOCKED" for c in a.runtime_correlations)


def test_no_runtime_is_live_unavailable_not_safe(db_session, make_analysis):
    a = make_analysis()
    a.runtime_sessions.clear()  # drop the conftest MOCKED demo session
    db_session.flush()
    run = RV.build_runtime_validation(db_session, a)
    assert run.mode == "UNAVAILABLE"
    assert all(f.runtime_validation_state == "LIVE_UNAVAILABLE" for f in a.findings)
    # LIVE_UNAVAILABLE / NOT_OBSERVED never means safe.
    view = RV.runtime_validation_view(a)
    assert "not mean safe" in view["note"]


def test_live_ran_but_not_observed_is_not_safe(db_session, make_analysis):
    a = make_analysis()
    # LIVE instrumented session that observed something unrelated.
    _session(db_session, a, adapter="adb", instrumented=True, observations=[
        {"type": "JAVA", "class": "android.app.Activity", "method": "onCreate"}])
    RV.build_runtime_validation(db_session, a)
    reach = next(f for f in a.findings if f.rule_id == "ANDROID-REACH-001")
    assert reach.runtime_validation_state == "NOT_OBSERVED"  # ran live, behavior not seen — not safe


# ---------------------------------------------------------------------------
# Device unavailable / APK hash mismatch (lifecycle)
# ---------------------------------------------------------------------------


def test_device_unavailable_returns_live_runtime_unavailable(db_session, make_analysis):
    from app.runtime.session import RuntimeLab
    from tests.test_runtime import MockAdb, MockFrida
    a = make_analysis()
    lab = RuntimeLab(db_session, adb=MockAdb(device=False), frida=MockFrida(available=False))
    result = lab.validate(a, "emulator-5554")
    assert result["status"] == "LIVE_RUNTIME_UNAVAILABLE"
    assert result["mode"] == "UNAVAILABLE"


def test_validate_lifecycle_stays_mocked(db_session, make_analysis):
    from app.runtime.session import RuntimeLab
    from tests.test_runtime import MockAdb, MockFrida
    a = make_analysis()
    lab = RuntimeLab(db_session, adb=MockAdb(), frida=MockFrida())
    result = lab.validate(a, "emulator-5554", profiles=["webview"])
    # A mock adapter is never LIVE — the whole lifecycle runs but stays MOCKED.
    assert result["status"] == "OK"
    assert result["mode"] == "MOCKED"
    assert any(ae.operation == "VALIDATE" and ae.result == "OK"
               for s in a.runtime_sessions for ae in s.audit_events)


# ---------------------------------------------------------------------------
# Correlation: static / JNI / native API
# ---------------------------------------------------------------------------


def test_static_method_correlation(db_session, make_analysis):
    a = make_analysis()
    _session(db_session, a, adapter="adb", observations=[
        {"type": "JAVA", "class": "com.x.Web", "method": "onCreate"}])
    RV.build_runtime_validation(db_session, a)
    corr = [c for c in a.runtime_correlations if c.subject_type == "CODE_METHOD"]
    assert corr and corr[0].correlation_type == "RUNTIME_CONFIRMS" and corr[0].mode == "LIVE"


def test_jni_and_native_api_correlation(db_session, make_analysis):
    a = make_analysis()
    _native(db_session, a)
    _session(db_session, a, adapter="adb", observations=[
        {"type": "JAVA", "class": "com.x.N", "method": "run"},
        {"type": "NATIVE", "symbol": "strcpy", "source": "FRIDA"}])
    RV.build_runtime_validation(db_session, a)
    types = {(c.subject_type, c.correlation_type) for c in a.runtime_correlations}
    assert ("JNI_BINDING", "RUNTIME_INVOCATION") in types
    assert ("NATIVE_API", "RUNTIME_REACHES") in types or ("NATIVE_FUNCTION", "RUNTIME_INVOCATION") in types


def test_native_reachability_not_fabricated(db_session, make_analysis):
    a = make_analysis()
    _native(db_session, a)
    # No native runtime observation -> no runtime native correlation fabricated.
    _session(db_session, a, adapter="adb", observations=[
        {"type": "JAVA", "class": "com.x.Web", "method": "onCreate"}])
    RV.build_runtime_validation(db_session, a)
    assert not any(c.subject_type in ("NATIVE_API", "NATIVE_FUNCTION") for c in a.runtime_correlations)


def test_taxonomy_classification(db_session, make_analysis):
    a = make_analysis()
    _session(db_session, a, adapter="adb", observations=[
        {"type": "JAVA", "class": "android.webkit.WebView", "method": "loadUrl"},
        {"type": "JAVA", "class": "java.lang.Class", "method": "forName"},
        {"type": "NATIVE", "symbol": "strcpy"}])
    RV.build_runtime_validation(db_session, a)
    taxo = {o.taxonomy for s in a.runtime_sessions for o in s.observations}
    assert "WEBVIEW_NAVIGATION" in taxo and "REFLECTION_RESOLUTION" in taxo and "NATIVE_API_INVOCATION" in taxo


# ---------------------------------------------------------------------------
# Redaction / bounded / truncation
# ---------------------------------------------------------------------------


def test_artifact_redaction_and_sha256(db_session, make_analysis):
    from app.runtime.session import RuntimeLab
    a = make_analysis()
    s = _session(db_session, a, adapter="adb")
    lab = RuntimeLab(db_session)
    res = lab.persist_artifact(s, "masked_logcat", "password=hunter2secret token here", redacted=True)
    assert res["status"] == "OK" and res["sha256"] and res["redacted"] is True
    art = s.artifacts[-1]
    assert art.sha256 == res["sha256"]


def test_truncation_recorded_not_silent(db_session, make_analysis, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "runtime_max_correlation_paths", 1)
    a = make_analysis()
    _session(db_session, a, adapter="adb", observations=[
        {"type": "JAVA", "class": "com.x.Web", "method": "onCreate"},
        {"type": "JAVA", "class": "android.webkit.WebView", "method": "loadUrl"}])
    run = RV.build_runtime_validation(db_session, a)
    assert run.truncated.get("correlations", 0) >= 1  # explicit TRUNCATED record, never silent


# ---------------------------------------------------------------------------
# Validation / remediation / diff / KG / investigation integration
# ---------------------------------------------------------------------------


def test_validation_runtime_claim_live_vs_mocked(db_session, make_analysis):
    from app.analysis.validation import build_claims, C_RT_WEBVIEW
    a = make_analysis()
    _session(db_session, a, adapter="adb", observations=[
        {"type": "JAVA", "class": "android.webkit.WebView", "method": "loadUrl"}])
    RV.build_runtime_validation(db_session, a)
    claims = build_claims(a)
    webview = [c for c in claims if c.claim_type == C_RT_WEBVIEW]
    assert webview and webview[0].state == "RUNTIME_CORROBORATED"


def test_validation_mocked_runtime_claim_blocked(db_session, make_analysis):
    from app.analysis.validation import build_claims, C_RT_WEBVIEW
    a = make_analysis()
    _session(db_session, a, adapter="mock", observations=[
        {"type": "JAVA", "class": "android.webkit.WebView", "method": "loadUrl"}])
    RV.build_runtime_validation(db_session, a)
    claims = build_claims(a)
    webview = [c for c in claims if c.claim_type == C_RT_WEBVIEW]
    # MOCKED never counts as LIVE corroboration -> never RUNTIME_CORROBORATED.
    assert webview
    assert webview[0].state in ("VALIDATION_BLOCKED", "UNVERIFIED")
    assert webview[0].state not in ("RUNTIME_CORROBORATED", "MULTI_SOURCE_CORROBORATED")


def test_no_mutation_of_static_truth(db_session, make_analysis):
    a = make_analysis()
    before = [(f.rule_id, f.severity, f.severity_score, f.confidence, f.confidence_score, f.status)
              for f in a.findings]
    risk_before = [(r.scope, r.overall_score) for r in a.risk_assessments]
    cve_before = [(m.cve_id, m.version_state, m.reachability_state) for m in a.vulnerability_matches]
    _session(db_session, a, adapter="adb", observations=[
        {"type": "JAVA", "class": "android.webkit.WebView", "method": "loadUrl"}])
    RV.build_runtime_validation(db_session, a)
    assert [(f.rule_id, f.severity, f.severity_score, f.confidence, f.confidence_score, f.status)
            for f in a.findings] == before
    assert [(r.scope, r.overall_score) for r in a.risk_assessments] == risk_before
    assert [(m.cve_id, m.version_state, m.reachability_state) for m in a.vulnerability_matches] == cve_before


def test_kg_projection_opt_in_snapshot_unchanged(db_session, make_analysis):
    from app.analysis import knowledge_graph as KG
    a = make_analysis()
    _session(db_session, a, adapter="adb", observations=[
        {"type": "JAVA", "class": "com.x.Web", "method": "onCreate"}])
    RV.build_runtime_validation(db_session, a)
    base = KG.build_knowledge_graph(a)
    assert not any(n.node_type == KG.N_RUNTIME_CORRELATION for n in base.nodes.values())
    assert KG.graph_digest(base) == KG.graph_digest(KG.build_knowledge_graph(a))
    withrt = KG.build_knowledge_graph(a, include_runtime_validation=True)
    corr_nodes = [n for n in withrt.nodes.values() if n.node_type == KG.N_RUNTIME_CORRELATION]
    assert corr_nodes
    for n in corr_nodes:
        assert n.provenance and n.provenance[0].source_type in (KG.P_RUNTIME_ADB, KG.P_RUNTIME_FRIDA)
    # at least one LIVE correlation is projected with a LIVE marker
    assert any(n.metadata.get("live") is True for n in corr_nodes)


def test_remediation_runtime_factor_never_remediated(db_session, make_analysis):
    from app.analysis.remediation import build_items
    a = make_analysis()
    _session(db_session, a, adapter="adb", observations=[
        {"type": "JAVA", "class": "android.webkit.WebView", "method": "loadUrl"}])
    RV.build_runtime_validation(db_session, a)
    items = build_items(a)
    # Runtime corroboration is a factor, but never sets an item REMEDIATED on its own.
    assert not any(i.status == "REMEDIATED" for i in items)


def test_diff_runtime_behavior(db_session, make_analysis):
    from app.analysis.runtime_validation import runtime_validation_from_diff
    baseline = make_analysis(package="com.base")
    candidate = make_analysis(package="com.cand")
    _session(db_session, baseline, adapter="adb", observations=[
        {"type": "JAVA", "class": "com.x.Web", "method": "onCreate"}])
    _session(db_session, candidate, adapter="adb", observations=[
        {"type": "JAVA", "class": "com.x.Web", "method": "onCreate"},
        {"type": "NATIVE", "symbol": "strcpy"}])
    _native(db_session, candidate)
    RV.build_runtime_validation(db_session, baseline)
    RV.build_runtime_validation(db_session, candidate)

    class _C: pass
    cmp = _C(); cmp.baseline = baseline; cmp.candidate = candidate
    result = runtime_validation_from_diff(cmp)
    assert result["status"] == "OK"
    assert any(ch["transition"] == "NEWLY_OBSERVED" for ch in result["changes"])


def test_diff_runtime_unavailable_when_not_both_live(db_session, make_analysis):
    from app.analysis.runtime_validation import runtime_validation_from_diff
    baseline = make_analysis(package="com.base")
    candidate = make_analysis(package="com.cand")
    _session(db_session, baseline, adapter="adb", observations=[
        {"type": "JAVA", "class": "com.x.Web", "method": "onCreate"}])
    _session(db_session, candidate, adapter="mock", observations=[
        {"type": "JAVA", "class": "com.x.Web", "method": "onCreate"}])
    RV.build_runtime_validation(db_session, baseline)
    RV.build_runtime_validation(db_session, candidate)

    class _C: pass
    cmp = _C(); cmp.baseline = baseline; cmp.candidate = candidate
    result = runtime_validation_from_diff(cmp)
    assert result["status"] == "RUNTIME_OBSERVATION_UNAVAILABLE"


# ---------------------------------------------------------------------------
# Determinism / idempotency / isolation / evidence chain
# ---------------------------------------------------------------------------


def test_deterministic_fingerprint_and_idempotent(db_session, make_analysis):
    a = make_analysis()
    _session(db_session, a, adapter="adb", observations=[
        {"type": "JAVA", "class": "com.x.Web", "method": "onCreate"},
        {"type": "JAVA", "class": "android.webkit.WebView", "method": "loadUrl"}])
    run1 = RV.build_runtime_validation(db_session, a)
    n = len(a.runtime_correlations)
    fp1 = run1.fingerprint
    run2 = RV.build_runtime_validation(db_session, a)
    assert len(a.runtime_correlations) == n  # idempotent, no duplicates
    assert run2.fingerprint == fp1 and run1.id != run2.id  # content-derived


def test_fingerprint_ignores_db_ids(db_session, make_analysis):
    # Same package + same runtime content -> identical fingerprint despite
    # different DB ids (content-derived; no DB id / timestamp participates).
    a1 = make_analysis()
    a2 = make_analysis()
    for a in (a1, a2):
        a.runtime_sessions.clear()
        db_session.flush()
        _session(db_session, a, adapter="adb", observations=[
            {"type": "JAVA", "class": "com.x.Web", "method": "onCreate"}])
    r1 = RV.build_runtime_validation(db_session, a1)
    r2 = RV.build_runtime_validation(db_session, a2)
    assert r1.fingerprint == r2.fingerprint


def test_cross_analysis_isolation(db_session, make_analysis):
    a1 = make_analysis(package="com.a")
    a2 = make_analysis(package="com.b")
    a2.runtime_sessions.clear()  # a2 has no runtime evidence of its own
    db_session.flush()
    _session(db_session, a1, adapter="adb", observations=[
        {"type": "JAVA", "class": "com.x.Web", "method": "onCreate"}])
    RV.build_runtime_validation(db_session, a1)
    RV.build_runtime_validation(db_session, a2)
    assert len(a1.runtime_correlations) >= 1
    assert len(a2.runtime_correlations) == 0  # no leakage across analyses
    assert all(c.analysis_id == a1.id for c in a1.runtime_correlations)


def test_evidence_chain_has_provenance(db_session, make_analysis):
    a = make_analysis()
    _session(db_session, a, adapter="adb", observations=[
        {"type": "JAVA", "class": "android.webkit.WebView", "method": "loadUrl"}])
    RV.build_runtime_validation(db_session, a)
    chain = RV.runtime_explain(a, "ANDROID-REACH-001")
    steps = {s["step"] for s in chain["chain"]}
    assert "FINDING" in steps and "CURRENT_VALIDATION_STATE" in steps
    assert all("provenance" in s for s in chain["chain"])
    assert "exploit" not in chain["note"].lower() or "no exploit" in chain["note"].lower()


def test_investigation_pins_runtime_and_timeline_correlation(db_session, make_analysis):
    from app.analysis import investigation as INV
    a = make_analysis()
    _session(db_session, a, adapter="adb", observations=[
        {"type": "JAVA", "class": "com.x.Web", "method": "onCreate"}])
    RV.build_runtime_validation(db_session, a)
    inv = INV.create_investigation(db_session, a, name="rt")
    corr = a.runtime_correlations[0]
    # a researcher can pin a runtime correlation (generic node pinning)
    node = INV.add_node(db_session, inv, f"RUNTIME_CORRELATION:{corr.fingerprint}",
                        node_type="RUNTIME_CORRELATION", label=corr.detail[:40])
    assert node is not None
    INV.rebuild_timeline(db_session, inv, a)
    events = {e.event_type for e in inv.timeline_events}
    assert "CORRELATION" in events and "LIVE_OBSERVATION" in events
    # hypotheses/notes never mutate analytical truth — findings untouched by pinning
    assert all(f.runtime_validation_state for f in a.findings)


def test_report_and_no_exploitable(db_session, make_analysis):
    import json
    from app.reports.json_report import build_report
    a = make_analysis()
    _session(db_session, a, adapter="adb", observations=[
        {"type": "JAVA", "class": "android.webkit.WebView", "method": "loadUrl"}])
    RV.build_runtime_validation(db_session, a)
    report = build_report(a, db_session)
    rv = report["runtime_validation"]
    assert rv["mode"] == "LIVE"
    assert set(rv) >= {"mode", "summary", "correlations", "blockers", "provenance", "uncertainties"}
    assert "exploitable" not in json.dumps(rv).lower()

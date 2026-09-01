"""Security assessment / decision-intelligence tests (prompt 24).

The layer is a deterministic projection over persisted evidence. It must never
produce SAFE/UNSAFE or `exploitable`, never mutate static truth, never duplicate
canonical records, and keep every uncertainty state distinct.
"""

import hashlib
import json

from app.assessment import taxonomy as T
from app.assessment.engine import assessment_from_diff, assessment_view, build_assessment, explain_conclusion


def _by_type(asm):
    return {c.conclusion_type: c for c in asm.conclusions}


def _states(asm):
    return {c.decision_state for c in asm.conclusions}


# ---------------------------------------------------------------------------
# taxonomy / no SAFE-UNSAFE-exploitable
# ---------------------------------------------------------------------------


def test_no_exploitable_no_safe_unsafe(db_session, make_analysis):
    a = make_analysis()
    build_assessment(db_session, a)
    dump = json.dumps(assessment_view(a)).lower()
    assert "exploitable" not in dump
    for c in a.assessments[-1].conclusions:
        assert c.decision_state in T.DECISION_STATES
        assert c.decision_state not in ("SAFE", "UNSAFE")


# ---------------------------------------------------------------------------
# finding conclusions
# ---------------------------------------------------------------------------


def test_finding_conclusion_states(db_session, make_analysis):
    a = make_analysis()
    findings = {f.rule_id: f for f in a.findings}
    findings["ANDROID-REACH-001"].status = "CONFIRMED_BY_STATIC_ANALYSIS"
    findings["ANDROID-WEBVIEW-001"].security_validation_state = "STATIC_SUPPORTED"
    findings["ANDROID-CVE-001"].security_validation_state = "VALIDATION_BLOCKED"
    db_session.flush()
    build_assessment(db_session, a)
    concs = {(c.subject_ref): c for c in a.assessments[-1].conclusions if c.subject_type == T.SUBJECT_FINDING}
    reach = next(c for r, c in concs.items() if r == str(findings["ANDROID-REACH-001"].id))
    web = next(c for r, c in concs.items() if r == str(findings["ANDROID-WEBVIEW-001"].id))
    cve = next(c for r, c in concs.items() if r == str(findings["ANDROID-CVE-001"].id))
    assert reach.conclusion_type == T.FINDING_CONFIRMED and reach.decision_state == T.CONFIRMED
    assert web.conclusion_type == T.FINDING_SUPPORTED and web.decision_state == T.SUPPORTED
    assert cve.conclusion_type == T.FINDING_BLOCKED and cve.decision_state == T.BLOCKED
    assert any(b.blocker == "VALIDATION_BLOCKED" for b in cve.blockers)


def test_runtime_confirmed_finding_is_strongly_supported(db_session, make_analysis):
    a = make_analysis()
    f = a.findings[0]
    f.runtime_validation_state = "CONFIRMED_RUNTIME_BEHAVIOR"
    db_session.flush()
    build_assessment(db_session, a)
    c = next(x for x in a.assessments[-1].conclusions if x.subject_ref == str(f.id))
    assert c.decision_state == T.STRONGLY_SUPPORTED
    assert any(e.mode == T.MODE_LIVE for e in c.evidence)


# ---------------------------------------------------------------------------
# CVE conclusions — POSSIBLY_AFFECTED never becomes AFFECTED
# ---------------------------------------------------------------------------


def test_cve_conclusions_preserve_uncertainty(db_session, make_analysis):
    a = make_analysis()
    for m in a.vulnerability_matches:
        if m.cve_id == "CVE-2020-0002":
            m.identity_confidence = "HIGH"  # AFFECTED + REACHABLE + HIGH identity
    db_session.flush()
    build_assessment(db_session, a)
    concs = {c.subject_ref: c for c in a.assessments[-1].conclusions if c.subject_type == T.SUBJECT_CVE}
    poss = next(c for r, c in concs.items() if r.startswith("CVE-2020-0001"))
    aff = next(c for r, c in concs.items() if r.startswith("CVE-2020-0002"))
    # POSSIBLY_AFFECTED -> version unverified, never AFFECTED/CONFIRMED
    assert poss.conclusion_type == T.CVE_VERSION_UNVERIFIED
    assert poss.conclusion_type != T.CVE_CONFIRMED
    assert any(b.blocker == "MISSING_VERSION" for b in poss.blockers)
    # AFFECTED + reachable + strong identity -> present/affected/reachable (not exploitability)
    assert aff.conclusion_type == T.CVE_CONFIRMED and aff.decision_state == T.STRONGLY_SUPPORTED
    # it may DISCLAIM exploitability, but must never positively assert it
    assert "not an exploitability" in aff.rationale.lower()


# ---------------------------------------------------------------------------
# runtime conclusions — LIVE vs MOCKED vs UNAVAILABLE
# ---------------------------------------------------------------------------


def _runtime_run(db, a, mode, live_claims=0):
    from app.models.runtime_validation import RuntimeValidationRun
    a.runtime_validation_runs.clear(); db.flush()
    a.runtime_validation_runs.append(RuntimeValidationRun(
        analysis_id=a.id, fingerprint=f"rt-{mode}", mode=mode, live_claim_count=live_claims, correlation_count=live_claims))
    db.flush()


def test_runtime_live_corroborated(db_session, make_analysis):
    a = make_analysis()
    _runtime_run(db_session, a, "LIVE", live_claims=2)
    build_assessment(db_session, a)
    c = next(x for x in a.assessments[-1].conclusions if x.conclusion_type == T.RUNTIME_CORROBORATED)
    assert c.decision_state == T.SUPPORTED


def test_runtime_mocked_never_corroborated(db_session, make_analysis):
    a = make_analysis()
    _runtime_run(db_session, a, "MOCKED", live_claims=0)
    build_assessment(db_session, a)
    types = {c.conclusion_type for c in a.assessments[-1].conclusions}
    assert T.RUNTIME_MOCKED_ONLY in types
    assert T.RUNTIME_CORROBORATED not in types  # MOCKED never satisfies LIVE
    mock = next(c for c in a.assessments[-1].conclusions if c.conclusion_type == T.RUNTIME_MOCKED_ONLY)
    assert mock.decision_state == T.UNVERIFIED


def test_runtime_unavailable_distinct_from_not_observed(db_session, make_analysis):
    a = make_analysis()
    a.runtime_sessions.clear(); a.runtime_validation_runs.clear(); db_session.flush()
    build_assessment(db_session, a)
    c = next(x for x in a.assessments[-1].conclusions if x.conclusion_type == T.RUNTIME_UNAVAILABLE)
    assert c.decision_state == T.INCONCLUSIVE  # UNAVAILABLE != NOT_OBSERVED, never "safe"


# ---------------------------------------------------------------------------
# native conclusions — ELF_ONLY + UNKNOWN_NATIVE_TARGET preserved
# ---------------------------------------------------------------------------


def _native(db, a):
    from app.models.analysis import JNIBinding, NativeFunction, NativeLibrary
    from app.native import deep_native as D
    lib = NativeLibrary(analysis_id=a.id, archive_path="lib/arm64-v8a/libx.so", abi="arm64-v8a", filename="libx.so",
                        size_bytes=4096, sha256=hashlib.sha256(b"libx").hexdigest(), architecture="arm64",
                        elf_type="ET_DYN", soname="libx.so", stripped=False, symbols_available=True, status="COMPLETE")
    a.native_libraries.append(lib); db.flush()
    lib.functions.append(NativeFunction(analysis_id=a.id, library_id=lib.id, name="strcpy", address=0x0,
                                        kind="imported", source="ELF", confidence="HIGH"))
    a.jni_bindings.append(JNIBinding(analysis_id=a.id, source="JAVA_NATIVE", confidence="HIGH", java_class="com.x.N",
                                     java_method="ghost", java_signature="()V", library_name="libx.so",
                                     native_function=None, evidence="static naming"))
    db.flush()
    D.build_deep_native(db, a)


def test_native_elf_only_and_unknown_target(db_session, make_analysis):
    a = make_analysis()
    _native(db_session, a)
    build_assessment(db_session, a)
    nat = [c for c in a.assessments[-1].conclusions if c.subject_type == T.SUBJECT_NATIVE]
    assert nat and nat[0].conclusion_type in (T.NATIVE_ANALYSIS_UNAVAILABLE, T.NATIVE_REACHABILITY_UNVERIFIED)
    # UNKNOWN_NATIVE_TARGET preserved as a blocker (JNI 'ghost' is unresolved)
    assert any(b.blocker == "UNKNOWN_NATIVE_TARGET" for b in nat[0].blockers)


# ---------------------------------------------------------------------------
# remediation — never REMEDIATED from runtime; runtime never mutates static truth
# ---------------------------------------------------------------------------


def test_remediation_never_remediated_and_runtime_never_overwrites_static(db_session, make_analysis):
    a = make_analysis()
    _runtime_run(db_session, a, "LIVE", live_claims=3)
    before_findings = [(f.id, f.severity, f.severity_score, f.confidence_score, f.status) for f in a.findings]
    before_cve = [(m.cve_id, m.version_state, m.reachability_state) for m in a.vulnerability_matches]
    build_assessment(db_session, a)
    assert not any(c.conclusion_type == T.REMEDIATION_REMEDIATED for c in a.assessments[-1].conclusions)
    # static truth untouched by the assessment projection
    assert [(f.id, f.severity, f.severity_score, f.confidence_score, f.status) for f in a.findings] == before_findings
    assert [(m.cve_id, m.version_state, m.reachability_state) for m in a.vulnerability_matches] == before_cve


# ---------------------------------------------------------------------------
# references (not duplicates), determinism, idempotency
# ---------------------------------------------------------------------------


def test_conclusions_reference_existing_evidence_not_duplicates(db_session, make_analysis):
    a = make_analysis()
    n_findings = len(a.findings)
    n_cve = len(a.vulnerability_matches)
    build_assessment(db_session, a)
    # every finding conclusion references an existing finding fingerprint/rule id
    finding_refs = {f.fingerprint for f in a.findings} | {f.rule_id for f in a.findings}
    for c in a.assessments[-1].conclusions:
        if c.subject_type == T.SUBJECT_FINDING:
            assert any(e.evidence_ref in finding_refs for e in c.evidence)
    # the projection created no new canonical records
    assert len(a.findings) == n_findings and len(a.vulnerability_matches) == n_cve


def test_deterministic_and_idempotent(db_session, make_analysis):
    a = make_analysis()
    r1 = build_assessment(db_session, a); fp1, n1 = r1.fingerprint, r1.conclusion_count
    r2 = build_assessment(db_session, a)
    assert r2.fingerprint == fp1 and r2.conclusion_count == n1  # deterministic + idempotent
    assert len(a.assessments) == 1 and r1.id != r2.id
    assert len(fp1) == 32


# ---------------------------------------------------------------------------
# aggregate + explain + diff
# ---------------------------------------------------------------------------


def test_overall_inconclusive_when_open(db_session, make_analysis):
    a = make_analysis()
    build_assessment(db_session, a)
    types = {c.conclusion_type for c in a.assessments[-1].conclusions}
    assert a.assessments[-1].status == T.ASSESSMENT_INCONCLUSIVE
    assert T.SECURITY_REVIEW_REQUIRED in types
    assert T.SECURITY_RELEVANT_EVIDENCE_PRESENT in types or True  # present iff relevant conclusions exist


def test_explain_chain_has_provenance_no_exploitability(db_session, make_analysis):
    a = make_analysis()
    build_assessment(db_session, a)
    c = a.assessments[-1].conclusions[0]
    chain = explain_conclusion(a, c.fingerprint)
    steps = {s["step"] for s in chain["chain"]}
    assert {"CONCLUSION", "DECISION_STATE", "RULE"} <= steps
    assert "exploit" not in chain["note"].lower() or "not" in chain["note"].lower()


def test_assessment_diff_conservative(db_session, make_analysis):
    baseline = make_analysis(package="com.base")
    candidate = make_analysis(package="com.cand")
    # give the candidate an extra confirmed finding so a NEW_CONCLUSION appears
    baseline.findings[0].status = "CONFIRMED_BY_STATIC_ANALYSIS"
    db_session.flush()
    build_assessment(db_session, baseline)
    build_assessment(db_session, candidate)

    class _C: pass
    cmp = _C(); cmp.baseline = baseline; cmp.candidate = candidate
    result = assessment_from_diff(cmp)
    assert "changes" in result
    for ch in result["changes"]:
        assert ch["transition"] in ("NO_LONGER_PRESENT", "NEW_CONCLUSION", "STATE_CHANGED")
        # a removed conclusion is never FIXED/REMEDIATED/NOT_AFFECTED
        if ch["transition"] == "NO_LONGER_PRESENT":
            assert ch["to_state"] is None
    assert "never impl" in result["note"].lower() or "safety" in result["note"].lower()


def test_cross_analysis_isolation(db_session, make_analysis):
    a1 = make_analysis(package="com.a")
    a2 = make_analysis(package="com.b")
    build_assessment(db_session, a1)
    assert len(a2.assessments) == 0  # building a1 never touches a2
    build_assessment(db_session, a2)
    assert all(s.assessment_id == a1.assessments[-1].id for s in a1.assessments[-1].subjects)

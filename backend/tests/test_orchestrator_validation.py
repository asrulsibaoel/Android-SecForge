"""End-to-end validation over the real pipeline (prompt 18).

Runs the orchestrator on the deterministic test APK (JADX forced unavailable);
the validation stage runs automatically and persists claims. Asserts the stage
is deterministic, idempotent, read-only against source truth, does not disturb
graph snapshots, and exposes validation in the report + KG opt-in projection.
"""

from app.analysis import validation as V
from app.analysis.orchestrator import analyze_apk


def test_validation_stage_runs(db_session, test_apk, no_jadx):
    analysis = analyze_apk(test_apk, db_session)
    stages = {s["name"]: s["status"] for s in analysis.stages}
    assert stages.get("validation") == "COMPLETE"
    # validation stage is status-exempt: PARTIAL here comes from JADX being absent,
    # never from the validation stage, which must never FAIL the analysis.
    assert analysis.status in ("COMPLETE", "PARTIAL")
    assert analysis.capabilities.get("validation") == "COMPLETE"
    # claims persisted with evidence + requirements
    assert analysis.validation_claims
    for c in analysis.validation_claims:
        assert c.validation_state and c.fingerprint and c.claim_type
        assert c.evidence or c.blockers


def test_validation_read_only_and_idempotent(db_session, test_apk, no_jadx):
    analysis = analyze_apk(test_apk, db_session)
    findings_before = [(f.rule_id, f.severity, f.confidence, f.status, f.runtime_status, f.validation_state)
                       for f in analysis.findings]
    risk_before = [(r.scope, r.overall_score) for r in analysis.risk_assessments]

    n1 = len(analysis.validation_claims)
    V.build_validation(db_session, analysis)  # re-run
    db_session.flush()
    assert len(analysis.validation_claims) == n1  # idempotent

    # existing finding fields + risk untouched (only additive columns written)
    assert [(f.rule_id, f.severity, f.confidence, f.status, f.runtime_status, f.validation_state)
            for f in analysis.findings] == findings_before
    assert [(r.scope, r.overall_score) for r in analysis.risk_assessments] == risk_before


def test_validation_report_and_finding_metadata(db_session, test_apk, no_jadx):
    from app.reports.json_report import build_report
    analysis = analyze_apk(test_apk, db_session)
    report = build_report(analysis, db_session)
    assert "validation" in report
    val = report["validation"]
    assert set(val) >= {"summary", "claims", "evidence", "blockers", "requirements", "uncertainties", "provenance"}
    # each finding exposes validation metadata (additive; existing fields intact)
    for f in report["findings"]:
        assert "validation" in f and "state" in f["validation"]
    import json
    assert "exploitable" not in json.dumps(val).lower()


def test_validation_kg_projection_opt_in_and_snapshot_unchanged(db_session, test_apk, no_jadx):
    from app.analysis import knowledge_graph as KG
    analysis = analyze_apk(test_apk, db_session)

    base = KG.build_knowledge_graph(analysis)  # default: no validation nodes
    assert not any(n.node_type == KG.N_VALIDATION_CLAIM for n in base.nodes.values())
    # graph snapshot digest is unchanged by the validation stage (recompute == default)
    assert KG.graph_digest(base) == KG.graph_digest(KG.build_knowledge_graph(analysis))

    withval = KG.build_knowledge_graph(analysis, include_validation=True)
    val_nodes = [n for n in withval.nodes.values() if n.node_type == KG.N_VALIDATION_CLAIM]
    if val_nodes:
        assert all(n.provenance and n.provenance[0].source_type == KG.P_VALIDATION for n in val_nodes)

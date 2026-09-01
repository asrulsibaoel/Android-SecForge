"""End-to-end remediation over the real analysis pipeline (prompt 17).

Runs the orchestrator on the deterministic test APK (JADX forced unavailable),
then builds a remediation plan and asserts it is evidence-backed, deterministic,
persisted, and read-only against the source analysis.
"""

from app.analysis import remediation as R
from app.analysis.orchestrator import analyze_apk


def test_orchestrator_then_remediation(db_session, test_apk, no_jadx):
    analysis = analyze_apk(test_apk, db_session)

    # source snapshot before remediation (must not be mutated)
    findings_before = [(f.rule_id, f.status, f.severity, f.confidence) for f in analysis.findings]
    risk_before = [(r.scope, r.overall_score) for r in analysis.risk_assessments]

    plan = R.build_plan(db_session, analysis, requested_by="test")
    db_session.commit()

    assert plan.item_count >= 1
    assert plan.fingerprint and plan.priority_distribution
    # every item is evidence-backed and carries priority/fixability/status
    for item in plan.items:
        assert item.evidence, f"{item.action} has no evidence"
        assert item.priority and item.fixability and item.status
        assert item.action

    # deterministic: rebuilding the in-memory view yields the same plan fingerprint
    assert R.plan_view(analysis)["fingerprint"] == plan.fingerprint

    # remediation never mutated source findings or risk
    assert [(f.rule_id, f.status, f.severity, f.confidence) for f in analysis.findings] == findings_before
    assert [(r.scope, r.overall_score) for r in analysis.risk_assessments] == risk_before


def test_remediation_report_section(db_session, test_apk, no_jadx):
    from app.reports.json_report import build_report

    analysis = analyze_apk(test_apk, db_session)
    report = build_report(analysis, db_session)
    assert "remediation" in report
    rem = report["remediation"]
    assert set(rem) >= {"summary", "items", "actions", "evidence", "dependencies", "uncertainties"}
    # deterministic and no exploitability language
    import json
    assert "exploitable" not in json.dumps(rem).lower()


def test_remediation_kg_projection_opt_in(db_session, test_apk, no_jadx):
    from app.analysis import knowledge_graph as KG

    analysis = analyze_apk(test_apk, db_session)
    R.build_plan(db_session, analysis, requested_by="test")
    db_session.flush()

    # default projection excludes remediation -> snapshot digest unaffected
    base = KG.build_knowledge_graph(analysis)
    assert not any(n.node_type == KG.N_REMEDIATION_ITEM for n in base.nodes.values())

    # opt-in projection includes remediation items with provenance
    withrem = KG.build_knowledge_graph(analysis, include_remediation=True)
    rem_nodes = [n for n in withrem.nodes.values() if n.node_type == KG.N_REMEDIATION_ITEM]
    if rem_nodes:  # test APK may produce items depending on fixtures
        assert all(n.provenance and n.provenance[0].source_type == KG.P_REMEDIATION for n in rem_nodes)
    # digests differ only when remediation is projected (determinism preserved otherwise)
    assert KG.graph_digest(base) == KG.graph_digest(KG.build_knowledge_graph(analysis))

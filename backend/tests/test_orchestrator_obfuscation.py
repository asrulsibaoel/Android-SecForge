"""End-to-end obfuscation over the real pipeline (prompt 19).

Runs the orchestrator on the deterministic test APK (JADX forced unavailable);
the obfuscation stage runs automatically. Asserts it is status-safe, read-only,
deterministic, exposed in the report, and KG-opt-in (snapshot-safe).
"""

from app.analysis import obfuscation as O
from app.analysis.orchestrator import analyze_apk


def test_obfuscation_stage_runs_status_safe(db_session, test_apk, no_jadx):
    analysis = analyze_apk(test_apk, db_session)
    stages = {s["name"]: s["status"] for s in analysis.stages}
    # JADX absent -> identifier/string/control-flow categories are UNAVAILABLE,
    # but the stage must not fail the analysis (status-safe).
    assert stages.get("obfuscation") in ("COMPLETE", "PARTIAL")
    assert analysis.status in ("COMPLETE", "PARTIAL")
    assert analysis.capabilities.get("obfuscation") == "COMPLETE"


def test_obfuscation_read_only_and_idempotent(db_session, test_apk, no_jadx):
    analysis = analyze_apk(test_apk, db_session)
    findings_before = [(f.rule_id, f.severity, f.confidence, f.status) for f in analysis.findings]
    risk_before = [(r.scope, r.overall_score) for r in analysis.risk_assessments]
    matches_before = [(m.cve_id, m.version_state) for m in analysis.vulnerability_matches]

    n1 = len(analysis.obfuscation_observations)
    O.build_obfuscation(db_session, analysis)  # re-run
    db_session.flush()
    assert len(analysis.obfuscation_observations) == n1  # idempotent, no duplicates

    assert [(f.rule_id, f.severity, f.confidence, f.status) for f in analysis.findings] == findings_before
    assert [(r.scope, r.overall_score) for r in analysis.risk_assessments] == risk_before
    assert [(m.cve_id, m.version_state) for m in analysis.vulnerability_matches] == matches_before


def test_obfuscation_report_section(db_session, test_apk, no_jadx):
    from app.reports.json_report import build_report
    analysis = analyze_apk(test_apk, db_session)
    report = build_report(analysis, db_session)
    assert "obfuscation" in report
    obf = report["obfuscation"]
    assert set(obf) >= {"summary", "score", "observations", "anti_analysis", "analysis_impacts",
                        "uncertainties", "provenance"}
    assert 0 <= obf["score"]["score"] <= 100
    import json
    assert "exploitable" not in json.dumps(obf).lower()


def test_obfuscation_kg_projection_opt_in_snapshot_unchanged(db_session, test_apk, no_jadx):
    from app.analysis import knowledge_graph as KG
    analysis = analyze_apk(test_apk, db_session)

    base = KG.build_knowledge_graph(analysis)  # default: no obfuscation nodes
    assert not any(n.node_type == KG.N_OBFUSCATION_OBSERVATION for n in base.nodes.values())
    # snapshot digest unchanged by the obfuscation stage
    assert KG.graph_digest(base) == KG.graph_digest(KG.build_knowledge_graph(analysis))

    withobf = KG.build_knowledge_graph(analysis, include_obfuscation=True)
    obf_nodes = [n for n in withobf.nodes.values()
                 if n.node_type in (KG.N_OBFUSCATION_OBSERVATION, KG.N_ANTI_ANALYSIS_INDICATOR, KG.N_ANALYSIS_IMPACT)]
    if obf_nodes:
        assert all(n.provenance and n.provenance[0].source_type == KG.P_OBFUSCATION for n in obf_nodes)

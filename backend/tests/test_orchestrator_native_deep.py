"""End-to-end deep native / Ghidra correlation over the real pipeline (prompt 20).

Runs the orchestrator on the deterministic test APK (JADX + Ghidra unavailable);
the native_deep stage runs automatically in ELF-only mode. Asserts it is
status-safe, read-only, deterministic, exposed in the report, and KG-opt-in
(snapshot-safe). A native APK (real .so) exercises real ELF/JNI evidence when a
host C compiler is available.
"""

from app.analysis.orchestrator import analyze_apk
from app.native import deep_native as D


def test_native_deep_stage_status_safe_without_ghidra(db_session, test_apk, no_jadx):
    analysis = analyze_apk(test_apk, db_session)
    stages = {s["name"]: s["status"] for s in analysis.stages}
    # Ghidra absent and (test APK) no native libs -> stage must never fail analysis.
    assert "native_deep" in stages
    assert stages["native_deep"] in ("COMPLETE", "PARTIAL", "UNAVAILABLE")
    assert analysis.status in ("COMPLETE", "PARTIAL")
    assert analysis.capabilities.get("ghidra_deep") == "UNAVAILABLE"


def test_native_deep_read_only_and_idempotent(db_session, test_apk, no_jadx):
    analysis = analyze_apk(test_apk, db_session)
    findings_before = [(f.rule_id, f.severity, f.confidence, f.status, f.validation_state)
                       for f in analysis.findings]
    risk_before = [(r.scope, r.overall_score) for r in analysis.risk_assessments]
    matches_before = [(m.cve_id, m.version_state, m.reachability_state) for m in analysis.vulnerability_matches]

    n_bin = len(analysis.native_binaries)
    n_fn = len(analysis.native_deep_functions)
    D.build_deep_native(db_session, analysis)  # re-run
    db_session.flush()
    assert len(analysis.native_binaries) == n_bin  # idempotent, no duplicates
    assert len(analysis.native_deep_functions) == n_fn

    # Existing findings / risk / CVE state untouched.
    assert [(f.rule_id, f.severity, f.confidence, f.status, f.validation_state)
            for f in analysis.findings] == findings_before
    assert [(r.scope, r.overall_score) for r in analysis.risk_assessments] == risk_before
    assert [(m.cve_id, m.version_state, m.reachability_state)
            for m in analysis.vulnerability_matches] == matches_before


def test_native_deep_report_section(db_session, test_apk, no_jadx):
    from app.reports.json_report import build_report
    import json
    analysis = analyze_apk(test_apk, db_session)
    report = build_report(analysis, db_session)
    assert "native_deep_analysis" in report
    section = report["native_deep_analysis"]
    assert set(section) >= {"capability", "summary", "binaries", "functions", "jni_bindings",
                            "call_edges", "api_paths", "evidence", "uncertainties"}
    # Never asserts exploitability anywhere in the section.
    assert "exploitable" not in json.dumps(section).lower()


def test_native_deep_kg_projection_opt_in_snapshot_unchanged(db_session, test_apk, no_jadx):
    from app.analysis import knowledge_graph as KG
    analysis = analyze_apk(test_apk, db_session)

    base = KG.build_knowledge_graph(analysis)
    assert not any(n.node_type == KG.N_NATIVE_ANALYSIS for n in base.nodes.values())
    # snapshot digest is unaffected by the native_deep stage (default projection).
    assert KG.graph_digest(base) == KG.graph_digest(KG.build_knowledge_graph(analysis))

    withnat = KG.build_knowledge_graph(analysis, include_native_deep=True)
    nat_nodes = [n for n in withnat.nodes.values()
                 if n.node_type in (KG.N_NATIVE_ANALYSIS, KG.N_NATIVE_BINARY, KG.N_NATIVE_DEEP_FUNCTION,
                                    KG.N_NATIVE_API, KG.N_NATIVE_DEEP_JNI)]
    for n in nat_nodes:
        assert n.provenance and n.provenance[0].source_type in (KG.P_GHIDRA, KG.P_ELF, KG.P_JNI)


def test_native_apk_real_elf_evidence(db_session, native_apk, no_jadx):
    """With a real compiled .so, ELF-only mode must produce real native evidence."""
    analysis = analyze_apk(native_apk, db_session)
    stages = {s["name"]: s["status"] for s in analysis.stages}
    assert stages.get("native_deep") in ("COMPLETE", "PARTIAL")
    run = D._latest_run(analysis)
    assert run is not None and run.mode == D.MODE_ELF_ONLY
    assert run.binaries_count >= 1
    assert len(analysis.native_binaries) >= 1
    # Real ELF, no Ghidra -> no fabricated call-chain reachability.
    assert not any(o.state == D.API_REACHED for o in analysis.native_api_observations)

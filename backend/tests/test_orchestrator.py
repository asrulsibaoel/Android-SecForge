from app.analysis import jadx as jadx_engine
from app.analysis.orchestrator import analyze_apk
from app.models.analysis import Analysis, EvidenceModel, FindingModel


def _stage(analysis, name):
    return next(stage for stage in analysis.stages if stage["name"] == name)


def test_pipeline_partial_when_jadx_unavailable(db_session, test_apk, no_jadx):
    analysis = analyze_apk(test_apk, db_session)

    assert analysis.status == "PARTIAL"
    assert analysis.capabilities["jadx"] == "UNAVAILABLE"
    assert analysis.capabilities["code_analysis"] == "UNAVAILABLE"
    assert _stage(analysis, "manifest")["status"] == "COMPLETE"
    assert _stage(analysis, "dex")["status"] == "COMPLETE"
    assert _stage(analysis, "code_index")["status"] == "SKIPPED"


def test_pipeline_persists_relational_analysis(db_session, test_apk, no_jadx):
    analysis = analyze_apk(test_apk, db_session)

    persisted = db_session.get(Analysis, analysis.id)
    assert persisted.manifest.package == "com.androidsecforge.testapp"
    assert persisted.manifest.source_format == "binary_axml"
    assert len(persisted.components) == 6
    assert sum(1 for component in persisted.components if component.effective_exported) == 5
    assert len(persisted.dex_artifacts) == 2
    assert {permission.protection_level for permission in persisted.permissions} >= {"DANGEROUS", "NORMAL", "UNKNOWN"}

    rule_ids = {finding.rule_id for finding in persisted.findings}
    assert {
        "ANDROID-MANIFEST-001",
        "ANDROID-MANIFEST-002",
        "ANDROID-MANIFEST-003",
        "ANDROID-COMPONENT-001",
        "ANDROID-COMPONENT-002",
    } <= rule_ids

    # provenance
    assert persisted.ruleset_version
    assert persisted.tool_versions["python"]


def test_evidence_is_persisted_and_linked(db_session, test_apk, no_jadx):
    analysis = analyze_apk(test_apk, db_session)
    provider_finding = next(f for f in analysis.findings if f.rule_id == "ANDROID-COMPONENT-002")
    assert provider_finding.evidence
    evidence = provider_finding.evidence[0]
    assert evidence.source == "manifest"
    assert "provider" in evidence.location
    # evidence rows exist independently in the table
    total_evidence = db_session.query(EvidenceModel).count()
    assert total_evidence >= 1
    assert db_session.query(FindingModel).count() == len(analysis.findings)


def test_pipeline_complete_with_mocked_jadx(db_session, test_apk, monkeypatch):
    def fake_run_jadx(apk_path, output_dir, timeout=None):
        sources = output_dir / "sources" / "com" / "x"
        sources.mkdir(parents=True, exist_ok=True)
        (sources / "WebActivity.java").write_text(
            "package com.x;\nclass WebActivity {\n  void f() { w.getSettings().setJavaScriptEnabled(true); }\n}\n"
        )
        return jadx_engine.JadxResult(
            status=jadx_engine.SUCCESS,
            version="jadx 1.4.7",
            output_dir=str(output_dir),
            sources_dir=str(output_dir / "sources"),
            duration_seconds=0.1,
            exit_code=0,
        )

    monkeypatch.setattr(jadx_engine, "run_jadx", fake_run_jadx)
    analysis = analyze_apk(test_apk, db_session)

    assert analysis.status == "COMPLETE"
    assert analysis.capabilities["jadx"] == "AVAILABLE"
    assert analysis.capabilities["code_analysis"] == "COMPLETE"
    assert any(entity.entity_type == "class" for entity in analysis.code_entities)
    assert "ANDROID-WEBVIEW-001" in {finding.rule_id for finding in analysis.findings}


def test_failure_in_one_stage_does_not_abort_pipeline(db_session, test_apk, no_jadx, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("dex exploded")

    monkeypatch.setattr("app.analysis.orchestrator.extract_dex", boom)
    analysis = analyze_apk(test_apk, db_session)

    assert analysis.status == "PARTIAL"
    assert _stage(analysis, "dex")["status"] == "FAILED"
    assert _stage(analysis, "manifest")["status"] == "COMPLETE"
    assert any("dex exploded" in error for error in analysis.errors)

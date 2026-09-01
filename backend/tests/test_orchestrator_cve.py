from app.analysis import jadx as jadx_engine
from app.analysis.orchestrator import analyze_apk
from app.models.analysis import Analysis
from app.services.cve_store import import_fixtures
from app.testapp.builder import PACKAGE


def _stage(analysis, name):
    return next(s for s in analysis.stages if s["name"] == name)


def test_cve_stages_offline_no_db(db_session, native_apk, no_jadx):
    """With an empty local CVE DB, analysis still completes with 0 matches."""
    analysis = analyze_apk(native_apk, db_session)
    assert _stage(analysis, "dependency_fingerprint")["status"] == "COMPLETE"
    assert _stage(analysis, "vulnerability_match")["status"] == "COMPLETE"
    persisted = db_session.get(Analysis, analysis.id)
    assert len(persisted.dependencies) >= 1  # bundled native libs
    assert persisted.vulnerability_matches == []
    assert analysis.capabilities["cve_analysis"] == "COMPLETE"


def test_cve_pipeline_with_fixtures_and_jadx(db_session, native_apk, monkeypatch):
    import_fixtures(db_session)  # populate local CVE DB before analysis

    def fake_run_jadx(apk_path, output_dir, timeout=None):
        pkg = output_dir / "sources" / "okhttp3"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "OkHttpClient.java").write_text("package okhttp3;\nclass OkHttpClient { void run(){} }\n")
        return jadx_engine.JadxResult(
            status=jadx_engine.SUCCESS, version="jadx 1.5.6", output_dir=str(output_dir),
            sources_dir=str(output_dir / "sources"), duration_seconds=0.1, exit_code=0)

    monkeypatch.setattr(jadx_engine, "run_jadx", fake_run_jadx)
    analysis = analyze_apk(native_apk, db_session)
    persisted = db_session.get(Analysis, analysis.id)

    assert any(d.name == "okhttp" for d in persisted.dependencies)
    okhttp_match = next((m for m in persisted.vulnerability_matches if m.dependency.name == "okhttp"), None)
    assert okhttp_match is not None
    # version unknown (no embedded metadata) -> POSSIBLY_AFFECTED, never AFFECTED
    assert okhttp_match.version_state == "POSSIBLY_AFFECTED"
    assert okhttp_match.correlation_state == "PRESENT_UNKNOWN_VERSION"
    assert any(f.rule_id == "ANDROID-CVE-002" for f in persisted.findings if f.category == "cve")

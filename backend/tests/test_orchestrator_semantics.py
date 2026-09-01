from app.analysis import jadx as jadx_engine
from app.analysis.orchestrator import analyze_apk
from app.models.analysis import Analysis
from app.testapp.builder import PACKAGE


def _stage(analysis, name):
    return next(s for s in analysis.stages if s["name"] == name)


def test_semantics_persist_without_jadx(db_session, native_apk, no_jadx):
    analysis = analyze_apk(native_apk, db_session)
    assert _stage(analysis, "semantics")["status"] == "COMPLETE"
    persisted = db_session.get(Analysis, analysis.id)
    # exported components from the manifest become security boundaries even without Java
    assert any(b.boundary_type == "EXTERNAL_INTENT" for b in persisted.security_boundaries)
    # the fixture's manifest declares a deep link (asftest://open)
    assert any(d.scheme == "asftest" for d in persisted.deep_links)
    # JNI boundary recorded from the native fixture
    assert any(b.boundary_type == "JNI" for b in persisted.security_boundaries)


def test_semantic_findings_with_mocked_jadx(db_session, native_apk, monkeypatch):
    def fake_run_jadx(apk_path, output_dir, timeout=None):
        pkg = output_dir / "sources" / PACKAGE.replace(".", "/")
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "MainActivity.java").write_text(
            f"package {PACKAGE};\n"
            "class MainActivity {\n"
            "  public void onCreate() {\n"
            '    String url = getIntent().getStringExtra("url");\n'
            "    web.loadUrl(url);\n"
            '    web.addJavascriptInterface(new Bridge(), "androidBridge");\n'
            "  }\n"
            "}\n"
        )
        return jadx_engine.JadxResult(
            status=jadx_engine.SUCCESS, version="jadx 1.5.6", output_dir=str(output_dir),
            sources_dir=str(output_dir / "sources"), duration_seconds=0.1, exit_code=0,
        )

    monkeypatch.setattr(jadx_engine, "run_jadx", fake_run_jadx)
    analysis = analyze_apk(native_apk, db_session)
    persisted = db_session.get(Analysis, analysis.id)

    assert analysis.capabilities["semantics"] == "COMPLETE"
    assert any(ep.component == ".MainActivity" and ep.lifecycle_event == "CREATE"
               for ep in persisted.android_entry_points)
    assert any(e.edge_type == "FRAMEWORK_DISPATCH" for e in persisted.semantic_edges)
    semantic = {f.rule_id for f in persisted.findings if f.category == "semantic"}
    assert "ANDROID-SEMANTIC-001" in semantic  # exported activity receives external input
    assert "ANDROID-SEMANTIC-004" in semantic  # WebView JS interface exposed

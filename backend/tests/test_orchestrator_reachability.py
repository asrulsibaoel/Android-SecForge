from app.analysis import jadx as jadx_engine
from app.analysis.orchestrator import analyze_apk
from app.models.analysis import Analysis
from app.testapp.builder import PACKAGE


def _stage(analysis, name):
    return next(s for s in analysis.stages if s["name"] == name)


def test_graph_and_reachability_persist_without_jadx(db_session, native_apk, no_jadx):
    analysis = analyze_apk(native_apk, db_session)
    assert _stage(analysis, "graph")["status"] == "COMPLETE"
    assert _stage(analysis, "reachability")["status"] == "COMPLETE"
    persisted = db_session.get(Analysis, analysis.id)
    # exported components from the manifest become entry points
    assert len(persisted.entry_points) >= 1
    # the native fixture imports strcpy -> a native security sink is recorded
    assert any(s.category == "native" and s.api == "strcpy" for s in persisted.security_sinks)
    # no Java sources (jadx unavailable) -> reachability capability degraded, no fabricated paths
    assert analysis.capabilities["reachability"] == "DEGRADED"


def test_reachability_finding_persisted_with_mocked_jadx(db_session, native_apk, monkeypatch):
    """Full pipeline with a controlled decompiled source: exported Activity whose
    onCreate reads an Intent extra and passes it to WebView.loadUrl."""

    def fake_run_jadx(apk_path, output_dir, timeout=None):
        pkg_dir = output_dir / "sources" / PACKAGE.replace(".", "/")
        pkg_dir.mkdir(parents=True, exist_ok=True)
        (pkg_dir / "MainActivity.java").write_text(
            f"package {PACKAGE};\n"
            "class MainActivity {\n"
            "  public void onCreate() {\n"
            '    String url = getIntent().getStringExtra("url");\n'
            "    web.loadUrl(url);\n"
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
    assert analysis.capabilities["reachability"] == "COMPLETE"
    assert any(s.api == "Intent.getStringExtra" for s in persisted.dataflow_sources)
    assert any(s.api == "WebView.loadUrl" for s in persisted.security_sinks)
    assert persisted.reachability_paths
    reach = [f for f in persisted.findings if f.category == "reachability"]
    assert any(f.rule_id == "ANDROID-REACH-001" and f.status == "REACHABLE" for f in reach)
    # evidence chain is recorded relationally
    finding = next(f for f in reach if f.rule_id == "ANDROID-REACH-001")
    assert finding.evidence and all(e.source == "reachability" for e in finding.evidence)

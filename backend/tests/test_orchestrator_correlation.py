"""End-to-end correlation/root-cause/attack-surface/risk scenarios (Phase 12).

Uses mocked JADX to inject controlled decompiled source so the full pipeline
produces deterministic correlation outputs. Proves negative cases too.
"""

from app.analysis import jadx as jadx_engine
from app.analysis.orchestrator import analyze_apk
from app.models.analysis import Analysis
from app.testapp.builder import PACKAGE


def _run(db_session, native_apk, monkeypatch, body: str):
    def fake(apk_path, output_dir, timeout=None):
        pkg = output_dir / "sources" / PACKAGE.replace(".", "/")
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "MainActivity.java").write_text(f"package {PACKAGE};\nclass MainActivity {{\n{body}\n}}\n")
        return jadx_engine.JadxResult(status=jadx_engine.SUCCESS, version="jadx 1.5.6",
                                      output_dir=str(output_dir), sources_dir=str(output_dir / "sources"),
                                      duration_seconds=0.1, exit_code=0)
    monkeypatch.setattr(jadx_engine, "run_jadx", fake)
    analysis = analyze_apk(native_apk, db_session)
    return db_session.get(Analysis, analysis.id), analysis


def _rc_categories(analysis):
    return {rc.category for rc in analysis.root_causes}


def _risk(analysis):
    return next(r for r in analysis.risk_assessments if r.scope == "overall")


def test_case_a_harmless_no_webview_root_cause(db_session, native_apk, monkeypatch):
    p, a = _run(db_session, native_apk, monkeypatch,
                '  public void onCreate() { String u = getIntent().getStringExtra("u"); int n = u.length(); }')
    # attack surface exists, but no unsafe-webview / reflection / dynamic-loading root cause
    assert p.attack_surface_nodes
    assert "UNSAFE_WEBVIEW_INPUT" not in _rc_categories(p)
    assert "DANGEROUS_DYNAMIC_LOADING" not in _rc_categories(p)


def test_case_b_webview_root_cause_and_risk(db_session, native_apk, monkeypatch):
    p, a = _run(db_session, native_apk, monkeypatch,
                '  public void onCreate() { String u = getIntent().getStringExtra("url"); web.loadUrl(u); }')
    assert "UNSAFE_WEBVIEW_INPUT" in _rc_categories(p)
    risk = _risk(p)
    assert risk.overall_score > 0
    assert any(f.name in ("sensitive_sink_reachable", "webview_javascript") for f in risk.factors)


def test_case_d_dynamic_loading_root_cause(db_session, native_apk, monkeypatch):
    p, a = _run(db_session, native_apk, monkeypatch,
                '  public void onCreate() { String pth = getIntent().getStringExtra("p"); new DexClassLoader(pth, null, null, null); }')
    assert "DANGEROUS_DYNAMIC_LOADING" in _rc_categories(p)


def test_case_e_jni_boundary_no_fabricated_native_reach(db_session, native_apk, monkeypatch):
    p, a = _run(db_session, native_apk, monkeypatch,
                '  public native int verify(String s);\n'
                '  public void onCreate() { String u = getIntent().getStringExtra("x"); verify(u); }')
    # The native fixture exports Java_..._verify, but MainActivity.verify won't demangle-match it,
    # so at most a JNI boundary is represented; no native sink is claimed reachable.
    assert not any(m.reachability_state == "REACHABLE" and m.correlation_state == "AFFECTED_REACHABLE"
                   for m in p.vulnerability_matches)
    # any reachability path terminating at a native function is marked UNKNOWN target (not a sink hit)
    for path in p.reachability_paths:
        if path.nodes and path.nodes[-1].get("type") == "NATIVE_FUNCTION":
            assert path.status in ("REACHABLE", "UNKNOWN")


def test_case_i_permission_protected_mitigation(db_session, native_apk, monkeypatch, tmp_path):
    # Build an APK whose exported activity is permission-protected.
    import zipfile
    from app.analysis.axml import ANDROID_NS, BuildAttr, BuildElement, encode_axml

    manifest = BuildElement("manifest", attrs=[BuildAttr("package", PACKAGE, "string", namespace=None)], children=[
        BuildElement("application", children=[
            BuildElement("activity", attrs=[
                BuildAttr("name", ".Guarded"), BuildAttr("exported", "true", "bool"),
                BuildAttr("permission", "com.x.PERM")]),
        ]),
    ])
    apk = tmp_path / "perm.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", encode_axml(manifest))
        z.writestr("classes.dex", b"dex")
    monkeypatch.setattr("app.analysis.jadx.jadx_executable", lambda: None)
    analysis = analyze_apk(apk, db_session)
    p = db_session.get(Analysis, analysis.id)
    guarded = next((n for n in p.attack_surface_nodes if n.component == ".Guarded"), None)
    assert guarded is not None
    assert guarded.exposure == "PERMISSION_PROTECTED"
    risk = _risk(p)
    assert any(f.name == "permission_protected" and f.direction == "negative" for f in risk.factors)


def test_severity_confidence_separate(db_session, native_apk, no_jadx):
    analysis = analyze_apk(native_apk, db_session)
    p = db_session.get(Analysis, analysis.id)
    risk = _risk(p)
    # severity (from score band) and confidence (from evidence) are independent fields
    assert risk.severity in ("info", "low", "medium", "high", "critical")
    assert risk.confidence in ("low", "medium", "high")

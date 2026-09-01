import json
from uuid import UUID

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.cli as cli
from app.core.config import settings
from app.db.session import Base
from app.testapp.builder import build_native_test_apk, build_test_apk, compile_native_fixture


@pytest.fixture
def cli_env(tmp_path, monkeypatch, no_jadx):
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path / "artifacts"))
    monkeypatch.setattr(settings, "workspace_path", str(tmp_path / "workspace"))
    engine = create_engine(f"sqlite:///{tmp_path / 'cli.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(cli, "SessionLocal", factory)
    monkeypatch.setattr(cli, "initialize_database", lambda: None)
    return tmp_path


def test_cli_analyze_reports_status_and_capabilities(cli_env, capsys):
    apk = build_test_apk(cli_env / "app.apk")
    cli.analyze(apk)
    out = capsys.readouterr().out
    assert "analysis_id=" in out
    assert "status=PARTIAL" in out
    assert "jadx=UNAVAILABLE" in out
    assert "ANDROID-COMPONENT-002" in out


def test_cli_analyze_json_is_machine_readable(cli_env, capsys):
    apk = build_test_apk(cli_env / "app.apk")
    cli.analyze(apk, as_json=True)
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "androidsecforge.report/1"
    assert payload["apk"]["package_name"] == "com.androidsecforge.testapp"
    assert payload["summary"]["total_findings"] == 9
    assert payload["manifest"]["source_format"] == "binary_axml"


def test_cli_findings_by_analysis_id(cli_env, capsys):
    apk = build_test_apk(cli_env / "app.apk")
    cli.analyze(apk)
    out = capsys.readouterr().out
    analysis_id = next(line.split("=", 1)[1] for line in out.splitlines() if line.startswith("analysis_id="))

    cli.show_findings(UUID(analysis_id), as_json=True)
    findings = json.loads(capsys.readouterr().out)
    assert any(finding["rule_id"] == "ANDROID-COMPONENT-002" for finding in findings)

    cli.inspect_dex(UUID(analysis_id))
    dex_out = capsys.readouterr().out
    assert "dex_files=2" in dex_out


def test_cli_native_commands(cli_env, capsys):
    so = compile_native_fixture(cli_env / "libasfnative.so")
    if so is None:
        pytest.skip("no host C compiler available")
    apk = build_native_test_apk(cli_env / "native.apk", so)
    cli.analyze(apk)
    out = capsys.readouterr().out
    analysis_id = next(line.split("=", 1)[1] for line in out.splitlines() if line.startswith("analysis_id="))
    aid = UUID(analysis_id)

    cli.native_list(aid, as_json=True)
    libs = json.loads(capsys.readouterr().out)
    assert len(libs) == 2
    assert {lib["abi"] for lib in libs} == {"arm64-v8a", "armeabi-v7a"}

    cli.native_jni(aid, as_json=True)
    bindings = json.loads(capsys.readouterr().out)
    assert any(b["source"] == "ELF_EXPORT" for b in bindings)

    cli.native_functions(aid, as_json=True)
    funcs = json.loads(capsys.readouterr().out)
    assert any(f["is_jni"] for f in funcs)


def test_cli_graph_commands(cli_env, capsys):
    so = compile_native_fixture(cli_env / "libasfnative.so")
    if so is None:
        pytest.skip("no host C compiler available")
    apk = build_native_test_apk(cli_env / "native.apk", so)
    cli.analyze(apk)
    out = capsys.readouterr().out
    aid = UUID(next(line.split("=", 1)[1] for line in out.splitlines() if line.startswith("analysis_id=")))

    cli.graph_build(aid, as_json=True)
    summary = json.loads(capsys.readouterr().out)
    assert summary["entry_points"] >= 1
    assert "sinks" in summary

    cli.graph_entrypoints(aid, as_json=True)
    entrypoints = json.loads(capsys.readouterr().out)
    assert len(entrypoints) >= 1

    cli.graph_sinks(aid, as_json=True)
    sinks = json.loads(capsys.readouterr().out)
    assert any(s["category"] == "native" for s in sinks)

    # a path query with no connecting route returns a non-REACHABLE status, not a fabricated path
    cli.graph_paths(aid, from_query="MainActivity", to_query="strcpy", as_json=True)
    result = json.loads(capsys.readouterr().out)
    assert result["status"] in ("NOT_REACHABLE", "UNKNOWN")
    assert result["paths"] == []


def test_cli_semantic_commands(cli_env, capsys):
    so = compile_native_fixture(cli_env / "libasfnative.so")
    if so is None:
        pytest.skip("no host C compiler available")
    apk = build_native_test_apk(cli_env / "native.apk", so)
    cli.analyze(apk)
    out = capsys.readouterr().out
    aid = UUID(next(line.split("=", 1)[1] for line in out.splitlines() if line.startswith("analysis_id=")))

    cli.semantic_boundaries(aid, as_json=True)
    boundaries = json.loads(capsys.readouterr().out)
    assert any(b["boundary_type"] == "EXTERNAL_INTENT" for b in boundaries)

    cli.semantic_deeplinks(aid, as_json=True)
    deeplinks = json.loads(capsys.readouterr().out)
    assert any(d["scheme"] == "asftest" for d in deeplinks)

    cli.semantic_entrypoints(aid, as_json=True)
    assert isinstance(json.loads(capsys.readouterr().out), list)


def test_cli_cve_and_dependency_commands(cli_env, capsys):
    so = compile_native_fixture(cli_env / "libasfnative.so")
    if so is None:
        pytest.skip("no host C compiler available")
    apk = build_native_test_apk(cli_env / "native.apk", so)

    # import fixtures into the (shared) local CVE DB used by the cli SessionLocal
    cli.cve_import_fixtures()
    fixtures = json.loads(capsys.readouterr().out)
    assert fixtures["imported"] >= 1

    cli.cve_search("okhttp", as_json=True)
    results = json.loads(capsys.readouterr().out)
    assert any(r["cve_id"] == "CVE-TEST-0001" for r in results)

    cli.cve_show("CVE-TEST-0001", as_json=True)
    show = json.loads(capsys.readouterr().out)
    assert show["products"][0]["product"] == "okhttp"

    cli.analyze(apk)
    out = capsys.readouterr().out
    aid = UUID(next(line.split("=", 1)[1] for line in out.splitlines() if line.startswith("analysis_id=")))

    cli.dependency_list(aid, as_json=True)
    deps = json.loads(capsys.readouterr().out)
    assert any(d["kind"] == "native" for d in deps)

    # re-correlate against the local CVE DB (offline flow)
    cli.cve_analyze(aid, as_json=True)
    report = json.loads(capsys.readouterr().out)
    assert "dependencies" in report and "matches" in report and "states" in report


def test_cli_risk_and_surface_commands(cli_env, capsys):
    so = compile_native_fixture(cli_env / "libasfnative.so")
    if so is None:
        pytest.skip("no host C compiler available")
    apk = build_native_test_apk(cli_env / "native.apk", so)
    cli.analyze(apk)
    out = capsys.readouterr().out
    aid = UUID(next(line.split("=", 1)[1] for line in out.splitlines() if line.startswith("analysis_id=")))

    cli.risk_summary(aid, as_json=True)
    risk = json.loads(capsys.readouterr().out)
    assert 0 <= risk["overall_score"] <= 100
    assert risk["severity"] in ("info", "low", "medium", "high", "critical")

    cli.risk_explain(aid, as_json=True)
    explain = json.loads(capsys.readouterr().out)
    assert isinstance(explain["factors"], list)

    cli.root_causes_list(aid, as_json=True)
    root_causes = json.loads(capsys.readouterr().out)
    assert isinstance(root_causes, list)

    cli.attack_surface_list(aid, as_json=True)
    surface = json.loads(capsys.readouterr().out)
    assert any(n["exposure"] in ("PUBLIC", "UNKNOWN", "INTERNAL") for n in surface)

    cli.graph_export(aid, fmt="json")
    graph = json.loads(capsys.readouterr().out)
    assert "nodes" in graph and "edges" in graph


def test_cli_report_is_reproducible(cli_env, capsys):
    apk = build_test_apk(cli_env / "app.apk")
    cli.analyze(apk, as_json=True)
    first = json.loads(capsys.readouterr().out)
    cli.analyze(apk, as_json=True)
    second = json.loads(capsys.readouterr().out)
    # Findings, permissions, and components are order-stable and content-identical
    # across runs (ids/timestamps aside).
    assert [f["rule_id"] for f in first["findings"]] == [f["rule_id"] for f in second["findings"]]
    assert first["summary"] == second["summary"]
    assert first["permissions"] == second["permissions"]

import subprocess
from pathlib import Path

from app.analysis import ghidra as ghidra_engine


def test_unavailable_when_not_installed(monkeypatch, tmp_path):
    monkeypatch.setattr(ghidra_engine, "analyze_headless_executable", lambda: None)
    result = ghidra_engine.analyze_library(tmp_path / "libx.so", tmp_path / "proj")
    assert result.status == ghidra_engine.UNAVAILABLE
    assert result.error


def test_process_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(ghidra_engine, "analyze_headless_executable", lambda: "/opt/ghidra/support/analyzeHeadless")
    monkeypatch.setattr(ghidra_engine, "_version", lambda executable: "11.0")

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, returncode=1, stdout="", stderr="boom")

    monkeypatch.setattr(ghidra_engine.subprocess, "run", fake_run)
    result = ghidra_engine.analyze_library(tmp_path / "libx.so", tmp_path / "proj")
    assert result.status == ghidra_engine.FAILED
    assert result.exit_code == 1
    assert result.functions == []


def test_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(ghidra_engine, "analyze_headless_executable", lambda: "/opt/ghidra/support/analyzeHeadless")

    def fake_run(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="analyzeHeadless", timeout=1)

    monkeypatch.setattr(ghidra_engine.subprocess, "run", fake_run)
    result = ghidra_engine.analyze_library(tmp_path / "libx.so", tmp_path / "proj", timeout=1)
    assert result.status == ghidra_engine.TIMEOUT


def test_success_parses_emitted_functions(monkeypatch, tmp_path):
    monkeypatch.setattr(ghidra_engine, "analyze_headless_executable", lambda: "/opt/ghidra/support/analyzeHeadless")
    monkeypatch.setattr(ghidra_engine, "_version", lambda executable: "11.0")
    proj = tmp_path / "proj"

    def fake_run(args, **kwargs):
        proj.mkdir(parents=True, exist_ok=True)
        (proj / "libx.so.functions.json").write_text(
            '{"functions": [{"name": "sub_1000", "address": "0x1000", "size": 42, "namespace": "global"}]}'
        )
        return subprocess.CompletedProcess(args, returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(ghidra_engine.subprocess, "run", fake_run)
    result = ghidra_engine.analyze_library(tmp_path / "libx.so", proj)
    assert result.status == ghidra_engine.SUCCESS
    assert result.functions[0].name == "sub_1000"
    assert result.functions[0].source == "Ghidra"

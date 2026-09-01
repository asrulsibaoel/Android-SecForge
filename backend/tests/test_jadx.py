import subprocess
from pathlib import Path

import pytest

from app.analysis import jadx as jadx_engine


@pytest.fixture
def apk(tmp_path) -> Path:
    path = tmp_path / "app.apk"
    path.write_bytes(b"PK\x03\x04placeholder")
    return path


def test_unavailable_when_not_installed(monkeypatch, apk, tmp_path):
    monkeypatch.setattr(jadx_engine, "jadx_executable", lambda: None)
    result = jadx_engine.run_jadx(apk, tmp_path / "out")
    assert result.status == jadx_engine.UNAVAILABLE
    assert result.error


def test_timeout(monkeypatch, apk, tmp_path):
    monkeypatch.setattr(jadx_engine, "jadx_executable", lambda: "/opt/jadx")
    monkeypatch.setattr(jadx_engine, "jadx_version", lambda executable=None: "jadx 1.4.7")

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="jadx", timeout=1)

    monkeypatch.setattr(jadx_engine.subprocess, "run", fake_run)
    result = jadx_engine.run_jadx(apk, tmp_path / "out", timeout=1)
    assert result.status == jadx_engine.TIMEOUT
    assert result.version == "jadx 1.4.7"


def test_failed_when_no_sources(monkeypatch, apk, tmp_path):
    monkeypatch.setattr(jadx_engine, "jadx_executable", lambda: "/opt/jadx")
    monkeypatch.setattr(jadx_engine, "jadx_version", lambda executable=None: "jadx 1.4.7")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args, returncode=1, stdout="", stderr="boom")

    monkeypatch.setattr(jadx_engine.subprocess, "run", fake_run)
    result = jadx_engine.run_jadx(apk, tmp_path / "out")
    assert result.status == jadx_engine.FAILED
    assert result.exit_code == 1


def test_success_with_produced_sources(monkeypatch, apk, tmp_path):
    out = tmp_path / "out"
    monkeypatch.setattr(jadx_engine, "jadx_executable", lambda: "/opt/jadx")
    monkeypatch.setattr(jadx_engine, "jadx_version", lambda executable=None: "jadx 1.4.7")

    def fake_run(args, **kwargs):
        sources = out / "sources" / "com"
        sources.mkdir(parents=True, exist_ok=True)
        (sources / "A.java").write_text("class A {}")
        return subprocess.CompletedProcess(args, returncode=0, stdout="done", stderr="")

    monkeypatch.setattr(jadx_engine.subprocess, "run", fake_run)
    result = jadx_engine.run_jadx(apk, out)
    assert result.status == jadx_engine.SUCCESS
    assert result.sources_dir is not None
    assert Path(result.sources_dir, "com", "A.java").exists()

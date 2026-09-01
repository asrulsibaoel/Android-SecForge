"""Web intake & execution workflow tests (prompt 26).

Intake bounds are backend-authoritative; the execution wrapper never fabricates
completion or progress, preserves capability limitations honestly, and reports
cancellation as unavailable for the monolithic in-process pipeline. The real
analysis pipeline is mocked here so the tests are fast and deterministic — the
wrapper (not the analyzer) is what these exercise.
"""

import time
import uuid
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from app.main import app
import app.services.execution as EX


@pytest.fixture(autouse=True)
def _reset():
    EX._reset_for_tests()
    yield
    EX._reset_for_tests()


# --- intake bounds (backend-authoritative) ---------------------------------

def test_rejects_unsupported_extension():
    r = TestClient(app).post("/api/v1/apk/import", files={"file": ("evil.txt", b"not an apk", "text/plain")})
    assert r.status_code == 400
    assert "APK" in r.json()["detail"]


def test_rejects_empty_artifact():
    r = TestClient(app).post("/api/v1/apk/import", files={"file": ("empty.apk", b"", "application/vnd.android.package-archive")})
    assert r.status_code == 400
    assert "empty" in r.json()["detail"].lower()


def test_rejects_oversized_artifact(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "upload_max_file_size", 4)
    r = TestClient(app).post("/api/v1/apk/import", files={"file": ("big.apk", b"way too many bytes", "application/octet-stream")})
    assert r.status_code == 413
    assert "maximum size" in r.json()["detail"].lower()


# --- execution lifecycle honesty -------------------------------------------

class _FakeManifest:
    def __init__(self, package):
        self.package = package


class _FakeAnalysis:
    def __init__(self, status, capabilities, stages, package="com.x"):
        self.id = uuid.uuid4()
        self.apk_id = uuid.uuid4()
        self.status = status
        self.capabilities = capabilities
        self.stages = stages
        self.manifest = _FakeManifest(package)
        self.started_at = None
        self.completed_at = None


@contextmanager
def _fake_session():
    yield object()


def _mock_pipeline(monkeypatch, analysis=None, raises=None):
    monkeypatch.setattr("app.db.session.SessionLocal", lambda: _fake_session())

    def fake_analyze(path, db):
        if raises is not None:
            raise raises
        return analysis

    monkeypatch.setattr("app.analysis.orchestrator.analyze_apk", fake_analyze)


def _wait_terminal(exec_id, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        e = EX.get_execution(exec_id)
        if e and e["state"] in EX.TERMINAL_STATES:
            return e
        time.sleep(0.02)
    return EX.get_execution(exec_id)


def test_partial_analysis_is_completed_with_limitations(monkeypatch):
    a = _FakeAnalysis("PARTIAL", {"code_analysis": "COMPLETE", "ghidra": "UNAVAILABLE", "native_deep": "PARTIAL"},
                      stages=[{"name": "manifest", "status": "COMPLETE"}, {"name": "ghidra", "status": "SKIPPED"}])
    _mock_pipeline(monkeypatch, analysis=a)
    snap = EX.start_execution("art-1", "/tmp/x.apk", artifact_meta={"filename": "x.apk"})
    assert snap["execution_id"] and snap["state"] in ({EX.QUEUED, EX.RUNNING} | EX.TERMINAL_STATES)
    e = _wait_terminal(snap["execution_id"])
    assert e["state"] == EX.COMPLETED_WITH_LIMITATIONS  # PARTIAL never fabricated into COMPLETED
    assert e["analysis_id"] == str(a.id)
    caps = {c["capability"]: c["state"] for c in e["capability_limitations"]}
    assert caps.get("ghidra") == "UNAVAILABLE"  # limitation stays visible
    assert "code_analysis" not in caps  # a COMPLETE capability is not a limitation


def test_complete_analysis_is_completed(monkeypatch):
    a = _FakeAnalysis("COMPLETE", {"code_analysis": "COMPLETE"}, stages=[{"name": "manifest", "status": "COMPLETE"}])
    _mock_pipeline(monkeypatch, analysis=a)
    e = _wait_terminal(EX.start_execution("art", "/tmp/x.apk")["execution_id"])
    assert e["state"] == EX.COMPLETED and not e["capability_limitations"]


def test_failed_analysis_is_failed_not_empty(monkeypatch):
    _mock_pipeline(monkeypatch, raises=RuntimeError("ingest blew up at /secret/path/artifacts/abc.apk"))
    e = _wait_terminal(EX.start_execution("art", "/tmp/x.apk")["execution_id"])
    assert e["state"] == EX.FAILED
    assert e["error"] and e["error"]["retryable"] is True and e["error"]["code"] == "RuntimeError"
    # bounded, non-leaky message; failure is not an empty/complete result
    assert e["analysis_id"] is None
    assert e["state"] not in (EX.COMPLETED, EX.COMPLETED_WITH_LIMITATIONS)


def test_no_fabricated_progress_stages_come_from_pipeline(monkeypatch):
    stages = [{"name": "ingest", "status": "COMPLETE"}, {"name": "manifest", "status": "COMPLETE"},
              {"name": "native_deep", "status": "PARTIAL"}]
    a = _FakeAnalysis("PARTIAL", {"native_deep": "PARTIAL"}, stages=stages)
    _mock_pipeline(monkeypatch, analysis=a)
    e = _wait_terminal(EX.start_execution("art", "/tmp/x.apk")["execution_id"])
    assert e["stages"] == stages  # exactly the pipeline's stages, nothing invented


def test_progress_sink_reports_real_stage_names():
    # The orchestrator hook forwards real stage names/statuses; default is a no-op.
    from app.analysis.orchestrator import _emit_progress, clear_progress_sink, set_progress_sink

    seen = []
    set_progress_sink(lambda name, stages: seen.append((name, len(stages))))
    try:
        class _S:
            def __init__(self, n): self.n = n
            def to_dict(self): return {"name": self.n, "status": "COMPLETE"}
        _emit_progress("manifest", [_S("ingest"), _S("manifest")])
    finally:
        clear_progress_sink()
    assert seen == [("manifest", 2)]
    # after clearing, emitting is a no-op (never breaks the analysis)
    _emit_progress("x", [])
    assert len(seen) == 1


def test_cancellation_unavailable(monkeypatch):
    started = {"go": False}

    def slow_analyze(path, db):
        while not started["go"]:
            time.sleep(0.01)
        return _FakeAnalysis("COMPLETE", {}, stages=[])

    monkeypatch.setattr("app.db.session.SessionLocal", lambda: _fake_session())
    monkeypatch.setattr("app.analysis.orchestrator.analyze_apk", slow_analyze)
    snap = EX.start_execution("art", "/tmp/x.apk")
    time.sleep(0.05)
    result = EX.cancel_execution(snap["execution_id"])
    assert result["status"] == "CANCELLATION_UNAVAILABLE"
    started["go"] = True
    _wait_terminal(snap["execution_id"])

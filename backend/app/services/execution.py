"""Web analysis execution service (prompt 26).

A thin, bounded, in-process wrapper around the EXISTING authoritative pipeline
(`app.analysis.orchestrator.analyze_apk`). It adds only an operational execution
lifecycle + live stage progress — no second analysis pipeline, no new analytical
truth, no new database table. Durable state remains the `Analysis` (status/stages)
and `APKArtifact` (input provenance) records; the live progress here is ephemeral
operational state held in-process (single-worker server).

Nothing is fabricated: a stage's real status comes straight from the orchestrator,
capability limitations from the persisted analysis capabilities, and completion is
only ever reported after `analyze_apk` actually returns.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import settings

# --- lifecycle states (operational, not analytical) ------------------------
INTAKE_VALIDATED = "INTAKE_VALIDATED"
QUEUED = "QUEUED"
RUNNING = "RUNNING"
COMPLETED = "COMPLETED"
COMPLETED_WITH_LIMITATIONS = "COMPLETED_WITH_LIMITATIONS"
FAILED = "FAILED"
CANCELLED = "CANCELLED"

TERMINAL_STATES = {COMPLETED, COMPLETED_WITH_LIMITATIONS, FAILED, CANCELLED}

# capability states that count as a "limitation" (never a success).
_LIMITATION_STATES = {"UNAVAILABLE", "DEGRADED", "PARTIAL", "SKIPPED", "NOT_CONNECTED", "MISSING",
                      "CAPABILITY_UNAVAILABLE"}

_lock = threading.Lock()
_executions: dict[str, dict] = {}
_by_analysis: dict[str, str] = {}
_semaphore = threading.BoundedSemaphore(max(1, settings.analysis_max_concurrent_executions))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _snapshot(exec_id: str) -> dict | None:
    with _lock:
        e = _executions.get(exec_id)
        return dict(e) if e else None


def start_execution(artifact_id: str, storage_path: str, requested_by: str = "web",
                    artifact_meta: dict | None = None) -> dict:
    """Register an execution for an already-validated artifact and start it in the
    background. Returns the initial execution snapshot (state QUEUED)."""
    exec_id = str(uuid.uuid4())
    with _lock:
        _executions[exec_id] = {
            "execution_id": exec_id,
            "artifact_id": artifact_id,
            "analysis_id": None,
            "state": QUEUED,
            "current_stage": None,
            "stages": [],
            "error": None,
            "capability_limitations": [],
            "artifact": artifact_meta or {},
            "created_at": _now(),
            "started_at": None,
            "ended_at": None,
            "requested_by": requested_by,
        }
    thread = threading.Thread(target=_run, args=(exec_id, storage_path), daemon=True,
                              name=f"asf-exec-{exec_id[:8]}")
    thread.start()
    return _snapshot(exec_id)  # type: ignore[return-value]


def _update(exec_id: str, **fields) -> None:
    with _lock:
        e = _executions.get(exec_id)
        if e is not None:
            e.update(fields)


def _run(exec_id: str, storage_path: str) -> None:
    from app.analysis.orchestrator import analyze_apk, clear_progress_sink, set_progress_sink
    from app.db.session import SessionLocal

    acquired = _semaphore.acquire(timeout=settings.runtime_validation_timeout_seconds * 2)
    if not acquired:
        _update(exec_id, state=FAILED, ended_at=_now(),
                error={"code": "QUEUE_TIMEOUT", "message": "timed out waiting for an execution slot",
                       "stage": None, "retryable": True})
        return
    try:
        _update(exec_id, state=RUNNING, started_at=_now())

        def sink(stage_name: str, stages: list[dict]) -> None:
            _update(exec_id, current_stage=stage_name, stages=stages)

        set_progress_sink(sink)
        try:
            with SessionLocal() as db:
                analysis = analyze_apk(Path(storage_path), db)
                caps = analysis.capabilities or {}
                limitations = [{"capability": k, "state": v} for k, v in sorted(caps.items())
                               if str(v).upper() in _LIMITATION_STATES]
                status = (analysis.status or "").upper()
                if status == "COMPLETE":
                    state = COMPLETED
                elif status == "FAILED":
                    state = FAILED
                else:  # PARTIAL (or anything non-terminal-complete) -> completed with limitations
                    state = COMPLETED_WITH_LIMITATIONS if status == "PARTIAL" else COMPLETED_WITH_LIMITATIONS
                aid = str(analysis.id)
                with _lock:
                    _by_analysis[aid] = exec_id
                _update(exec_id, state=state, analysis_id=aid, ended_at=_now(),
                        stages=analysis.stages or [], capability_limitations=limitations,
                        artifact={**(_snapshot(exec_id) or {}).get("artifact", {}),
                                  "package": (analysis.manifest.package if analysis.manifest else None)})
        finally:
            clear_progress_sink()
    except Exception as error:  # honest failure — never a fabricated empty result
        snap = _snapshot(exec_id) or {}
        _update(exec_id, state=FAILED, ended_at=_now(),
                error={"code": type(error).__name__, "message": _bounded_message(error),
                       "stage": snap.get("current_stage"), "retryable": True})
    finally:
        _semaphore.release()


def _bounded_message(error: Exception) -> str:
    # A short, non-leaky message (no stack traces / no absolute paths).
    msg = str(error).strip().splitlines()[0] if str(error).strip() else type(error).__name__
    msg = msg.replace(str(Path(settings.artifact_storage_path).resolve()), "<artifact>")
    return msg[:300]


def get_execution(exec_id: str) -> dict | None:
    return _snapshot(exec_id)


def get_execution_by_analysis(analysis_id: str) -> dict | None:
    with _lock:
        exec_id = _by_analysis.get(analysis_id)
    return _snapshot(exec_id) if exec_id else None


def cancel_execution(exec_id: str) -> dict:
    """Cooperative cancellation is not supported for the monolithic in-process
    pipeline (§13) — report it honestly rather than killing a process unsafely."""
    snap = _snapshot(exec_id)
    if snap is None:
        return {"status": "NOT_FOUND"}
    if snap["state"] in TERMINAL_STATES:
        return {"status": "ALREADY_TERMINAL", "state": snap["state"]}
    return {"status": "CANCELLATION_UNAVAILABLE",
            "reason": "the analysis pipeline runs as a single bounded in-process task and cannot be "
                      "cooperatively cancelled; it will run to completion.",
            "state": snap["state"]}


def _reset_for_tests() -> None:  # pragma: no cover - test helper
    with _lock:
        _executions.clear()
        _by_analysis.clear()

"""Web analysis execution service (prompt 26).

A thin, bounded wrapper around the EXISTING authoritative pipeline
(`app.analysis.orchestrator.analyze_apk`). It adds only an operational execution
lifecycle + live stage progress — no second analysis pipeline, no new analytical
truth, no new database table. Durable state remains the `Analysis` (status/stages)
and `APKArtifact` (input provenance) records; the live progress here is ephemeral
operational state held in-process.

Concurrency model — why a separate PROCESS, not a thread:
    `analyze_apk` is CPU-bound *Python* work (graph build, code index, correlation,
    ELF parsing, marshalling Ghidra output). Running it in a thread inside the web
    server lets it monopolise the CPython GIL and starve uvicorn's event loop, so
    every request — including the progress poll — hangs until it yields. With jadx +
    Ghidra deep enabled a run takes minutes, so the UI appears frozen. Running it in
    a child process (its own interpreter/GIL) keeps the server fully responsive; a
    lightweight manager thread drains the child's progress over a queue into the
    in-memory registry that the poll API reads. Tests flip `_INLINE_FOR_TESTS` to run
    the same core inline so they can mock the pipeline in-process.

Nothing is fabricated: a stage's real status comes straight from the orchestrator,
capability limitations from the persisted analysis capabilities, and completion is
only ever reported after `analyze_apk` actually returns.
"""

from __future__ import annotations

import multiprocessing
import queue as _queue
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

# Run the analysis in a worker process (production). Tests set this True to run the
# same core inline (in-process) so `analyze_apk`/`SessionLocal` mocks apply.
_INLINE_FOR_TESTS = False


def _mp_context():
    """A start method that does NOT re-exec the server: prefer forkserver (clean,
    single-threaded server forks workers), then fork, then spawn."""
    methods = multiprocessing.get_all_start_methods()
    method = "forkserver" if "forkserver" in methods else ("fork" if "fork" in methods else "spawn")
    return multiprocessing.get_context(method)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _snapshot(exec_id: str) -> dict | None:
    with _lock:
        e = _executions.get(exec_id)
        return dict(e) if e else None


def _update(exec_id: str, **fields) -> None:
    with _lock:
        e = _executions.get(exec_id)
        if e is not None:
            e.update(fields)


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
    thread = threading.Thread(target=_manage, args=(exec_id, storage_path), daemon=True,
                              name=f"asf-mgr-{exec_id[:8]}")
    thread.start()
    return _snapshot(exec_id)  # type: ignore[return-value]


def _manage(exec_id: str, storage_path: str) -> None:
    """Manager thread: bound concurrency, run the analysis (process or inline), and
    keep the in-memory registry updated. I/O-bound (queue draining), so it never
    starves the event loop."""
    acquired = _semaphore.acquire(timeout=settings.runtime_validation_timeout_seconds * 2)
    if not acquired:
        _update(exec_id, state=FAILED, ended_at=_now(),
                error={"code": "QUEUE_TIMEOUT", "message": "timed out waiting for an execution slot",
                       "stage": None, "retryable": True})
        return
    try:
        _update(exec_id, state=RUNNING, started_at=_now())
        if _INLINE_FOR_TESTS:
            _run_inline(exec_id, storage_path)
        else:
            _run_in_process(exec_id, storage_path)
    finally:
        _semaphore.release()


def _run_inline(exec_id: str, storage_path: str) -> None:
    """In-process execution (tests): mocks of analyze_apk/SessionLocal apply here."""
    try:
        payload = _execute(storage_path, lambda name, stages: _update(exec_id, current_stage=name, stages=stages))
        _apply_done(exec_id, payload)
    except Exception as error:  # honest failure — never a fabricated empty result
        _apply_failed(exec_id, {"code": type(error).__name__, "message": _bounded_message(error)})


def _run_in_process(exec_id: str, storage_path: str) -> None:
    """Production: run analyze_apk in a child process (own GIL) and stream its
    progress over a queue so the web server stays responsive throughout."""
    ctx = _mp_context()
    q = ctx.Queue()
    proc = ctx.Process(target=_worker_main, args=(storage_path, q), daemon=True,
                       name=f"asf-exec-{exec_id[:8]}")
    proc.start()
    terminal = False
    try:
        while True:
            try:
                msg = q.get(timeout=1.0)
            except _queue.Empty:
                if not proc.is_alive():
                    break  # died without reporting — handled below
                continue
            kind = msg[0]
            if kind == "progress":
                _, name, stages = msg
                _update(exec_id, current_stage=name, stages=stages)
            elif kind == "done":
                _apply_done(exec_id, msg[1])
                terminal = True
                break
            elif kind == "failed":
                _apply_failed(exec_id, msg[1])
                terminal = True
                break
    finally:
        proc.join(timeout=10)
        if proc.is_alive():
            proc.terminate()
        snap = _snapshot(exec_id)
        if not terminal and snap is not None and snap["state"] not in TERMINAL_STATES:
            _apply_failed(exec_id, {"code": "WORKER_DIED",
                                    "message": "analysis process exited before reporting a result"})


def _worker_main(storage_path: str, q) -> None:  # runs in the child process
    """Child-process entrypoint: run the pipeline, stream progress + the final
    result payload back over the queue. Only picklable data crosses the boundary."""
    try:
        payload = _execute(storage_path, lambda name, stages: q.put(("progress", name, stages)))
        q.put(("done", payload))
    except Exception as error:
        q.put(("failed", {"code": type(error).__name__, "message": _bounded_message(error)}))


def _execute(storage_path: str, on_progress) -> dict:
    """Run the authoritative pipeline once and return a picklable result payload.
    Imports are function-local so test monkeypatches of analyze_apk/SessionLocal
    apply, and so the heavy modules load in the worker (not at server import)."""
    from app.analysis.orchestrator import analyze_apk, clear_progress_sink, set_progress_sink
    from app.db.session import SessionLocal

    set_progress_sink(lambda name, stages: on_progress(name, stages))
    try:
        with SessionLocal() as db:
            analysis = analyze_apk(Path(storage_path), db)
            return _result_payload(analysis)
    finally:
        clear_progress_sink()


def _result_payload(analysis) -> dict:
    """Map a finished analysis to the operational result. PARTIAL is never
    fabricated into COMPLETED; capability limitations stay visible."""
    caps = analysis.capabilities or {}
    limitations = [{"capability": k, "state": v} for k, v in sorted(caps.items())
                   if str(v).upper() in _LIMITATION_STATES]
    status = (analysis.status or "").upper()
    if status == "COMPLETE":
        state = COMPLETED
    elif status == "FAILED":
        state = FAILED
    else:  # PARTIAL (or any non-clean-complete terminal) -> completed with limitations
        state = COMPLETED_WITH_LIMITATIONS
    return {
        "state": state,
        "analysis_id": str(analysis.id),
        "stages": analysis.stages or [],
        "capability_limitations": limitations,
        "package": (analysis.manifest.package if analysis.manifest else None),
    }


def _apply_done(exec_id: str, payload: dict) -> None:
    aid = payload.get("analysis_id")
    if aid:
        with _lock:
            _by_analysis[aid] = exec_id
    snap = _snapshot(exec_id) or {}
    _update(exec_id, state=payload.get("state", COMPLETED), analysis_id=aid, ended_at=_now(),
            stages=payload.get("stages") or snap.get("stages") or [],
            capability_limitations=payload.get("capability_limitations", []),
            artifact={**snap.get("artifact", {}), "package": payload.get("package")})


def _apply_failed(exec_id: str, err: dict) -> None:
    snap = _snapshot(exec_id) or {}
    _update(exec_id, state=FAILED, ended_at=_now(),
            error={"code": err.get("code", "Error"), "message": err.get("message", ""),
                   "stage": snap.get("current_stage"), "retryable": True})


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
    """Cooperative cancellation is not offered (§13): the pipeline runs as a single
    bounded worker to completion. Reported honestly rather than killing it mid-write."""
    snap = _snapshot(exec_id)
    if snap is None:
        return {"status": "NOT_FOUND"}
    if snap["state"] in TERMINAL_STATES:
        return {"status": "ALREADY_TERMINAL", "state": snap["state"]}
    return {"status": "CANCELLATION_UNAVAILABLE",
            "reason": "the analysis runs as a separate bounded worker process and is not "
                      "cooperatively cancellable; it will run to completion.",
            "state": snap["state"]}


def _reset_for_tests() -> None:  # pragma: no cover - test helper
    """Reset registries AND run inline (in-process) so tests can mock the pipeline;
    production never calls this and keeps the worker-process model."""
    global _INLINE_FOR_TESTS
    with _lock:
        _executions.clear()
        _by_analysis.clear()
    _INLINE_FOR_TESTS = True

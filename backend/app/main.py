import tempfile
from pathlib import Path
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db, initialize_database
from app.models.analysis import Analysis
from app.models.apk import APKArtifact
from app.reports.json_report import build_report
from app.schemas.apk import APKArtifactResponse
from app.services.apk_ingestion import APKIngestionError, get_artifact, ingest_apk
from app.services.doctor import doctor_report


def _allowed_extensions() -> set[str]:
    return {e.strip().lower() for e in settings.upload_allowed_extensions.split(",") if e.strip()}


# Honest intake classification for the artifact type (§4). The backend only claims
# the format was recognized for intake — not that every format is analyzed identically.
_INTAKE_TYPE = {"apk": "APK", "apks": "APK_SET", "apkm": "APKM", "aab": "APP_BUNDLE"}

initialize_database()
app = FastAPI(title="AndroidSecForge", version="0.1.0")


@app.get("/", include_in_schema=False)
def web_ui() -> FileResponse:
    return FileResponse(Path(__file__).resolve().parent / "web" / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/doctor")
def doctor() -> dict:
    return doctor_report()


@app.post("/api/v1/apk/import", response_model=APKArtifactResponse, status_code=status.HTTP_201_CREATED)
async def import_apk(file: UploadFile, db: Session = Depends(get_db)) -> APKArtifact:
    """Bounded artifact intake. Backend validation is authoritative (§6): extension,
    size, and empty-file checks are enforced here regardless of the frontend. The
    uploaded filename is never used as a filesystem path — ingest_apk stores under a
    server-generated content-addressed name."""
    suffix = Path(file.filename).suffix.lower() if file.filename else ""
    if suffix not in _allowed_extensions():
        raise HTTPException(status_code=400, detail="Upload must be an APK, AAB, APKS, or APKM file")
    written = 0
    with tempfile.NamedTemporaryFile(suffix=suffix) as temp:
        while chunk := await file.read(1024 * 1024):
            written += len(chunk)
            if written > settings.upload_max_file_size:
                raise HTTPException(status_code=413,
                                    detail=f"Artifact exceeds the maximum size of {settings.upload_max_file_size} bytes")
            temp.write(chunk)
        temp.flush()
        if written == 0:
            raise HTTPException(status_code=400, detail="Uploaded artifact is empty")
        try:
            return ingest_apk(Path(temp.name), db)
        except APKIngestionError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error


@app.get("/api/v1/apk/{artifact_id}", response_model=APKArtifactResponse)
def artifact_detail(artifact_id: UUID, db: Session = Depends(get_db)) -> APKArtifact:
    artifact = get_artifact(artifact_id, db)
    if artifact is None:
        raise HTTPException(status_code=404, detail="APK artifact not found")
    return artifact


@app.get("/api/v1/apk", response_model=list[APKArtifactResponse])
def artifact_list(db: Session = Depends(get_db)) -> list[APKArtifact]:
    return list(db.scalars(select(APKArtifact).order_by(APKArtifact.created_at.desc())))


@app.get("/api/v1/apk/{artifact_id}/framework")
def framework_detail(artifact_id: UUID, db: Session = Depends(get_db)) -> dict:
    artifact = get_artifact(artifact_id, db)
    if artifact is None:
        raise HTTPException(status_code=404, detail="APK artifact not found")
    return artifact.framework


@app.get("/api/v1/apk/{artifact_id}/ipc")
def ipc_detail(artifact_id: UUID, db: Session = Depends(get_db)) -> dict:
    artifact = get_artifact(artifact_id, db)
    if artifact is None:
        raise HTTPException(status_code=404, detail="APK artifact not found")
    return artifact.ipc


@app.get("/api/v1/apk/{artifact_id}/dex")
def dex_detail(artifact_id: UUID, db: Session = Depends(get_db)) -> dict:
    artifact = get_artifact(artifact_id, db)
    if artifact is None:
        raise HTTPException(status_code=404, detail="APK artifact not found")
    return {"dex": artifact.dex, "jadx": artifact.structure.get("jadx"), "workspace": artifact.workspace_path}


def _get_analysis(analysis_id: UUID, db: Session) -> Analysis:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis


@app.get("/api/v1/apk/{artifact_id}/analyses")
def analyses_for_apk(artifact_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(
        select(Analysis).where(Analysis.apk_id == artifact_id).order_by(Analysis.started_at.desc())
    )
    return [
        {"id": str(row.id), "profile": row.profile, "status": row.status, "started_at": row.started_at.isoformat()}
        for row in rows
    ]


@app.get("/api/v1/analyses")
def analyses_list(limit: int = 50, db: Session = Depends(get_db)) -> list[dict]:
    """Bounded, deterministic list of recent analyses (prompt 22 dashboard). A
    read-only projection over persisted rows — no analytical truth is created."""
    limit = max(1, min(limit, settings.analysis_history_limit))
    rows = list(db.scalars(select(Analysis).order_by(Analysis.started_at.desc()).limit(limit)))
    artifacts = {a.id: a for a in db.scalars(
        select(APKArtifact).where(APKArtifact.id.in_([r.apk_id for r in rows])))} if rows else {}
    out = []
    for row in rows:
        manifest = row.manifest
        art = artifacts.get(row.apk_id)
        out.append({
            "id": str(row.id), "apk_id": str(row.apk_id), "profile": row.profile, "status": row.status,
            "apk_sha256": row.apk_sha256, "started_at": row.started_at.isoformat() if row.started_at else None,
            "package": manifest.package if manifest else None,
            "finding_count": len(row.findings),
            "native_library_count": len(row.native_libraries),
            "artifact_filename": art.original_filename if art else None,
            "artifact_type": _INTAKE_TYPE.get((art.artifact_type or "").lower(), art.artifact_type) if art else None,
        })
    return out


def _artifact_meta(art: APKArtifact) -> dict:
    return {"artifact_id": str(art.id), "filename": art.original_filename,
            "artifact_type": _INTAKE_TYPE.get((art.artifact_type or "").lower(), art.artifact_type),
            "sha256": art.sha256, "size_bytes": art.size_bytes, "package": art.package_name,
            "version_name": art.version_name}


@app.post("/api/v1/analyses", status_code=status.HTTP_202_ACCEPTED)
def create_analysis(artifact_id: UUID, db: Session = Depends(get_db)) -> dict:
    """Start an analysis for a previously-intaken artifact using the EXISTING
    authoritative pipeline (prompt 26). Returns immediately with a QUEUED execution;
    poll the progress endpoint. This never bypasses backend validation and creates
    no second pipeline."""
    from app.services.execution import start_execution

    art = get_artifact(artifact_id, db)
    if art is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    if not Path(art.storage_path).is_file():
        raise HTTPException(status_code=409, detail="Stored artifact is no longer available on disk")
    return start_execution(str(art.id), art.storage_path, requested_by="web", artifact_meta=_artifact_meta(art))


@app.get("/api/v1/analysis/execution/{execution_id}")
def get_execution_status(execution_id: UUID) -> dict:
    from app.services.execution import get_execution

    e = get_execution(str(execution_id))
    if e is None:
        raise HTTPException(status_code=404, detail="Execution not found (executions are in-process and ephemeral)")
    return e


@app.post("/api/v1/analysis/execution/{execution_id}/cancel")
def cancel_analysis_execution(execution_id: UUID) -> dict:
    from app.services.execution import cancel_execution

    return cancel_execution(str(execution_id))


@app.get("/api/v1/analysis/{analysis_id}/progress")
def analysis_progress(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    """Progress for an analysis. Prefers the in-process execution record (live stage
    progress); falls back to the persisted analysis (e.g. a CLI-created one) — never
    fabricating progress or completion."""
    from app.services.execution import COMPLETED, COMPLETED_WITH_LIMITATIONS, FAILED, get_execution_by_analysis

    e = get_execution_by_analysis(str(analysis_id))
    if e is not None:
        return e
    a = _get_analysis(analysis_id, db)
    status_map = {"COMPLETE": COMPLETED, "PARTIAL": COMPLETED_WITH_LIMITATIONS, "FAILED": FAILED}
    limitations = [{"capability": k, "state": v} for k, v in sorted((a.capabilities or {}).items())
                   if str(v).upper() in {"UNAVAILABLE", "DEGRADED", "PARTIAL", "SKIPPED"}]
    return {"execution_id": None, "analysis_id": str(a.id), "artifact_id": str(a.apk_id),
            "state": status_map.get((a.status or "").upper(), "COMPLETED_WITH_LIMITATIONS"),
            "current_stage": None, "stages": a.stages or [], "error": None,
            "capability_limitations": limitations,
            "artifact": {"package": a.manifest.package if a.manifest else None},
            "created_at": a.started_at.isoformat() if a.started_at else None,
            "started_at": a.started_at.isoformat() if a.started_at else None,
            "ended_at": a.completed_at.isoformat() if a.completed_at else None,
            "requested_by": "cli"}


@app.get("/api/v1/analysis/{analysis_id}")
def analysis_report(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    return build_report(_get_analysis(analysis_id, db), db)


@app.get("/api/v1/analysis/{analysis_id}/findings")
def analysis_findings(analysis_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    return build_report(_get_analysis(analysis_id, db), db)["findings"]


@app.get("/api/v1/analysis/{analysis_id}/risk")
def analysis_risk(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    report = build_report(_get_analysis(analysis_id, db), db)
    return {"risk": report.get("risk", {}), "summary": report["summary"]}


@app.get("/api/v1/analysis/{analysis_id}/attack-surface")
def analysis_attack_surface(analysis_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    return build_report(_get_analysis(analysis_id, db), db)["attack_surface"]


@app.get("/api/v1/analysis/{analysis_id}/root-causes")
def analysis_root_causes(analysis_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    return build_report(_get_analysis(analysis_id, db), db)["root_causes"]


@app.get("/api/v1/analysis/{analysis_id}/graph/export")
def analysis_graph_export(analysis_id: UUID, format: str = "json", db: Session = Depends(get_db)):
    from fastapi.responses import PlainTextResponse

    from app.reports.graph_export import export_graph

    analysis = _get_analysis(analysis_id, db)
    try:
        content = export_graph(analysis, format)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    media = "application/json" if format == "json" else "text/plain"
    return PlainTextResponse(content, media_type=media)


# --- Runtime Lab (explicit, auditable) -------------------------------------


def _get_runtime_session(session_id: UUID, db: Session):
    from app.models.runtime import RuntimeSession

    session = db.get(RuntimeSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Runtime session not found")
    return session


@app.get("/api/v1/runtime/devices")
def runtime_devices() -> dict:
    from app.runtime.adb import AdbAdapter

    adb = AdbAdapter()
    devices = adb.list_devices() if adb.available else []
    return {"adb_available": adb.available,
            "devices": [{"serial": d.serial, "state": d.state, "model": d.model, "is_emulator": d.is_emulator}
                        for d in devices]}


@app.get("/api/v1/runtime/devices/{serial}")
def runtime_device(serial: str) -> dict:
    from app.runtime.adb import AdbAdapter

    adb = AdbAdapter()
    match = next((d for d in (adb.list_devices() if adb.available else []) if d.serial == serial), None)
    if match is None:
        raise HTTPException(status_code=404, detail="device not attached")
    d = adb.enrich_device(match)
    return {"serial": d.serial, "state": d.state, "model": d.model, "android_version": d.android_version,
            "abi": d.abi, "is_emulator": d.is_emulator, "rooted": d.rooted}


@app.post("/api/v1/runtime/sessions")
def runtime_create_session(analysis_id: UUID, device: str | None = None, db: Session = Depends(get_db)) -> dict:
    from app.runtime.session import RuntimeLab

    analysis = _get_analysis(analysis_id, db)
    lab = RuntimeLab(db, requested_by="rest")
    session = lab.create_session(analysis)
    result = {"session_id": str(session.id), "state": session.session_state}
    if device:
        result["device"] = lab.select_device(session, device)
    db.commit()
    return result


@app.get("/api/v1/runtime/sessions/{session_id}")
def runtime_get_session(session_id: UUID, db: Session = Depends(get_db)) -> dict:
    s = _get_runtime_session(session_id, db)
    return {"id": str(s.id), "state": s.session_state, "device": s.device_serial, "package": s.package_name,
            "instrumentation_enabled": s.instrumentation_enabled, "error": s.error,
            "observations": len(s.observations), "events": len(s.events)}


@app.post("/api/v1/runtime/sessions/{session_id}/install")
def runtime_install(session_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.models.apk import APKArtifact
    from app.runtime.session import RuntimeLab

    s = _get_runtime_session(session_id, db)
    apk = db.get(APKArtifact, s.analysis.apk_id)
    result = RuntimeLab(db, requested_by="rest").install(s, apk.storage_path if apk else "")
    db.commit()
    return result


@app.post("/api/v1/runtime/sessions/{session_id}/launch")
def runtime_launch(session_id: UUID, activity: str | None = None, db: Session = Depends(get_db)) -> dict:
    from app.runtime.session import RuntimeLab

    s = _get_runtime_session(session_id, db)
    result = RuntimeLab(db, requested_by="rest").launch(s, activity)
    db.commit()
    return result


@app.post("/api/v1/runtime/sessions/{session_id}/stop")
def runtime_stop(session_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.runtime.session import RuntimeLab

    s = _get_runtime_session(session_id, db)
    result = RuntimeLab(db, requested_by="rest").stop(s)
    db.commit()
    return result


@app.get("/api/v1/runtime/sessions/{session_id}/observations")
def runtime_observations(session_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    s = _get_runtime_session(session_id, db)
    return [{"type": o.observation_type, "class": o.class_name, "method": o.method_name, "symbol": o.symbol,
             "source": o.source, "confidence": o.confidence, "timestamp": o.timestamp.isoformat()}
            for o in s.observations]


@app.post("/api/v1/runtime/sessions/{session_id}/correlate")
def runtime_correlate(session_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.runtime_correlation import correlate_runtime

    s = _get_runtime_session(session_id, db)
    summary = correlate_runtime(s.analysis)
    db.commit()
    return summary


@app.get("/api/v1/analysis/{analysis_id}/runtime")
def analysis_runtime(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    report = build_report(_get_analysis(analysis_id, db), db)
    return {"runtime_summary": report["runtime_summary"], "runtime_sessions": report["runtime_sessions"],
            "runtime_validation": report["runtime_validation"]}


# --- Real-device capability discovery (prompt 23) --------------------------
@app.get("/api/v1/runtime/device")
def runtime_device_capability(serial: str | None = None) -> dict:
    """Read-only device discovery from actual ADB output. Attaches to nothing;
    never infers frida-server availability from host Frida."""
    from app.runtime.device import discover_device

    return discover_device(serial)


# --- Live runtime validation & behavioral corroboration (prompt 21) --------
@app.post("/api/v1/runtime/validate")
def runtime_validate(analysis_id: UUID, device: str, apk_path: str | None = None,
                     profiles: str = "lifecycle,intents,webview", duration: int = 10,
                     activity: str | None = None, db: Session = Depends(get_db)) -> dict:
    """Explicit live validation. Returns LIVE_RUNTIME_UNAVAILABLE when no device
    is attached — never fabricates LIVE data."""
    from app.runtime.session import RuntimeLab

    analysis = _get_analysis(analysis_id, db)
    profile_list = [p.strip() for p in profiles.split(",") if p.strip()]
    result = RuntimeLab(db, requested_by="rest").validate(analysis, device, apk_path=apk_path,
                                                          profiles=profile_list, duration=duration, activity=activity)
    db.commit()
    return result


@app.get("/api/v1/analysis/{analysis_id}/runtime/validation")
def analysis_runtime_validation(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.runtime_validation import runtime_validation_view

    return runtime_validation_view(_get_analysis(analysis_id, db))


@app.post("/api/v1/analysis/{analysis_id}/runtime/correlate")
def analysis_runtime_build_validation(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.runtime_validation import build_runtime_validation

    analysis = _get_analysis(analysis_id, db)
    run = build_runtime_validation(db, analysis, requested_by="rest")
    db.commit()
    return {"mode": run.mode, "correlations": run.correlation_count, "live_claims": run.live_claim_count,
            "corroborated_findings": run.corroborated_finding_count, "fingerprint": run.fingerprint}


@app.get("/api/v1/analysis/{analysis_id}/runtime/correlations")
def analysis_runtime_correlations(analysis_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    from app.analysis.runtime_validation import runtime_validation_view

    return runtime_validation_view(_get_analysis(analysis_id, db))["correlations"]


@app.get("/api/v1/analysis/{analysis_id}/runtime/explain/{subject}")
def analysis_runtime_explain(analysis_id: UUID, subject: str, db: Session = Depends(get_db)) -> dict:
    from app.analysis.runtime_validation import runtime_explain

    return runtime_explain(_get_analysis(analysis_id, db), subject)


@app.get("/api/v1/runtime/sessions/{session_id}/events")
def runtime_session_events(session_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    s = _get_runtime_session(session_id, db)
    return [{"type": e.event_type, "tag": e.tag, "priority": e.priority, "message": e.message} for e in s.events]


@app.get("/api/v1/runtime/sessions/{session_id}/artifacts")
def runtime_session_artifacts(session_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    s = _get_runtime_session(session_id, db)
    return [{"kind": a.kind, "sha256": a.sha256, "size": a.size_bytes, "path": a.path} for a in s.artifacts]


@app.post("/api/v1/runtime/sessions/{session_id}/finalize")
def runtime_session_finalize(session_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.models.analysis import Analysis
    from app.runtime.session import RuntimeLab

    s = _get_runtime_session(session_id, db)
    analysis = db.get(Analysis, s.analysis_id)
    result = RuntimeLab(db, requested_by="rest").finalize(s, analysis)
    db.commit()
    return result


@app.get("/api/v1/diff/{comparison_id}/runtime")
def diff_runtime_validation(comparison_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.runtime_validation import runtime_validation_from_diff

    return runtime_validation_from_diff(_get_comparison(comparison_id, db))


# --- Knowledge graph + Investigation workspace (prompt 14) -----------------


def _get_investigation(investigation_id: UUID, db: Session):
    from app.models.investigation import Investigation

    inv = db.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


def _get_finding(finding_id: UUID, db: Session):
    from app.models.analysis import FindingModel

    f = db.get(FindingModel, finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return f


@app.post("/api/v1/investigations", status_code=status.HTTP_201_CREATED)
def create_investigation(analysis_id: UUID, name: str | None = None, description: str = "",
                         db: Session = Depends(get_db)) -> dict:
    from app.analysis import investigation as INV

    analysis = _get_analysis(analysis_id, db)
    inv = INV.create_investigation(db, analysis, name=name, description=description, created_by="rest")
    db.commit()
    return {"investigation_id": str(inv.id), "name": inv.name, "analysis_id": str(analysis.id)}


@app.get("/api/v1/investigations")
def list_investigations(analysis_id: UUID | None = None, db: Session = Depends(get_db)) -> list[dict]:
    from app.models.investigation import Investigation

    query = select(Investigation)
    if analysis_id is not None:
        query = query.where(Investigation.analysis_id == analysis_id)
    return [{"id": str(i.id), "name": i.name, "status": i.status, "analysis_id": str(i.analysis_id),
             "findings": len(i.findings), "hypotheses": len(i.hypotheses)}
            for i in db.scalars(query.order_by(Investigation.created_at.desc()))]


@app.get("/api/v1/investigations/{investigation_id}")
def get_investigation(investigation_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis import investigation as INV

    return INV.investigation_view(_get_investigation(investigation_id, db))


@app.post("/api/v1/investigations/{investigation_id}/nodes", status_code=status.HTTP_201_CREATED)
def investigation_add_node(investigation_id: UUID, node_ref: str, node_type: str = "", label: str = "",
                           note: str = "", db: Session = Depends(get_db)) -> dict:
    from app.analysis import investigation as INV

    inv = _get_investigation(investigation_id, db)
    node = INV.add_node(db, inv, node_ref, node_type, label, note)
    db.commit()
    return {"node_ref": node.node_ref, "type": node.node_type}


@app.post("/api/v1/investigations/{investigation_id}/findings", status_code=status.HTTP_201_CREATED)
def investigation_add_finding(investigation_id: UUID, finding_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis import investigation as INV

    inv = _get_investigation(investigation_id, db)
    finding = _get_finding(finding_id, db)
    if finding.analysis_id != inv.analysis_id:
        raise HTTPException(status_code=400, detail="finding belongs to a different analysis")
    INV.add_finding(db, inv, finding)
    db.commit()
    return {"finding_id": str(finding.id), "rule_id": finding.rule_id}


@app.post("/api/v1/investigations/{investigation_id}/notes", status_code=status.HTTP_201_CREATED)
def investigation_add_note(investigation_id: UUID, body: str, author: str = "researcher",
                           target_ref: str | None = None, db: Session = Depends(get_db)) -> dict:
    from app.analysis import investigation as INV

    inv = _get_investigation(investigation_id, db)
    note = INV.add_note(db, inv, body, author, target_ref)
    db.commit()
    return {"note_id": str(note.id)}


@app.post("/api/v1/investigations/{investigation_id}/hypotheses", status_code=status.HTTP_201_CREATED)
def investigation_add_hypothesis(investigation_id: UUID, statement: str, status_value: str = "OPEN",
                                 rationale: str = "", db: Session = Depends(get_db)) -> dict:
    from app.analysis import investigation as INV

    inv = _get_investigation(investigation_id, db)
    try:
        hyp = INV.add_hypothesis(db, inv, statement, rationale, status_value)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    db.commit()
    return {"hypothesis_id": str(hyp.id), "status": hyp.status,
            "note": "researcher hypothesis — does not modify any finding"}


@app.post("/api/v1/investigations/{investigation_id}/bookmarks", status_code=status.HTTP_201_CREATED)
def investigation_add_bookmark(investigation_id: UUID, ref_type: str, ref_id: str, label: str = "",
                               db: Session = Depends(get_db)) -> dict:
    from app.analysis import investigation as INV

    inv = _get_investigation(investigation_id, db)
    bm = INV.add_bookmark(db, inv, ref_type, ref_id, label)
    db.commit()
    return {"bookmark_id": str(bm.id)}


@app.get("/api/v1/investigations/{investigation_id}/timeline")
def investigation_timeline(investigation_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    from app.analysis import investigation as INV

    inv = _get_investigation(investigation_id, db)
    INV.rebuild_timeline(db, inv, inv.analysis)
    db.commit()
    return INV.timeline_view(inv)


@app.get("/api/v1/investigations/{investigation_id}/graph")
def investigation_graph(investigation_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis import knowledge_graph as KG

    inv = _get_investigation(investigation_id, db)
    kg = KG.build_knowledge_graph(inv.analysis)
    return {"analysis_id": str(inv.analysis_id), "digest": KG.graph_digest(kg), "truncated": kg.truncated,
            **KG.snapshot_counts(kg, inv.analysis)}


@app.get("/api/v1/investigations/{investigation_id}/findings")
def investigation_findings(investigation_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    inv = _get_investigation(investigation_id, db)
    id_to_finding = {f.id: f for f in inv.analysis.findings}
    out = []
    for link in inv.findings:
        f = id_to_finding.get(link.finding_id)
        if f is not None:
            out.append({"id": str(f.id), "rule_id": f.rule_id, "severity": f.severity, "status": f.status,
                        "component": f.component, "validation_state": f.validation_state})
    return out


@app.get("/api/v1/investigations/{investigation_id}/paths")
def investigation_paths(investigation_id: UUID, from_query: str, to_query: str, max_depth: int | None = None,
                        min_confidence: str | None = None, db: Session = Depends(get_db)) -> dict:
    from app.analysis import graph_queries as GQ

    inv = _get_investigation(investigation_id, db)
    return GQ.investigate_paths(inv.analysis, from_query, to_query, max_depth=max_depth,
                                min_confidence=min_confidence)


@app.get("/api/v1/investigations/{investigation_id}/export")
def investigation_export(investigation_id: UUID, format: str = "json", db: Session = Depends(get_db)):
    from fastapi.responses import PlainTextResponse

    from app.reports.investigation_report import export_investigation

    inv = _get_investigation(investigation_id, db)
    try:
        content = export_investigation(inv.analysis, inv, format)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    media = "application/json" if format == "json" else "text/plain"
    return PlainTextResponse(content, media_type=media)


@app.get("/api/v1/findings/{finding_id}/explain")
def finding_explain(finding_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.finding_explorer import explain_finding

    finding = _get_finding(finding_id, db)
    analysis = _get_analysis(finding.analysis_id, db)
    return explain_finding(analysis, finding)


@app.get("/api/v1/findings/{finding_id}/evidence-chain")
def finding_evidence_chain(finding_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.finding_explorer import evidence_chain

    finding = _get_finding(finding_id, db)
    analysis = _get_analysis(finding.analysis_id, db)
    return evidence_chain(analysis, finding)


@app.get("/api/v1/findings/{finding_id}/explore")
def finding_explore(finding_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.finding_explorer import explore_finding

    finding = _get_finding(finding_id, db)
    analysis = _get_analysis(finding.analysis_id, db)
    return explore_finding(analysis, finding)


@app.get("/api/v1/analysis/{analysis_id}/graph/query")
def analysis_graph_query(analysis_id: UUID, name: str, min_confidence: str | None = None,
                         max_depth: int | None = None, component: str | None = None,
                         db: Session = Depends(get_db)) -> dict:
    from app.analysis import graph_queries as GQ

    analysis = _get_analysis(analysis_id, db)
    try:
        return GQ.run_query(analysis, name, {"min_confidence": min_confidence, "max_depth": max_depth,
                                             "component": component})
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.get("/api/v1/analysis/{analysis_id}/graph/knowledge")
def analysis_knowledge_graph(analysis_id: UUID, format: str = "json", db: Session = Depends(get_db)):
    from fastapi.responses import PlainTextResponse

    from app.reports.investigation_report import graph_dot, graph_graphml, graph_json

    analysis = _get_analysis(analysis_id, db)
    fn = {"json": graph_json, "dot": graph_dot, "graphml": graph_graphml}.get(format)
    if fn is None:
        raise HTTPException(status_code=400, detail=f"unsupported format: {format}")
    media = "application/json" if format == "json" else "text/plain"
    return PlainTextResponse(fn(analysis), media_type=media)


@app.get("/api/v1/analysis/{analysis_id}/graph/snapshot")
def analysis_graph_snapshot(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    from datetime import datetime, timezone

    from app.analysis import knowledge_graph as KG

    analysis = _get_analysis(analysis_id, db)
    snap = KG.build_snapshot(analysis, datetime.now(timezone.utc))
    db.commit()
    return {"digest": snap.digest, "graph_version": snap.graph_version, "node_count": snap.node_count,
            "edge_count": snap.edge_count, "finding_count": snap.finding_count,
            "root_cause_count": snap.root_cause_count,
            "runtime_observation_count": snap.runtime_observation_count}


# --- Comparative APK analysis (prompt 15) ----------------------------------


def _get_comparison(comparison_id: UUID, db: Session):
    from app.models.comparison import AnalysisComparison

    c = db.get(AnalysisComparison, comparison_id)
    if c is None:
        raise HTTPException(status_code=404, detail="Comparison not found")
    return c


@app.post("/api/v1/diff", status_code=status.HTTP_201_CREATED)
def create_diff(baseline: UUID, candidate: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.diff import compare_analyses

    a = _get_analysis(baseline, db)
    b = _get_analysis(candidate, db)
    comparison = compare_analyses(db, a, b, requested_by="rest")
    db.commit()
    return {"comparison_id": str(comparison.id), "status": comparison.status,
            "snapshot_mode": comparison.snapshot_mode, "security_impact": comparison.security_impact,
            "impact_confidence": comparison.impact_confidence, "fingerprint": comparison.fingerprint,
            "error": comparison.error, "summary": comparison.summary}


@app.get("/api/v1/diff/{comparison_id}")
def get_diff(comparison_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.reports.comparison_report import build_comparison_report

    return build_comparison_report(_get_comparison(comparison_id, db))


@app.get("/api/v1/diff/{comparison_id}/summary")
def get_diff_summary(comparison_id: UUID, db: Session = Depends(get_db)) -> dict:
    c = _get_comparison(comparison_id, db)
    return {"status": c.status, "snapshot_mode": c.snapshot_mode, "security_impact": c.security_impact,
            "impact_confidence": c.impact_confidence, "summary": c.summary,
            "category_summaries": [{"category": s.category, "added": s.added, "removed": s.removed,
                                    "changed": s.changed, "unchanged": s.unchanged,
                                    "security_relevant": s.security_relevant}
                                   for s in sorted(c.category_summaries, key=lambda s: s.category)]}


@app.get("/api/v1/diff/{comparison_id}/changes")
def get_diff_changes(comparison_id: UUID, category: str | None = None, change_type: str | None = None,
                     min_confidence: str | None = None, security_only: bool = False,
                     db: Session = Depends(get_db)) -> list[dict]:
    from app.analysis.diff import _CONF_RANK

    c = _get_comparison(comparison_id, db)
    out = []
    for ch in c.changes:
        if category and ch.category != category:
            continue
        if change_type and ch.change_type != change_type.upper():
            continue
        if min_confidence and _CONF_RANK.get((ch.confidence or "UNKNOWN").upper(), -1) < \
                _CONF_RANK.get(min_confidence.upper(), -1):
            continue
        if security_only and not ch.security_relevant:
            continue
        out.append({"category": ch.category, "entity_type": ch.entity_type, "identity": ch.entity_identity,
                    "change_type": ch.change_type, "confidence": ch.confidence,
                    "security_relevant": ch.security_relevant, "baseline": ch.baseline_value,
                    "candidate": ch.candidate_value, "provenance": ch.provenance, "evidence": ch.evidence})
    return out


@app.get("/api/v1/diff/{comparison_id}/findings")
def get_diff_findings(comparison_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    c = _get_comparison(comparison_id, db)
    return [{"change_type": f.change_type, "rule_id": f.rule_id, "component": f.component,
             "changed_dimensions": f.changed_dimensions, "confidence": f.confidence,
             "security_relevant": f.security_relevant,
             "disposition": "NO_LONGER_DETECTED" if f.change_type == "REMOVED" else None,
             "baseline": f.baseline_value, "candidate": f.candidate_value}
            for f in c.finding_changes]


@app.get("/api/v1/diff/{comparison_id}/attack-surface")
def get_diff_attack_surface(comparison_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    c = _get_comparison(comparison_id, db)
    return [{"change_type": ch.change_type, "entity_type": ch.entity_type, "identity": ch.entity_identity,
             "baseline": ch.baseline_value, "candidate": ch.candidate_value, "evidence": ch.evidence}
            for ch in c.changes if ch.category == "attack_surface"]


@app.get("/api/v1/diff/{comparison_id}/risk")
def get_diff_risk(comparison_id: UUID, db: Session = Depends(get_db)) -> dict:
    c = _get_comparison(comparison_id, db)
    rd = c.risk_delta
    if rd is None:
        return {"status": "NO_RISK_DELTA"}
    return {"baseline_score": rd.baseline_score, "candidate_score": rd.candidate_score, "delta": rd.delta,
            "severity_transition": rd.severity_transition, "confidence_transition": rd.confidence_transition,
            "factor_changes": rd.factor_changes,
            "note": "Risk changed according to the configured scoring model; not a claim about exploitability."}


@app.get("/api/v1/diff/{comparison_id}/paths")
def get_diff_paths(comparison_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    c = _get_comparison(comparison_id, db)
    return [{"change_type": ch.change_type, "identity": ch.entity_identity, "confidence": ch.confidence,
             "security_relevant": ch.security_relevant, "evidence": ch.evidence}
            for ch in c.changes if ch.category == "reachability"]


@app.get("/api/v1/diff/{comparison_id}/export")
def get_diff_export(comparison_id: UUID, format: str = "report", db: Session = Depends(get_db)):
    from fastapi.responses import PlainTextResponse

    from app.reports.comparison_report import export_comparison_graph

    c = _get_comparison(comparison_id, db)
    try:
        content = export_comparison_graph(c, format)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    media = "application/json" if format in ("json", "report") else "text/plain"
    return PlainTextResponse(content, media_type=media)


# --- Vulnerability intelligence (prompt 16) --------------------------------


@app.get("/api/v1/cve/providers")
def cve_providers() -> list[dict]:
    from app.intel.service import providers

    return providers()


@app.get("/api/v1/cve/freshness")
def cve_freshness(db: Session = Depends(get_db)) -> dict:
    from app.intel.service import db_freshness

    return db_freshness(db)


@app.get("/api/v1/cve/{cve_id}")
def cve_detail(cve_id: str, db: Session = Depends(get_db)) -> dict:
    from app.intel.service import show

    data = show(db, cve_id)
    if data is None:
        raise HTTPException(status_code=404, detail="CVE not found")
    return data


@app.get("/api/v1/cve/{cve_id}/identities")
def cve_identities(cve_id: str, db: Session = Depends(get_db)) -> list[dict]:
    from app.intel.service import identities

    return identities(db, cve_id)


@app.get("/api/v1/cve/{cve_id}/signatures")
def cve_signatures(cve_id: str, db: Session = Depends(get_db)) -> list[dict]:
    from app.intel.service import signatures

    return signatures(db, cve_id)


@app.get("/api/v1/cve/{cve_id}/references")
def cve_references(cve_id: str, db: Session = Depends(get_db)) -> list[str]:
    from app.intel.service import references

    return references(db, cve_id)


@app.get("/api/v1/cve/{cve_id}/explain")
def cve_explain(cve_id: str, db: Session = Depends(get_db)) -> dict:
    from app.intel.service import show

    data = show(db, cve_id)
    if data is None:
        raise HTTPException(status_code=404, detail="CVE not found")
    # A CVE-level explanation is the conflict-resolved canonical view + provenance.
    return {"cve_id": cve_id, "canonical": data["canonical"], "providers": data["providers"],
            "disagreements": data["disagreements"], "identities": data["identities"],
            "signatures": data["signatures"], "external_intelligence": data["external_intelligence"],
            "freshness": data["freshness"]}


@app.get("/api/v1/analysis/{analysis_id}/cve")
def analysis_cve(analysis_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    analysis = _get_analysis(analysis_id, db)
    return [{"match_id": str(m.id), "cve_id": m.cve_id, "dependency": m.dependency.name,
             "version_state": m.version_state, "correlation_state": m.correlation_state,
             "reachability_state": m.reachability_state, "signature_state": m.signature_state,
             "identity_confidence": m.identity_confidence, "severity": m.severity,
             "providers": m.providers, "fixed_versions": m.fixed_versions}
            for m in analysis.vulnerability_matches]


@app.get("/api/v1/analysis/{analysis_id}/cve/{match_id}/explain")
def analysis_cve_explain(analysis_id: UUID, match_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.intel.service import explain_match

    data = explain_match(db, analysis_id, match_id)
    if data is None:
        raise HTTPException(status_code=404, detail="match not found for this analysis")
    return data


# --- Remediation intelligence (prompt 17) ----------------------------------


@app.get("/api/v1/analysis/{analysis_id}/remediation")
def analysis_remediation(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.remediation import plan_view

    return plan_view(_get_analysis(analysis_id, db))


@app.get("/api/v1/analysis/{analysis_id}/remediation/summary")
def analysis_remediation_summary(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.remediation import plan_view

    return plan_view(_get_analysis(analysis_id, db))["summary"]


@app.get("/api/v1/analysis/{analysis_id}/remediation/{item_id}")
def analysis_remediation_item(analysis_id: UUID, item_id: str, db: Session = Depends(get_db)) -> dict:
    from app.analysis.remediation import plan_view

    view = plan_view(_get_analysis(analysis_id, db))
    item = next((i for i in view["items"] if i["id"] == item_id or i["id"].startswith(item_id)), None)
    if item is None:
        raise HTTPException(status_code=404, detail="remediation item not found")
    return item


@app.get("/api/v1/analysis/{analysis_id}/remediation/{item_id}/explain")
def analysis_remediation_explain(analysis_id: UUID, item_id: str, db: Session = Depends(get_db)) -> dict:
    from app.analysis.remediation import build_items, explain_item

    analysis = _get_analysis(analysis_id, db)
    item = next((i for i in build_items(analysis) if i.fingerprint == item_id or i.fingerprint.startswith(item_id)),
                None)
    if item is None:
        raise HTTPException(status_code=404, detail="remediation item not found")
    return explain_item(analysis, item)


@app.get("/api/v1/diff/{comparison_id}/remediation")
def diff_remediation(comparison_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.remediation import remediation_from_diff

    return remediation_from_diff(_get_comparison(comparison_id, db))


# --- Security validation intelligence (prompt 18) --------------------------


@app.get("/api/v1/analysis/{analysis_id}/validation")
def analysis_validation(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.validation import validation_view

    return validation_view(_get_analysis(analysis_id, db))


@app.get("/api/v1/analysis/{analysis_id}/validation/summary")
def analysis_validation_summary(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.validation import validation_view

    return validation_view(_get_analysis(analysis_id, db))["summary"]


@app.get("/api/v1/analysis/{analysis_id}/validation/claims")
def analysis_validation_claims(analysis_id: UUID, state: str | None = None, claim_type: str | None = None,
                               min_confidence: int | None = None, db: Session = Depends(get_db)) -> list[dict]:
    from app.analysis.validation import validation_view

    claims = validation_view(_get_analysis(analysis_id, db))["claims"]
    if state:
        claims = [c for c in claims if c["validation_state"] == state.upper()]
    if claim_type:
        claims = [c for c in claims if claim_type.upper() in c["claim_type"].upper()]
    if min_confidence is not None:
        claims = [c for c in claims if c["confidence"] >= min_confidence]
    return claims


@app.get("/api/v1/analysis/{analysis_id}/validation/blockers")
def analysis_validation_blockers(analysis_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    from app.analysis.validation import validation_view

    return validation_view(_get_analysis(analysis_id, db))["blockers"]


@app.get("/api/v1/analysis/{analysis_id}/validation/requirements")
def analysis_validation_requirements(analysis_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    from app.analysis.validation import validation_view

    return validation_view(_get_analysis(analysis_id, db))["requirements"]


@app.get("/api/v1/analysis/{analysis_id}/validation/findings")
def analysis_validation_findings(analysis_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    analysis = _get_analysis(analysis_id, db)
    return [{"rule_id": f.rule_id, "component": f.component,
             "validation_state": getattr(f, "security_validation_state", "UNVERIFIED"),
             "confidence": getattr(f, "validation_confidence", 0),
             "claim_count": getattr(f, "validation_claim_count", 0),
             "blocker_count": getattr(f, "validation_blocker_count", 0)}
            for f in analysis.findings if not f.is_duplicate]


@app.get("/api/v1/analysis/{analysis_id}/validation/remediation")
def analysis_validation_remediation(analysis_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    from app.analysis.validation import validation_view

    return [c for c in validation_view(_get_analysis(analysis_id, db))["claims"]
            if c["claim_type"] == "REMEDIATION_STATE_SUPPORTED"]


@app.get("/api/v1/analysis/{analysis_id}/validation/{claim_id}/explain")
def analysis_validation_explain(analysis_id: UUID, claim_id: str, db: Session = Depends(get_db)) -> dict:
    from app.analysis.validation import build_claims, explain_claim

    analysis = _get_analysis(analysis_id, db)
    claim = next((c for c in build_claims(analysis)
                  if c.fingerprint == claim_id or c.fingerprint.startswith(claim_id)), None)
    if claim is None:
        raise HTTPException(status_code=404, detail="validation claim not found")
    return explain_claim(analysis, claim)


@app.get("/api/v1/diff/{comparison_id}/validation")
def diff_validation(comparison_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.validation import validate_comparison

    return validate_comparison(_get_comparison(comparison_id, db))


# --- Obfuscation & anti-analysis intelligence (prompt 19) ------------------


@app.get("/api/v1/analysis/{analysis_id}/obfuscation")
def analysis_obfuscation(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.obfuscation import obfuscation_view

    return obfuscation_view(_get_analysis(analysis_id, db))


@app.get("/api/v1/analysis/{analysis_id}/obfuscation/summary")
def analysis_obfuscation_summary(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.obfuscation import obfuscation_view

    view = obfuscation_view(_get_analysis(analysis_id, db))
    return {"summary": view["summary"], "score": view["score"], "fingerprint": view["fingerprint"]}


@app.get("/api/v1/analysis/{analysis_id}/obfuscation/observations")
def analysis_obfuscation_observations(analysis_id: UUID, category: str | None = None,
                                      db: Session = Depends(get_db)) -> list[dict]:
    from app.analysis.obfuscation import obfuscation_view

    obs = obfuscation_view(_get_analysis(analysis_id, db))["observations"]
    if category:
        obs = [o for o in obs if category.upper() in o["category"].upper()]
    return obs


@app.get("/api/v1/analysis/{analysis_id}/obfuscation/anti-analysis")
def analysis_obfuscation_anti(analysis_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    from app.analysis.obfuscation import obfuscation_view

    return obfuscation_view(_get_analysis(analysis_id, db))["anti_analysis"]


@app.get("/api/v1/analysis/{analysis_id}/obfuscation/impacts")
def analysis_obfuscation_impacts(analysis_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    from app.analysis.obfuscation import obfuscation_view

    return obfuscation_view(_get_analysis(analysis_id, db))["analysis_impacts"]


@app.get("/api/v1/analysis/{analysis_id}/obfuscation/{observation_id}/explain")
def analysis_obfuscation_explain(analysis_id: UUID, observation_id: str, db: Session = Depends(get_db)) -> dict:
    from app.analysis.obfuscation import explain_observation, obfuscation_view

    analysis = _get_analysis(analysis_id, db)
    view = obfuscation_view(analysis)
    item = next((o for o in view["observations"]
                 if o["id"] == observation_id or o["id"].startswith(observation_id)), None)
    if item is None:
        raise HTTPException(status_code=404, detail="observation not found")
    return explain_observation(analysis, item)


@app.get("/api/v1/diff/{comparison_id}/obfuscation")
def diff_obfuscation(comparison_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.analysis.obfuscation import obfuscation_from_diff

    return obfuscation_from_diff(_get_comparison(comparison_id, db))


# --- deep native / Ghidra correlation (prompt 20) -----------------------------
@app.get("/api/v1/analysis/{analysis_id}/native")
def analysis_native_deep(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.native.deep_native import native_deep_view

    return native_deep_view(_get_analysis(analysis_id, db))


@app.get("/api/v1/analysis/{analysis_id}/native/binaries")
def analysis_native_binaries(analysis_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    from app.native.deep_native import native_deep_view

    return native_deep_view(_get_analysis(analysis_id, db))["binaries"]


@app.get("/api/v1/analysis/{analysis_id}/native/functions")
def analysis_native_functions(analysis_id: UUID, function_type: str | None = None,
                              db: Session = Depends(get_db)) -> list[dict]:
    from app.native.deep_native import native_deep_view

    fns = native_deep_view(_get_analysis(analysis_id, db))["functions"]
    if function_type:
        fns = [f for f in fns if f["function_type"].upper() == function_type.upper()]
    return fns


@app.get("/api/v1/analysis/{analysis_id}/native/jni")
def analysis_native_jni(analysis_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    from app.native.deep_native import native_deep_view

    return native_deep_view(_get_analysis(analysis_id, db))["jni_bindings"]


@app.get("/api/v1/analysis/{analysis_id}/native/calls")
def analysis_native_calls(analysis_id: UUID, db: Session = Depends(get_db)) -> list[dict]:
    from app.native.deep_native import native_deep_view

    return native_deep_view(_get_analysis(analysis_id, db))["call_edges"]


@app.get("/api/v1/analysis/{analysis_id}/native/paths")
def analysis_native_paths(analysis_id: UUID, from_query: str, to_query: str = "",
                          max_depth: int | None = None, db: Session = Depends(get_db)) -> dict:
    from app.native.deep_native import native_paths

    return native_paths(_get_analysis(analysis_id, db), from_query, to_query, max_depth)


@app.get("/api/v1/analysis/{analysis_id}/native/explain/{target}")
def analysis_native_explain(analysis_id: UUID, target: str, db: Session = Depends(get_db)) -> dict:
    from app.native.deep_native import native_explain

    return native_explain(_get_analysis(analysis_id, db), target)


@app.get("/api/v1/diff/{comparison_id}/native")
def diff_native_deep(comparison_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.native.deep_native import native_deep_from_diff

    return native_deep_from_diff(_get_comparison(comparison_id, db))


# --- security assessment & decision intelligence (prompt 24) ---------------
@app.get("/api/v1/analysis/{analysis_id}/assessment")
def analysis_assessment(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.assessment.engine import assessment_view

    return assessment_view(_get_analysis(analysis_id, db))


@app.post("/api/v1/analysis/{analysis_id}/assessment")
def analysis_assessment_build(analysis_id: UUID, db: Session = Depends(get_db)) -> dict:
    """Compute + persist the deterministic assessment (projection over existing evidence)."""
    from app.assessment.engine import build_assessment

    analysis = _get_analysis(analysis_id, db)
    asm = build_assessment(db, analysis, requested_by="rest")
    db.commit()
    return {"status": asm.status, "fingerprint": asm.fingerprint, "subjects": asm.subject_count,
            "conclusions": asm.conclusion_count, "open": asm.open_count, "blockers": asm.blocker_count}


@app.get("/api/v1/analysis/{analysis_id}/assessment/conclusions")
def analysis_assessment_conclusions(analysis_id: UUID, state: str | None = None,
                                    db: Session = Depends(get_db)) -> list[dict]:
    from app.assessment.engine import assessment_view

    rows = assessment_view(_get_analysis(analysis_id, db))["conclusions"]
    if state:
        rows = [c for c in rows if c["decision_state"] == state.upper()]
    return rows


@app.get("/api/v1/analysis/{analysis_id}/assessment/explain/{ref}")
def analysis_assessment_explain(analysis_id: UUID, ref: str, db: Session = Depends(get_db)) -> dict:
    from app.assessment.engine import explain_conclusion

    return explain_conclusion(_get_analysis(analysis_id, db), ref)


@app.get("/api/v1/diff/{comparison_id}/assessment")
def diff_assessment(comparison_id: UUID, db: Session = Depends(get_db)) -> dict:
    from app.assessment.engine import assessment_from_diff

    return assessment_from_diff(_get_comparison(comparison_id, db))
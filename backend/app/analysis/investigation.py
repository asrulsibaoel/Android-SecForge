"""Investigation workspace service (prompt 14).

Persistent researcher workspace built on top of the canonical analysis. Every
operation here writes ONLY investigation state (nodes/edges/findings/notes/
hypotheses/bookmarks/timeline). It never mutates findings, severity, confidence,
risk, CVE state, or the code graph — researcher annotations are strictly separate
from machine evidence, and a hypothesis is never auto-promoted.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.analysis import graph_queries as GQ
from app.models.investigation import (
    HYPOTHESIS_STATES,
    Investigation,
    InvestigationBookmark,
    InvestigationEdge,
    InvestigationFinding,
    InvestigationHypothesis,
    InvestigationHypothesisEvidence,
    InvestigationNode,
    InvestigationNote,
    InvestigationTimelineEvent,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def create_investigation(db: Session, analysis, name: str | None = None, description: str = "",
                         created_by: str = "cli") -> Investigation:
    inv = Investigation(name=name or f"Investigation of {analysis.apk_sha256[:12]}",
                        description=description, created_by=created_by, status="OPEN",
                        created_at=_now(), updated_at=_now())
    analysis.investigations.append(inv)
    db.flush()
    rebuild_timeline(db, inv, analysis)
    return inv


def rename_investigation(db: Session, inv: Investigation, name: str) -> Investigation:
    inv.name = name
    inv.updated_at = _now()
    return inv


def add_finding(db: Session, inv: Investigation, finding) -> InvestigationFinding:
    existing = next((f for f in inv.findings if f.finding_id == finding.id), None)
    if existing:
        return existing
    row = InvestigationFinding(finding_id=finding.id, added_at=_now())
    inv.findings.append(row)
    inv.updated_at = _now()
    db.flush()
    return row


def add_node(db: Session, inv: Investigation, node_ref: str, node_type: str = "", label: str = "",
             note: str = "") -> InvestigationNode:
    existing = next((n for n in inv.nodes if n.node_ref == node_ref), None)
    if existing:
        if note:
            existing.note = note
        return existing
    row = InvestigationNode(node_ref=node_ref, node_type=node_type, label=label, note=note, added_at=_now())
    inv.nodes.append(row)
    inv.updated_at = _now()
    db.flush()
    return row


def add_path(db: Session, inv: Investigation, analysis, from_query: str, to_query: str,
             max_depth: int | None = None, min_confidence: str | None = None) -> dict:
    """Pin the shortest evidence path between two node sets into the investigation."""
    result = GQ.investigate_paths(analysis, from_query, to_query, max_depth=max_depth,
                                  min_confidence=min_confidence)
    if not result["paths"]:
        return {"pinned": 0, "status": result["status"], "reason": result.get("reason", "no path"),
                "uncertainty": result.get("uncertainty", [])}
    path = result["paths"][0]
    pinned_nodes = 0
    for n in path["nodes"]:
        add_node(db, inv, n["key"], n["type"], n["label"])
        pinned_nodes += 1
    pinned_edges = 0
    for e in path["edges"]:
        inv.edges.append(InvestigationEdge(src_ref=e["src"], dst_ref=e["dst"], edge_type=e["type"],
                                           note=e.get("evidence", ""), added_at=_now()))
        pinned_edges += 1
    inv.updated_at = _now()
    db.flush()
    return {"pinned": pinned_nodes, "edges": pinned_edges, "status": result["status"],
            "confidence": path["confidence"], "uncertainty": result.get("uncertainty", [])}


def add_note(db: Session, inv: Investigation, body: str, author: str = "researcher",
             target_ref: str | None = None) -> InvestigationNote:
    row = InvestigationNote(body=body, author=author, target_ref=target_ref, created_at=_now())
    inv.notes.append(row)
    inv.updated_at = _now()
    db.flush()
    # A note becomes a timeline event; rebuild keeps the timeline coherent.
    inv.timeline_events.append(InvestigationTimelineEvent(
        timestamp=row.created_at, event_type="RESEARCHER_NOTE", source="USER_NOTE",
        entity_ref=target_ref, confidence="N/A", detail=body[:200], sequence=10_000 + len(inv.notes)))
    return row


def add_hypothesis(db: Session, inv: Investigation, statement: str, rationale: str = "",
                   status: str = "OPEN") -> InvestigationHypothesis:
    status = _valid_status(status)
    hyp = InvestigationHypothesis(statement=statement, rationale=rationale, status=status,
                                  created_at=_now(), updated_at=_now())
    inv.hypotheses.append(hyp)
    inv.updated_at = _now()
    db.flush()
    return hyp


def set_hypothesis_status(db: Session, hyp: InvestigationHypothesis, status: str,
                          rationale: str | None = None) -> InvestigationHypothesis:
    """Update researcher hypothesis state ONLY. This never touches any finding,
    severity, confidence, risk score, or CVE state."""
    hyp.status = _valid_status(status)
    if rationale is not None:
        hyp.rationale = rationale
    hyp.updated_at = _now()
    return hyp


def attach_hypothesis_evidence(db: Session, hyp: InvestigationHypothesis, ref_type: str, ref_id: str,
                               detail: str = "") -> InvestigationHypothesisEvidence:
    row = InvestigationHypothesisEvidence(ref_type=ref_type.upper(), ref_id=ref_id, detail=detail, added_at=_now())
    hyp.evidence.append(row)
    hyp.updated_at = _now()
    db.flush()
    return row


def add_bookmark(db: Session, inv: Investigation, ref_type: str, ref_id: str,
                 label: str = "") -> InvestigationBookmark:
    row = InvestigationBookmark(ref_type=ref_type.upper(), ref_id=ref_id, label=label, created_at=_now())
    inv.bookmarks.append(row)
    inv.updated_at = _now()
    db.flush()
    return row


def _valid_status(status: str) -> str:
    s = (status or "OPEN").upper()
    if s not in HYPOTHESIS_STATES:
        raise ValueError(f"invalid hypothesis status '{status}'; allowed: {', '.join(HYPOTHESIS_STATES)}")
    return s


# ---------------------------------------------------------------------------
# Timeline (Phase 5) — deterministic
# ---------------------------------------------------------------------------


def rebuild_timeline(db: Session, inv: Investigation, analysis) -> list[InvestigationTimelineEvent]:
    """(Re)build the deterministic timeline from analysis + researcher notes.

    Static events use analysis timestamps; runtime events use their actual
    timestamps; note events use their creation time. No timestamp is fabricated."""
    # Clear through the delete-orphan collection so the in-memory list stays
    # consistent (db.delete leaves stale entries and duplicates on rebuild).
    inv.timeline_events.clear()
    db.flush()

    events = _static_events(analysis) + _runtime_events(analysis)
    for e in events:
        inv.timeline_events.append(InvestigationTimelineEvent(**e))
    # Re-attach note events (notes may already exist on the investigation).
    for i, note in enumerate(inv.notes):
        inv.timeline_events.append(InvestigationTimelineEvent(
            timestamp=note.created_at, event_type="RESEARCHER_NOTE", source="USER_NOTE",
            entity_ref=note.target_ref, confidence="N/A", detail=(note.body or "")[:200],
            sequence=10_000 + i))
    db.flush()
    return list(inv.timeline_events)


_STAGE_EVENT = {
    "ingest": ("APK_INGESTION", "DEX"),
    "manifest": ("MANIFEST_PARSE", "MANIFEST"),
    "jadx": ("JADX_DECOMPILE", "JADX"),
    "code_index": ("CODE_INDEX", "JADX"),
    "native": ("ELF_PARSE", "ELF"),
    "jni": ("JNI_ANALYSIS", "JNI"),
    "semantics": ("SEMANTIC_ANALYSIS", "SEMANTICS"),
    "reachability": ("REACHABILITY_ANALYSIS", "REACHABILITY"),
    "vulnerability_match": ("CVE_CORRELATION", "CVE_DATABASE"),
    "correlation": ("FINDING_GENERATION", "STATIC_RULE"),
}


def _static_events(analysis) -> list[dict]:
    base = analysis.started_at
    out = []
    for i, stage in enumerate(analysis.stages or []):
        mapping = _STAGE_EVENT.get(stage.get("name"))
        if mapping is None:
            continue
        event_type, source = mapping
        out.append({"timestamp": base, "event_type": event_type, "source": source,
                    "entity_ref": None, "confidence": _stage_conf(stage.get("status")),
                    "detail": f"{stage.get('name')}={stage.get('status')} {stage.get('detail', '')}".strip(),
                    "sequence": i})
    return out


def _runtime_events(analysis) -> list[dict]:
    out = []
    seq = 1000
    for s in analysis.runtime_sessions:
        out.append({"timestamp": s.started_at, "event_type": "RUNTIME_SESSION", "source": "RUNTIME_ADB",
                    "entity_ref": f"RUNTIME_SESSION:{s.id}", "confidence": "HIGH",
                    "detail": f"session {s.session_state} adapter={(s.metadata_ or {}).get('adapter')}",
                    "sequence": seq})
        seq += 1
        for o in s.observations:
            out.append({"timestamp": o.timestamp, "event_type": "LIVE_OBSERVATION"
                        if (s.metadata_ or {}).get("adapter") == "adb" else "RUNTIME_OBSERVATION",
                        "source": "RUNTIME_FRIDA" if o.source == "FRIDA" else "RUNTIME_ADB",
                        "entity_ref": f"RUNTIME_OBSERVATION:{o.id}", "confidence": o.confidence,
                        "detail": f"{o.observation_type} {o.class_name or ''}.{o.method_name or ''}{o.symbol or ''}".strip(),
                        "sequence": seq})
            seq += 1
    # runtime correlation events (prompt 21): persisted static↔runtime links
    for c in analysis.runtime_correlations:
        out.append({"timestamp": c.created_at, "event_type": "CORRELATION",
                    "source": c.provenance, "entity_ref": f"RUNTIME_CORRELATION:{c.fingerprint}",
                    "confidence": c.confidence,
                    "detail": f"{c.correlation_type} [{c.mode}] {c.subject_type} {c.detail[:80]}",
                    "sequence": seq})
        seq += 1
    return out


def _stage_conf(status: str | None) -> str:
    return {"COMPLETE": "HIGH", "DEGRADED": "MEDIUM", "PARTIAL": "MEDIUM"}.get(status or "", "UNKNOWN")


def timeline_view(inv: Investigation) -> list[dict]:
    def key(ev):
        ts = ev.timestamp
        return (ts.isoformat() if ts else "", ev.sequence)
    return [
        {"timestamp": _iso(ev.timestamp), "event_type": ev.event_type, "source": ev.source,
         "entity_ref": ev.entity_ref, "evidence_ref": ev.evidence_ref, "confidence": ev.confidence,
         "detail": ev.detail}
        for ev in sorted(inv.timeline_events, key=key)
    ]


# ---------------------------------------------------------------------------
# View
# ---------------------------------------------------------------------------


def investigation_view(inv: Investigation) -> dict:
    return {
        "id": str(inv.id), "analysis_id": str(inv.analysis_id), "name": inv.name,
        "description": inv.description, "status": inv.status, "created_by": inv.created_by,
        "created_at": _iso(inv.created_at), "updated_at": _iso(inv.updated_at),
        "nodes": [{"node_ref": n.node_ref, "type": n.node_type, "label": n.label, "note": n.note}
                  for n in inv.nodes],
        "edges": [{"src": e.src_ref, "dst": e.dst_ref, "type": e.edge_type, "note": e.note}
                  for e in inv.edges],
        "findings": [str(f.finding_id) for f in inv.findings],
        "notes": [{"id": str(n.id), "author": n.author, "body": n.body, "target_ref": n.target_ref,
                   "created_at": _iso(n.created_at)} for n in inv.notes],
        "hypotheses": [_hypothesis_view(h) for h in inv.hypotheses],
        "bookmarks": [{"ref_type": b.ref_type, "ref_id": b.ref_id, "label": b.label} for b in inv.bookmarks],
        "counts": {"nodes": len(inv.nodes), "edges": len(inv.edges), "findings": len(inv.findings),
                   "notes": len(inv.notes), "hypotheses": len(inv.hypotheses), "bookmarks": len(inv.bookmarks)},
    }


def _hypothesis_view(h: InvestigationHypothesis) -> dict:
    return {"id": str(h.id), "statement": h.statement, "status": h.status, "rationale": h.rationale,
            "annotation": "researcher hypothesis — does not change machine findings",
            "evidence": [{"ref_type": e.ref_type, "ref_id": e.ref_id, "detail": e.detail} for e in h.evidence]}


def _iso(value) -> str | None:
    return value.isoformat() if value else None

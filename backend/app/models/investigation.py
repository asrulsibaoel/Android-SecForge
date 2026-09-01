"""Investigation workspace + graph-snapshot models (prompt 14).

These tables hold *researcher state* — investigations, pinned nodes/paths,
notes, hypotheses, bookmarks, and a deterministic investigation timeline — plus
graph snapshots for reproducibility. They are strictly separate from analytical
truth: nothing here writes back to findings, severity, confidence, risk, CVE
state, or the canonical code graph. A hypothesis is an annotation, never a fact.

The knowledge graph itself is NOT persisted as a second graph; it is projected
on demand from the existing canonical tables (see
``app.analysis.knowledge_graph``). Only investigation state and snapshots are
stored here, and they reference graph nodes/entities by their stable string IDs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Hypothesis lifecycle states. A hypothesis is researcher state and is NEVER
# automatically promoted; SUPPORTED/REFUTED require an explicit researcher action.
HYPOTHESIS_OPEN = "OPEN"
HYPOTHESIS_SUPPORTED = "SUPPORTED"
HYPOTHESIS_REFUTED = "REFUTED"
HYPOTHESIS_UNKNOWN = "UNKNOWN"
HYPOTHESIS_STATES = (HYPOTHESIS_OPEN, HYPOTHESIS_SUPPORTED, HYPOTHESIS_REFUTED, HYPOTHESIS_UNKNOWN)


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(256), default="Investigation")
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="OPEN")  # OPEN | ARCHIVED
    created_by: Mapped[str] = mapped_column(String(128), default="cli")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    analysis: Mapped["Analysis"] = relationship(back_populates="investigations")  # noqa: F821
    nodes: Mapped[list["InvestigationNode"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    edges: Mapped[list["InvestigationEdge"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    findings: Mapped[list["InvestigationFinding"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    notes: Mapped[list["InvestigationNote"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    hypotheses: Mapped[list["InvestigationHypothesis"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    bookmarks: Mapped[list["InvestigationBookmark"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    timeline_events: Mapped[list["InvestigationTimelineEvent"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )


class InvestigationNode(Base):
    """A canonical graph node the researcher pinned into the investigation.

    ``node_ref`` is the stable knowledge-graph node ID (never a copy of the
    node's analytical data — the projection remains the source of truth)."""
    __tablename__ = "investigation_nodes"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    node_ref: Mapped[str] = mapped_column(String(1024), index=True)
    node_type: Mapped[str] = mapped_column(String(32))
    label: Mapped[str] = mapped_column(String(512), default="")
    note: Mapped[str] = mapped_column(Text, default="")
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    investigation: Mapped[Investigation] = relationship(back_populates="nodes")


class InvestigationEdge(Base):
    """A pinned relationship or path segment (references graph node IDs)."""
    __tablename__ = "investigation_edges"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    src_ref: Mapped[str] = mapped_column(String(1024))
    dst_ref: Mapped[str] = mapped_column(String(1024))
    edge_type: Mapped[str] = mapped_column(String(32))
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    note: Mapped[str] = mapped_column(Text, default="")
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    investigation: Mapped[Investigation] = relationship(back_populates="edges")


class InvestigationFinding(Base):
    __tablename__ = "investigation_findings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    investigation: Mapped[Investigation] = relationship(back_populates="findings")


class InvestigationNote(Base):
    """A free-text researcher annotation. Clearly machine-distinct: it is stored
    here, never merged into finding descriptions or evidence."""
    __tablename__ = "investigation_notes"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    body: Mapped[str] = mapped_column(Text, default="")
    author: Mapped[str] = mapped_column(String(128), default="researcher")
    target_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)  # optional node/finding it annotates
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    investigation: Mapped[Investigation] = relationship(back_populates="notes")


class InvestigationHypothesis(Base):
    """A researcher hypothesis. ``status`` is researcher state only and MUST NOT
    change any finding severity/confidence/status or the analytical truth."""
    __tablename__ = "investigation_hypotheses"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    statement: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default=HYPOTHESIS_OPEN)
    rationale: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    investigation: Mapped[Investigation] = relationship(back_populates="hypotheses")
    evidence: Mapped[list["InvestigationHypothesisEvidence"]] = relationship(
        back_populates="hypothesis", cascade="all, delete-orphan"
    )


class InvestigationHypothesisEvidence(Base):
    __tablename__ = "investigation_hypothesis_evidence"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    hypothesis_id: Mapped[UUID] = mapped_column(ForeignKey("investigation_hypotheses.id", ondelete="CASCADE"), index=True)
    ref_type: Mapped[str] = mapped_column(String(24))  # NODE | EDGE | FINDING | PATH | OBSERVATION | CVE | NOTE
    ref_id: Mapped[str] = mapped_column(String(1024))
    detail: Mapped[str] = mapped_column(Text, default="")
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    hypothesis: Mapped[InvestigationHypothesis] = relationship(back_populates="evidence")


class InvestigationBookmark(Base):
    __tablename__ = "investigation_bookmarks"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    ref_type: Mapped[str] = mapped_column(String(24))  # NODE | FINDING | PATH | EVIDENCE | CVE | OBSERVATION
    ref_id: Mapped[str] = mapped_column(String(1024))
    label: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    investigation: Mapped[Investigation] = relationship(back_populates="bookmarks")


class InvestigationTimelineEvent(Base):
    """A deterministic timeline event. Static events use analysis timestamps;
    runtime events use their actual timestamps. Historical timestamps are never
    fabricated."""
    __tablename__ = "investigation_timeline_events"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(24))
    entity_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    evidence_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    confidence: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    detail: Mapped[str] = mapped_column(Text, default="")
    sequence: Mapped[int] = mapped_column(Integer, default=0)  # deterministic tie-break ordering

    investigation: Mapped[Investigation] = relationship(back_populates="timeline_events")


class GraphSnapshot(Base):
    """A reproducibility record: counts + a deterministic content hash of the
    projected knowledge graph. Same persisted analysis → same hash."""
    __tablename__ = "graph_snapshots"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    graph_version: Mapped[str] = mapped_column(String(32), default="kg/1")
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    root_cause_count: Mapped[int] = mapped_column(Integer, default=0)
    runtime_observation_count: Mapped[int] = mapped_column(Integer, default=0)
    node_type_counts: Mapped[dict] = mapped_column(JSON, default=dict)
    edge_type_counts: Mapped[dict] = mapped_column(JSON, default=dict)
    digest: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    analysis: Mapped["Analysis"] = relationship(back_populates="graph_snapshots")  # noqa: F821


Index("ix_investigation_nodes_inv_ref", InvestigationNode.investigation_id, InvestigationNode.node_ref)
Index("ix_investigation_timeline_inv_seq", InvestigationTimelineEvent.investigation_id, InvestigationTimelineEvent.sequence)
Index("ix_graph_snapshots_analysis_digest", GraphSnapshot.analysis_id, GraphSnapshot.digest)

"""Comparative-analysis (APK diff) models (prompt 15).

A comparison references two existing analyses (baseline A, candidate B) and,
where available, their prompt-14 graph snapshots. It never copies or mutates the
canonical graph or either analysis — it only records the deterministic
differences plus a conservative security-impact verdict, all with provenance.

Direction matters: A→B is a distinct comparison from B→A, and the fingerprint
encodes the ordered pair.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Comparison status.
STATUS_COMPLETE = "COMPLETE"
STATUS_PARTIAL = "PARTIAL"
STATUS_FAILED = "FAILED"

# Snapshot mode.
MODE_SNAPSHOT = "SNAPSHOT"
MODE_RECONSTRUCTED = "RECONSTRUCTED"
MODE_MIXED = "MIXED"

# Security-impact verdicts (conservative).
IMPACT_REGRESSION = "SECURITY_REGRESSION"
IMPACT_IMPROVEMENT = "SECURITY_IMPROVEMENT"
IMPACT_MIXED = "MIXED"
IMPACT_NONE = "NO_MATERIAL_SECURITY_CHANGE"
IMPACT_INCONCLUSIVE = "INCONCLUSIVE"

# Change types.
CHANGE_ADDED = "ADDED"
CHANGE_REMOVED = "REMOVED"
CHANGE_CHANGED = "CHANGED"
CHANGE_UNCHANGED = "UNCHANGED"


class AnalysisComparison(Base):
    __tablename__ = "analysis_comparisons"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    baseline_analysis_id: Mapped[UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    candidate_analysis_id: Mapped[UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    snapshot_a_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("graph_snapshots.id", ondelete="SET NULL"), nullable=True)
    snapshot_b_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("graph_snapshots.id", ondelete="SET NULL"), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16), default=STATUS_COMPLETE, index=True)
    snapshot_mode: Mapped[str] = mapped_column(String(16), default=MODE_RECONSTRUCTED)
    security_impact: Mapped[str] = mapped_column(String(32), default=IMPACT_NONE, index=True)
    impact_confidence: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    requested_by: Mapped[str] = mapped_column(String(128), default="cli")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)

    baseline: Mapped["Analysis"] = relationship(  # noqa: F821
        foreign_keys=[baseline_analysis_id])
    candidate: Mapped["Analysis"] = relationship(  # noqa: F821
        foreign_keys=[candidate_analysis_id])
    changes: Mapped[list["ComparisonChange"]] = relationship(
        back_populates="comparison", cascade="all, delete-orphan")
    finding_changes: Mapped[list["ComparisonFinding"]] = relationship(
        back_populates="comparison", cascade="all, delete-orphan")
    risk_delta: Mapped["ComparisonRiskDelta | None"] = relationship(
        back_populates="comparison", cascade="all, delete-orphan", uselist=False)
    category_summaries: Mapped[list["ComparisonSummary"]] = relationship(
        back_populates="comparison", cascade="all, delete-orphan")


class ComparisonChange(Base):
    __tablename__ = "comparison_changes"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    comparison_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_comparisons.id", ondelete="CASCADE"), index=True)
    category: Mapped[str] = mapped_column(String(24), index=True)
    entity_type: Mapped[str] = mapped_column(String(32), index=True)
    entity_identity: Mapped[str] = mapped_column(String(1024), index=True)
    change_type: Mapped[str] = mapped_column(String(16), index=True)
    baseline_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    candidate_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    security_relevant: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    provenance: Mapped[str] = mapped_column(String(32), default="STATIC")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)

    comparison: Mapped[AnalysisComparison] = relationship(back_populates="changes")


class ComparisonFinding(Base):
    __tablename__ = "comparison_findings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    comparison_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_comparisons.id", ondelete="CASCADE"), index=True)
    change_type: Mapped[str] = mapped_column(String(16), index=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    baseline_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    candidate_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    component: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    changed_dimensions: Mapped[list] = mapped_column(JSON, default=list)
    confidence: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    security_relevant: Mapped[bool] = mapped_column(Boolean, default=False)
    baseline_value: Mapped[dict] = mapped_column(JSON, default=dict)
    candidate_value: Mapped[dict] = mapped_column(JSON, default=dict)

    comparison: Mapped[AnalysisComparison] = relationship(back_populates="finding_changes")


class ComparisonRiskDelta(Base):
    __tablename__ = "comparison_risk_deltas"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    comparison_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_comparisons.id", ondelete="CASCADE"), index=True)
    baseline_score: Mapped[int] = mapped_column(Integer, default=0)
    candidate_score: Mapped[int] = mapped_column(Integer, default=0)
    delta: Mapped[int] = mapped_column(Integer, default=0)
    baseline_severity: Mapped[str] = mapped_column(String(16), default="info")
    candidate_severity: Mapped[str] = mapped_column(String(16), default="info")
    severity_transition: Mapped[str] = mapped_column(String(48), default="")
    baseline_confidence: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    candidate_confidence: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    confidence_transition: Mapped[str] = mapped_column(String(48), default="")
    factor_changes: Mapped[dict] = mapped_column(JSON, default=dict)

    comparison: Mapped[AnalysisComparison] = relationship(back_populates="risk_delta")


class ComparisonSummary(Base):
    """Per-category counts (ADDED/REMOVED/CHANGED/UNCHANGED + security-relevant)."""
    __tablename__ = "comparison_summaries"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    comparison_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_comparisons.id", ondelete="CASCADE"), index=True)
    category: Mapped[str] = mapped_column(String(24), index=True)
    added: Mapped[int] = mapped_column(Integer, default=0)
    removed: Mapped[int] = mapped_column(Integer, default=0)
    changed: Mapped[int] = mapped_column(Integer, default=0)
    unchanged: Mapped[int] = mapped_column(Integer, default=0)
    security_relevant: Mapped[int] = mapped_column(Integer, default=0)

    comparison: Mapped[AnalysisComparison] = relationship(back_populates="category_summaries")


Index("ix_comparison_changes_cmp_cat", ComparisonChange.comparison_id, ComparisonChange.category)
Index("ix_comparison_changes_cmp_type", ComparisonChange.comparison_id, ComparisonChange.change_type)
Index("ix_analysis_comparisons_pair", AnalysisComparison.baseline_analysis_id,
      AnalysisComparison.candidate_analysis_id)

"""Live runtime validation & behavioral corroboration models (prompt 21).

Persisted, provenance-backed correlation between LIVE (or MOCKED) runtime
observations and the existing static model. Runtime evidence is a separate source
that NEVER overwrites static truth and NEVER asserts exploitability. LIVE and
MOCKED are kept strictly distinct: only genuinely LIVE evidence can corroborate.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Evidence mode — LIVE vs MOCKED must never be conflated.
MODE_LIVE = "LIVE"
MODE_MOCKED = "MOCKED"
MODE_UNAVAILABLE = "UNAVAILABLE"

# Correlation types (also KG edge types).
CORR_CONFIRMS = "RUNTIME_CONFIRMS"
CORR_CORROBORATES = "RUNTIME_CORROBORATES"
CORR_REACHES = "RUNTIME_REACHES"
CORR_INVOCATION = "RUNTIME_INVOCATION"

# Finding runtime-validation states (additive; never change severity/risk/etc).
RVS_CONFIRMED = "CONFIRMED_RUNTIME_BEHAVIOR"
RVS_CORROBORATED = "RUNTIME_CORROBORATED"
RVS_NOT_OBSERVED = "NOT_OBSERVED"
RVS_INCONCLUSIVE = "RUNTIME_INCONCLUSIVE"
RVS_LIVE_UNAVAILABLE = "LIVE_UNAVAILABLE"


class RuntimeValidationRun(Base):
    __tablename__ = "runtime_validation_runs"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    session_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("runtime_sessions.id", ondelete="SET NULL"), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    mode: Mapped[str] = mapped_column(String(16), default=MODE_UNAVAILABLE)  # LIVE | MOCKED | UNAVAILABLE
    device_serial: Mapped[str | None] = mapped_column(String(128), nullable=True)
    apk_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    observation_count: Mapped[int] = mapped_column(Integer, default=0)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    process_count: Mapped[int] = mapped_column(Integer, default=0)
    artifact_count: Mapped[int] = mapped_column(Integer, default=0)
    correlation_count: Mapped[int] = mapped_column(Integer, default=0)
    live_claim_count: Mapped[int] = mapped_column(Integer, default=0)
    corroborated_finding_count: Mapped[int] = mapped_column(Integer, default=0)
    truncated: Mapped[dict] = mapped_column(JSON, default=dict)
    blockers: Mapped[list] = mapped_column(JSON, default=list)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    analysis: Mapped["Analysis"] = relationship(back_populates="runtime_validation_runs")  # noqa: F821


class RuntimeCorrelation(Base):
    __tablename__ = "runtime_correlations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    run_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("runtime_validation_runs.id", ondelete="CASCADE"), nullable=True, index=True)
    observation_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("runtime_observations.id", ondelete="SET NULL"), nullable=True)
    session_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("runtime_sessions.id", ondelete="SET NULL"), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    subject_type: Mapped[str] = mapped_column(String(24), index=True)  # FINDING/CODE_METHOD/COMPONENT/JNI_BINDING/...
    subject_ref: Mapped[str] = mapped_column(String(1024))
    taxonomy: Mapped[str | None] = mapped_column(String(40), nullable=True)
    correlation_type: Mapped[str] = mapped_column(String(24))  # RUNTIME_CONFIRMS/CORROBORATES/REACHES/INVOCATION
    mode: Mapped[str] = mapped_column(String(16), default=MODE_MOCKED)  # LIVE | MOCKED
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")
    provenance: Mapped[str] = mapped_column(String(16), default="RUNTIME_FRIDA")  # RUNTIME_ADB | RUNTIME_FRIDA
    detail: Mapped[str] = mapped_column(Text, default="")
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    analysis: Mapped["Analysis"] = relationship(back_populates="runtime_correlations")  # noqa: F821


Index("ix_runtime_correlations_subject", RuntimeCorrelation.analysis_id, RuntimeCorrelation.subject_type)

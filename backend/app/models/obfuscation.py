"""Obfuscation & anti-analysis intelligence models (prompt 19).

A deterministic, offline projection over already-persisted evidence (code
entities, code graph, semantics, native/JNI) that identifies transformations
making static analysis difficult and the analytical impact that results. It is
analysis intelligence, not an evasion/bypass engine: it never mutates findings,
CVE state, severity, risk, or the canonical graph, never asserts exploitability,
and preserves observed-fact vs indicator vs unknown distinctions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Observation states (fact vs indicator vs inferred vs unknown vs unsupported).
S_OBSERVED = "OBSERVED"
S_STRONG_INDICATOR = "STRONG_INDICATOR"
S_WEAK_INDICATOR = "WEAK_INDICATOR"
S_INFERRED = "INFERRED"
S_UNKNOWN = "UNKNOWN"
S_UNSUPPORTED = "UNSUPPORTED"
# Reflection / dynamic-load resolution states.
S_RESOLVED = "RESOLVED"
S_PARTIALLY_RESOLVED = "PARTIALLY_RESOLVED"
S_EXTERNALLY_INFLUENCED = "EXTERNALLY_INFLUENCED"
S_UNRESOLVED = "UNRESOLVED"

# Anti-analysis evidence levels.
L_INDICATOR = "INDICATOR"
L_SUPPORTED = "SUPPORTED"
L_CONFIRMED_STATIC = "CONFIRMED_STATIC"
L_UNKNOWN = "UNKNOWN"


class ObfuscationObservation(Base):
    __tablename__ = "obfuscation_observations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    finding_type: Mapped[str] = mapped_column(String(32), index=True)  # ANDROID-OBFUSCATION-00X
    category: Mapped[str] = mapped_column(String(32), index=True)
    indicator: Mapped[str] = mapped_column(String(256))
    target_type: Mapped[str] = mapped_column(String(24), default="APK")
    target: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    state: Mapped[str] = mapped_column(String(24), default=S_UNKNOWN, index=True)
    confidence: Mapped[str] = mapped_column(String(16), default="LOW")
    source_type: Mapped[str] = mapped_column(String(24), default="STATIC_RULE")
    source_id: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    uncertainties: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    analysis: Mapped["Analysis"] = relationship(back_populates="obfuscation_observations")  # noqa: F821


class AntiAnalysisIndicator(Base):
    __tablename__ = "anti_analysis_indicators"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    finding_type: Mapped[str] = mapped_column(String(32), index=True)  # ANDROID-ANTI-ANALYSIS-00X
    category: Mapped[str] = mapped_column(String(32), index=True)
    indicator: Mapped[str] = mapped_column(String(256))
    target_type: Mapped[str] = mapped_column(String(24), default="APK")
    target: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    evidence_level: Mapped[str] = mapped_column(String(20), default=L_INDICATOR, index=True)
    confidence: Mapped[str] = mapped_column(String(16), default="LOW")
    source_type: Mapped[str] = mapped_column(String(24), default="STATIC_RULE")
    source_id: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    uncertainties: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    analysis: Mapped["Analysis"] = relationship(back_populates="anti_analysis_indicators")  # noqa: F821


class AnalysisImpact(Base):
    __tablename__ = "analysis_impacts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    impact_category: Mapped[str] = mapped_column(String(40), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    affected_target: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    confidence: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    source_observation_fp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    analysis: Mapped["Analysis"] = relationship(back_populates="analysis_impacts")  # noqa: F821


Index("ix_obf_observations_analysis_category", ObfuscationObservation.analysis_id, ObfuscationObservation.category)
Index("ix_anti_analysis_analysis_category", AntiAnalysisIndicator.analysis_id, AntiAnalysisIndicator.category)
Index("ix_analysis_impacts_analysis_category", AnalysisImpact.analysis_id, AnalysisImpact.impact_category)

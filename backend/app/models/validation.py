"""Security verification & validation-intelligence models (prompt 18).

A validation layer that projects over already-persisted evidence to answer *what
security claim can currently be verified, corroborated, or remains unverified,
and what evidence is still required*. It is NOT an exploitability engine and
never introduces an `exploitable` state. It never mutates findings, CVE state,
risk, or remediation priority — validation is an additional axis with its own
deterministic fingerprints.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Validation states (none implies exploitability).
VS_UNVERIFIED = "UNVERIFIED"
VS_STATIC_SUPPORTED = "STATIC_SUPPORTED"
VS_RUNTIME_CORROBORATED = "RUNTIME_CORROBORATED"
VS_MULTI_SOURCE = "MULTI_SOURCE_CORROBORATED"
VS_BLOCKED = "VALIDATION_BLOCKED"
VS_INCONCLUSIVE = "INCONCLUSIVE"
VS_NOT_APPLICABLE = "NOT_APPLICABLE"
VS_SUPERSEDED = "SUPERSEDED"


class ValidationClaim(Base):
    __tablename__ = "validation_claims"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True)
    remediation_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)  # remediation item fingerprint
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)  # analysis-independent identity
    claim_type: Mapped[str] = mapped_column(String(40), index=True)
    target_type: Mapped[str] = mapped_column(String(24), default="FINDING")
    target: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    current_state: Mapped[str | None] = mapped_column(String(256), nullable=True)
    validation_state: Mapped[str] = mapped_column(String(28), default=VS_UNVERIFIED, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    independent_source_count: Mapped[int] = mapped_column(Integer, default=0)
    source_families: Mapped[list] = mapped_column(JSON, default=list)
    required_capabilities: Mapped[list] = mapped_column(JSON, default=list)
    missing_evidence: Mapped[list] = mapped_column(JSON, default=list)
    uncertainty: Mapped[list] = mapped_column(JSON, default=list)
    provenance: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    analysis: Mapped["Analysis"] = relationship(back_populates="validation_claims")  # noqa: F821
    evidence: Mapped[list["ValidationEvidence"]] = relationship(
        back_populates="claim", cascade="all, delete-orphan")
    blockers: Mapped[list["ValidationBlocker"]] = relationship(
        back_populates="claim", cascade="all, delete-orphan")
    requirements: Mapped[list["ValidationRequirement"]] = relationship(
        back_populates="claim", cascade="all, delete-orphan")


class ValidationEvidence(Base):
    __tablename__ = "validation_evidence"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    claim_id: Mapped[UUID] = mapped_column(ForeignKey("validation_claims.id", ondelete="CASCADE"), index=True)
    source_family: Mapped[str] = mapped_column(String(28), index=True)
    source_type: Mapped[str] = mapped_column(String(32))
    source_id: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    confidence: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    live: Mapped[bool] = mapped_column(Boolean, default=False)  # runtime: LIVE vs MOCKED
    detail: Mapped[str] = mapped_column(Text, default="")
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    claim: Mapped[ValidationClaim] = relationship(back_populates="evidence")


class ValidationBlocker(Base):
    __tablename__ = "validation_blockers"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    claim_id: Mapped[UUID] = mapped_column(ForeignKey("validation_claims.id", ondelete="CASCADE"), index=True)
    blocker: Mapped[str] = mapped_column(String(32), index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    missing: Mapped[str] = mapped_column(Text, default="")

    claim: Mapped[ValidationClaim] = relationship(back_populates="blockers")


class ValidationRequirement(Base):
    __tablename__ = "validation_requirements"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    claim_id: Mapped[UUID] = mapped_column(ForeignKey("validation_claims.id", ondelete="CASCADE"), index=True)
    requirement: Mapped[str] = mapped_column(String(48))
    satisfied: Mapped[bool] = mapped_column(Boolean, default=False)
    detail: Mapped[str] = mapped_column(Text, default="")

    claim: Mapped[ValidationClaim] = relationship(back_populates="requirements")


class ValidationTransition(Base):
    """Baseline→candidate validation transition (from an APK comparison)."""
    __tablename__ = "validation_transitions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), nullable=True, index=True)
    comparison_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("analysis_comparisons.id", ondelete="CASCADE"), nullable=True, index=True)
    claim_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    baseline_state: Mapped[str] = mapped_column(String(28))
    candidate_state: Mapped[str] = mapped_column(String(28))
    transition: Mapped[str] = mapped_column(String(48))
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


Index("ix_validation_claims_analysis_type", ValidationClaim.analysis_id, ValidationClaim.claim_type)
Index("ix_validation_claims_analysis_state", ValidationClaim.analysis_id, ValidationClaim.validation_state)

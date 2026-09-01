"""Security assessment / decision-intelligence models (prompt 24).

A projection layer: every conclusion references existing persisted evidence by
its ID / fingerprint and duplicates no canonical finding / CVE / remediation /
validation / native / runtime record. Deterministic, content-derived fingerprints
(no DB ids / timestamps participate). No `exploitable` field exists.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(28), default="ASSESSMENT_INCONCLUSIVE")
    subject_count: Mapped[int] = mapped_column(Integer, default=0)
    conclusion_count: Mapped[int] = mapped_column(Integer, default=0)
    open_count: Mapped[int] = mapped_column(Integer, default=0)
    blocker_count: Mapped[int] = mapped_column(Integer, default=0)
    truncated: Mapped[dict] = mapped_column(JSON, default=dict)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    requested_by: Mapped[str] = mapped_column(String(128), default="cli")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    analysis: Mapped["Analysis"] = relationship(back_populates="assessments")  # noqa: F821
    subjects: Mapped[list["AssessmentSubject"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan")
    conclusions: Mapped[list["SecurityConclusion"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan")
    summaries: Mapped[list["AssessmentSummary"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan")
    transitions: Mapped[list["AssessmentTransition"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan")


class AssessmentSubject(Base):
    __tablename__ = "assessment_subjects"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    subject_type: Mapped[str] = mapped_column(String(24), index=True)  # FINDING/CVE/RUNTIME/NATIVE/REMEDIATION/ASSESSMENT
    subject_ref: Mapped[str] = mapped_column(String(1024))  # existing entity id / fingerprint (never duplicated)
    label: Mapped[str] = mapped_column(String(512), default="")

    assessment: Mapped[Assessment] = relationship(back_populates="subjects")


class SecurityConclusion(Base):
    __tablename__ = "security_conclusions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    subject_type: Mapped[str] = mapped_column(String(24), index=True)
    subject_ref: Mapped[str] = mapped_column(String(1024))
    conclusion_type: Mapped[str] = mapped_column(String(48), index=True)
    decision_state: Mapped[str] = mapped_column(String(28), index=True)
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")
    rule_id: Mapped[str] = mapped_column(String(64), default="")  # the inspectable rule that fired
    rationale: Mapped[str] = mapped_column(Text, default="")

    assessment: Mapped[Assessment] = relationship(back_populates="conclusions")
    evidence: Mapped[list["DecisionEvidence"]] = relationship(
        back_populates="conclusion", cascade="all, delete-orphan")
    blockers: Mapped[list["DecisionBlocker"]] = relationship(
        back_populates="conclusion", cascade="all, delete-orphan")
    requirements: Mapped[list["DecisionRequirement"]] = relationship(
        back_populates="conclusion", cascade="all, delete-orphan")
    dependencies: Mapped[list["DecisionDependency"]] = relationship(
        back_populates="conclusion", cascade="all, delete-orphan")


class DecisionEvidence(Base):
    __tablename__ = "decision_evidence"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    conclusion_id: Mapped[UUID] = mapped_column(ForeignKey("security_conclusions.id", ondelete="CASCADE"), index=True)
    source_layer: Mapped[str] = mapped_column(String(24), index=True)  # FINDINGS/CVE/VALIDATION/RUNTIME/NATIVE_DEEP/...
    evidence_ref: Mapped[str] = mapped_column(String(1024))  # existing id / fingerprint of the referenced record
    mode: Mapped[str] = mapped_column(String(16), default="STATIC")  # STATIC | LIVE | MOCKED | UNAVAILABLE
    provenance: Mapped[str] = mapped_column(String(32), default="STATIC")
    detail: Mapped[str] = mapped_column(Text, default="")

    conclusion: Mapped[SecurityConclusion] = relationship(back_populates="evidence")


class DecisionBlocker(Base):
    __tablename__ = "decision_blockers"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    conclusion_id: Mapped[UUID] = mapped_column(ForeignKey("security_conclusions.id", ondelete="CASCADE"), index=True)
    blocker: Mapped[str] = mapped_column(String(48))
    reason: Mapped[str] = mapped_column(Text, default="")
    missing: Mapped[str] = mapped_column(String(256), default="")

    conclusion: Mapped[SecurityConclusion] = relationship(back_populates="blockers")


class DecisionRequirement(Base):
    __tablename__ = "decision_requirements"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    conclusion_id: Mapped[UUID] = mapped_column(ForeignKey("security_conclusions.id", ondelete="CASCADE"), index=True)
    requirement: Mapped[str] = mapped_column(String(64))
    satisfied: Mapped[bool] = mapped_column(Boolean, default=False)
    detail: Mapped[str] = mapped_column(Text, default="")

    conclusion: Mapped[SecurityConclusion] = relationship(back_populates="requirements")


class DecisionDependency(Base):
    __tablename__ = "decision_dependencies"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    conclusion_id: Mapped[UUID] = mapped_column(ForeignKey("security_conclusions.id", ondelete="CASCADE"), index=True)
    depends_on: Mapped[str] = mapped_column(String(1024))  # conclusion fingerprint or existing entity ref
    dependency_type: Mapped[str] = mapped_column(String(32), default="CONCLUSION")
    detail: Mapped[str] = mapped_column(Text, default="")

    conclusion: Mapped[SecurityConclusion] = relationship(back_populates="dependencies")


class AssessmentTransition(Base):
    __tablename__ = "assessment_transitions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    subject_ref: Mapped[str] = mapped_column(String(1024))
    transition: Mapped[str] = mapped_column(String(48))  # e.g. NEW_CONCLUSION / STATE_CHANGED / NO_LONGER_PRESENT
    from_state: Mapped[str | None] = mapped_column(String(28), nullable=True)
    to_state: Mapped[str | None] = mapped_column(String(28), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")

    assessment: Mapped[Assessment] = relationship(back_populates="transitions")


class AssessmentSummary(Base):
    __tablename__ = "assessment_summaries"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    dimension: Mapped[str] = mapped_column(String(32))  # by_decision_state / by_conclusion_type / by_subject_type
    counts: Mapped[dict] = mapped_column(JSON, default=dict)

    assessment: Mapped[Assessment] = relationship(back_populates="summaries")


Index("ix_security_conclusions_state", SecurityConclusion.assessment_id, SecurityConclusion.decision_state)

"""Remediation-planning models (prompt 17).

A remediation plan is a deterministic *projection* over the already-persisted
analysis evidence (findings, CVE matches, root causes, attack surface,
reachability, semantics, native/JNI, runtime). It NEVER mutates findings, CVE
state, risk, attack-surface nodes, or the canonical graph. Every recommendation
is evidence-backed and carries a stable fingerprint for deterministic dedup.
Recommendations are review/fix guidance — never automatic patches, and never an
exploitability claim.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Remediation statuses (none implies exploitability).
STATUS_OPEN = "OPEN"
STATUS_REVIEW_REQUIRED = "REVIEW_REQUIRED"
STATUS_VERSION_UNVERIFIED = "VERSION_UNVERIFIED"
STATUS_RECOMMENDED = "RECOMMENDED"
STATUS_CONDITIONALLY_RECOMMENDED = "CONDITIONALLY_RECOMMENDED"
STATUS_REMEDIATED = "REMEDIATED"
STATUS_NO_LONGER_DETECTED = "NO_LONGER_DETECTED"
STATUS_INCONCLUSIVE = "INCONCLUSIVE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"
STATUS_NEW_REMEDIATION_REQUIRED = "NEW_REMEDIATION_REQUIRED"

# Priority bands (remediation priority, NOT exploitability).
PRIORITY_CRITICAL = "CRITICAL"
PRIORITY_HIGH = "HIGH"
PRIORITY_MEDIUM = "MEDIUM"
PRIORITY_LOW = "LOW"
PRIORITY_INFO = "INFO"
PRIORITY_UNDETERMINED = "UNDETERMINED"

# Fixability classes.
FIX_DIRECT = "DIRECT_FIX"
FIX_CONDITIONAL = "CONDITIONAL_FIX"
FIX_CODE_REVIEW = "CODE_REVIEW"
FIX_CONFIG_REVIEW = "CONFIGURATION_REVIEW"
FIX_ARCH_REVIEW = "ARCHITECTURAL_REVIEW"
FIX_ENVIRONMENTAL = "ENVIRONMENTAL"
FIX_UNKNOWN = "UNKNOWN_FIX"


class RemediationPlan(Base):
    __tablename__ = "remediation_plans"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16), default="COMPLETE")
    item_count: Mapped[int] = mapped_column(Integer, default=0)
    requested_by: Mapped[str] = mapped_column(String(128), default="cli")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    priority_distribution: Mapped[dict] = mapped_column(JSON, default=dict)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)

    analysis: Mapped["Analysis"] = relationship(back_populates="remediation_plans")  # noqa: F821
    items: Mapped[list["RemediationItem"]] = relationship(
        back_populates="plan", cascade="all, delete-orphan")
    dependencies: Mapped[list["RemediationDependency"]] = relationship(
        back_populates="plan", cascade="all, delete-orphan")


class RemediationItem(Base):
    __tablename__ = "remediation_items"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    plan_id: Mapped[UUID] = mapped_column(ForeignKey("remediation_plans.id", ondelete="CASCADE"), index=True)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)  # deterministic dedup
    action: Mapped[str] = mapped_column(String(48), index=True)
    status: Mapped[str] = mapped_column(String(24), index=True)
    priority: Mapped[str] = mapped_column(String(16), index=True)
    priority_score: Mapped[int] = mapped_column(Integer, default=0)
    fixability: Mapped[str] = mapped_column(String(24), index=True)
    source_category: Mapped[str] = mapped_column(String(24), index=True)
    target: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    target_type: Mapped[str] = mapped_column(String(24), default="FINDING")
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text, default="")
    current_state: Mapped[str | None] = mapped_column(String(256), nullable=True)
    recommended_state: Mapped[str | None] = mapped_column(String(512), nullable=True)
    confidence: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    uncertainties: Mapped[list] = mapped_column(JSON, default=list)
    priority_factors: Mapped[list] = mapped_column(JSON, default=list)

    plan: Mapped[RemediationPlan] = relationship(back_populates="items")
    evidence: Mapped[list["RemediationEvidence"]] = relationship(
        back_populates="item", cascade="all, delete-orphan")
    actions: Mapped[list["RemediationAction"]] = relationship(
        back_populates="item", cascade="all, delete-orphan")


class RemediationEvidence(Base):
    __tablename__ = "remediation_evidence"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    item_id: Mapped[UUID] = mapped_column(ForeignKey("remediation_items.id", ondelete="CASCADE"), index=True)
    source_type: Mapped[str] = mapped_column(String(32), index=True)  # FINDING|CVE|ROOT_CAUSE|ATTACK_SURFACE|...
    source_id: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    confidence: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    detail: Mapped[str] = mapped_column(Text, default="")
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    item: Mapped[RemediationItem] = relationship(back_populates="evidence")


class RemediationAction(Base):
    """An ordered concrete step of a remediation item (e.g. VERIFY_VERSION then
    UPDATE_DEPENDENCY). Preserves prerequisite ordering within an item."""
    __tablename__ = "remediation_actions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    item_id: Mapped[UUID] = mapped_column(ForeignKey("remediation_items.id", ondelete="CASCADE"), index=True)
    order: Mapped[int] = mapped_column(Integer, default=0)
    action: Mapped[str] = mapped_column(String(48))
    target: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    recommended_state: Mapped[str | None] = mapped_column(String(512), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")

    item: Mapped[RemediationItem] = relationship(back_populates="actions")


class RemediationDependency(Base):
    """Item→item prerequisite/ordering relationship (NOT a second graph — only
    the ordering relationships needed to explain sequencing are persisted)."""
    __tablename__ = "remediation_dependencies"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    plan_id: Mapped[UUID] = mapped_column(ForeignKey("remediation_plans.id", ondelete="CASCADE"), index=True)
    from_item_id: Mapped[UUID] = mapped_column(ForeignKey("remediation_items.id", ondelete="CASCADE"))
    to_item_id: Mapped[UUID] = mapped_column(ForeignKey("remediation_items.id", ondelete="CASCADE"))
    relation: Mapped[str] = mapped_column(String(24), default="BLOCKED_BY")

    plan: Mapped[RemediationPlan] = relationship(back_populates="dependencies")


Index("ix_remediation_items_plan_priority", RemediationItem.plan_id, RemediationItem.priority)
Index("ix_remediation_items_analysis_action", RemediationItem.analysis_id, RemediationItem.action)

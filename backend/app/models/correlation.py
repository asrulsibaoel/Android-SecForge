"""Correlation, root-cause, attack-surface, and risk models.

These unify the existing independent analysis outputs (findings, reachability
paths, boundaries, dependencies, CVE matches) into a single security model. They
reference — never duplicate — the underlying evidence.
"""

from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import Boolean, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class FindingCorrelation(Base):
    """Index row: a finding participates in a correlation group keyed by a shared
    evidence dimension (component / sink / dependency / cve / boundary / entry)."""
    __tablename__ = "finding_correlations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    dimension: Mapped[str] = mapped_column(String(32), index=True)
    correlation_key: Mapped[str] = mapped_column(String(512), index=True)

    analysis: Mapped["Analysis"] = relationship(back_populates="finding_correlations")  # noqa: F821


class RootCause(Base):
    __tablename__ = "root_causes"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    identifier: Mapped[str] = mapped_column(String(128), index=True)  # deterministic
    category: Mapped[str] = mapped_column(String(48), index=True)
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    severity_score: Mapped[int] = mapped_column(Integer, default=0)
    confidence_score: Mapped[int] = mapped_column(Integer, default=0)
    affected_components: Mapped[list] = mapped_column(JSON, default=list)
    affected_code_nodes: Mapped[list] = mapped_column(JSON, default=list)
    affected_dependencies: Mapped[list] = mapped_column(JSON, default=list)
    boundaries: Mapped[list] = mapped_column(JSON, default=list)
    paths: Mapped[list] = mapped_column(JSON, default=list)

    analysis: Mapped["Analysis"] = relationship(back_populates="root_causes")  # noqa: F821
    findings: Mapped[list["RootCauseFinding"]] = relationship(
        back_populates="root_cause", cascade="all, delete-orphan"
    )
    evidence: Mapped[list["RootCauseEvidence"]] = relationship(
        back_populates="root_cause", cascade="all, delete-orphan"
    )


class RootCauseFinding(Base):
    __tablename__ = "root_cause_findings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    root_cause_id: Mapped[UUID] = mapped_column(ForeignKey("root_causes.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(64))

    root_cause: Mapped[RootCause] = relationship(back_populates="findings")


class RootCauseEvidence(Base):
    __tablename__ = "root_cause_evidence"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    root_cause_id: Mapped[UUID] = mapped_column(ForeignKey("root_causes.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str] = mapped_column(Text)
    reference: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    root_cause: Mapped[RootCause] = relationship(back_populates="evidence")


class AttackSurfaceNode(Base):
    __tablename__ = "attack_surface_nodes"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    node_key: Mapped[str] = mapped_column(String(1024), index=True)
    node_type: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(512))
    exposure: Mapped[str] = mapped_column(String(24), index=True)  # PUBLIC | PERMISSION_PROTECTED | INTERNAL | UNKNOWN
    component: Mapped[str | None] = mapped_column(String(512), nullable=True)
    permission: Mapped[str | None] = mapped_column(String(512), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    evidence: Mapped[str] = mapped_column(Text, default="")

    analysis: Mapped["Analysis"] = relationship(back_populates="attack_surface_nodes")  # noqa: F821


class AttackSurfaceEdge(Base):
    __tablename__ = "attack_surface_edges"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    src_key: Mapped[str] = mapped_column(String(1024))
    dst_key: Mapped[str] = mapped_column(String(1024))
    edge_type: Mapped[str] = mapped_column(String(32))
    evidence: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")

    analysis: Mapped["Analysis"] = relationship(back_populates="attack_surface_edges")  # noqa: F821


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    scope: Mapped[str] = mapped_column(String(512), default="overall", index=True)  # 'overall' or entry-point key
    overall_score: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    severity_score: Mapped[int] = mapped_column(Integer, default=0)
    confidence_score: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)

    analysis: Mapped["Analysis"] = relationship(back_populates="risk_assessments")  # noqa: F821
    factors: Mapped[list["RiskFactor"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )


class RiskFactor(Base):
    __tablename__ = "risk_factors"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey("risk_assessments.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(64))
    weight: Mapped[int] = mapped_column(Integer)
    direction: Mapped[str] = mapped_column(String(8))  # positive | negative
    category: Mapped[str] = mapped_column(String(32), default="")
    evidence: Mapped[str] = mapped_column(Text, default="")

    assessment: Mapped[RiskAssessment] = relationship(back_populates="factors")


Index("ix_finding_correlations_dim_key", FindingCorrelation.analysis_id, FindingCorrelation.dimension, FindingCorrelation.correlation_key)
Index("ix_attack_surface_nodes_analysis_type", AttackSurfaceNode.analysis_id, AttackSurfaceNode.node_type)

"""Dependency & CVE models.

The vulnerability tables (``vulnerabilities``, ``vulnerability_references``,
``affected_products``, ``affected_version_ranges``) form a provider-neutral,
analysis-independent local CVE database populated by ``cve import``/``cve sync``.
The dependency tables (``dependencies``, ``dependency_evidence``,
``vulnerability_matches``) are per-analysis and reference the shared CVE data.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


# ---------------------------------------------------------------------------
# Global CVE database (not tied to any analysis)
# ---------------------------------------------------------------------------


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    cve_id: Mapped[str] = mapped_column(String(64), index=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    published_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    modified_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(32), default="local", index=True)  # provider
    source_id: Mapped[str | None] = mapped_column(String(128), nullable=True)  # provider_record_id
    retrieved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_test_data: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    # Prompt-16 intelligence expansion (nullable for backward compatibility).
    withdrawn_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    provider_modified_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # External intelligence signals — SEPARATE from AndroidSecForge severity/risk.
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False, index=True)  # CISA KEV
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    bundle_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    references: Mapped[list["VulnerabilityReference"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    products: Mapped[list["AffectedProduct"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    aliases: Mapped[list["VulnerabilityAlias"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    identities: Mapped[list["VulnerabilityIdentity"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    signatures: Mapped[list["VulnerabilitySignature"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    scores: Mapped[list["VulnerabilityScore"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    provider_records: Mapped[list["VulnerabilityProviderRecord"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )


class VulnerabilityReference(Base):
    __tablename__ = "vulnerability_references"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    vulnerability_id: Mapped[UUID] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(1024))
    ref_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="references")


class AffectedProduct(Base):
    __tablename__ = "affected_products"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    vulnerability_id: Mapped[UUID] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(32), index=True)  # maven | native | android | generic
    vendor: Mapped[str | None] = mapped_column(String(256), nullable=True)
    product: Mapped[str] = mapped_column(String(256), index=True)
    cpe: Mapped[str | None] = mapped_column(String(512), nullable=True)
    purl: Mapped[str | None] = mapped_column(String(512), nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    version_strategy: Mapped[str] = mapped_column(String(16), default="GENERIC")

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="products")
    ranges: Mapped[list["AffectedVersionRange"]] = relationship(
        back_populates="product", cascade="all, delete-orphan"
    )


class AffectedVersionRange(Base):
    __tablename__ = "affected_version_ranges"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    product_id: Mapped[UUID] = mapped_column(ForeignKey("affected_products.id", ondelete="CASCADE"), index=True)
    introduced: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fixed: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_affected: Mapped[str | None] = mapped_column(String(64), nullable=True)
    exact: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw: Mapped[str | None] = mapped_column(String(256), nullable=True)

    product: Mapped[AffectedProduct] = relationship(back_populates="ranges")


class VulnerabilityAlias(Base):
    __tablename__ = "vulnerability_aliases"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    vulnerability_id: Mapped[UUID] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    alias: Mapped[str] = mapped_column(String(64), index=True)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="aliases")


class VulnerabilityIdentity(Base):
    """Normalized identity a CVE affects: CPE / PURL / MAVEN / PACKAGE / SONAME."""
    __tablename__ = "vulnerability_identities"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    vulnerability_id: Mapped[UUID] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    identity_type: Mapped[str] = mapped_column(String(16), index=True)  # CPE | PURL | MAVEN | PACKAGE | SONAME | CWE
    value: Mapped[str] = mapped_column(String(512), index=True)
    ecosystem: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="identities")


class VulnerabilitySignature(Base):
    """Provider-supplied code/native vulnerability signature. Never invented — a
    signature exists only when a provider supplied it."""
    __tablename__ = "vulnerability_signatures"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    vulnerability_id: Mapped[UUID] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(24), index=True)  # PACKAGE|CLASS|METHOD|FIELD|NATIVE_SYMBOL|JNI|API_SEQUENCE
    package: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    class_name: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    method: Mapped[str | None] = mapped_column(String(256), nullable=True)
    descriptor: Mapped[str | None] = mapped_column(String(512), nullable=True)
    field: Mapped[str | None] = mapped_column(String(256), nullable=True)
    native_symbol: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    api_sequence: Mapped[list] = mapped_column(JSON, default=list)
    provider: Mapped[str] = mapped_column(String(32), default="unknown")
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="signatures")


class VulnerabilityScore(Base):
    """Multi-metric scoring: CVSS v2/v3/v3.1/v4, EPSS, KEV — stored per provider,
    never merged into AndroidSecForge severity/risk."""
    __tablename__ = "vulnerability_scores"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    vulnerability_id: Mapped[UUID] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # CVSS2|CVSS3|CVSS31|CVSS4|EPSS|KEV
    provider: Mapped[str] = mapped_column(String(32), default="unknown")
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    extra: Mapped[dict] = mapped_column(JSON, default=dict)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="scores")


class VulnerabilityProviderRecord(Base):
    """Provenance of one provider's contribution to a CVE (bounded raw excerpt)."""
    __tablename__ = "vulnerability_provider_records"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    vulnerability_id: Mapped[UUID] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    provider_record_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    modified_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    retrieved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)  # bounded

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="provider_records")


class IntelBundle(Base):
    """Record of an imported/created offline intelligence bundle."""
    __tablename__ = "intel_bundles"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128), index=True)
    bundle_version: Mapped[str] = mapped_column(String(64), default="1")
    checksum: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="COMPLETE")  # COMPLETE | PARTIAL | FAILED
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    identity_count: Mapped[int] = mapped_column(Integer, default=0)
    signature_count: Mapped[int] = mapped_column(Integer, default=0)
    providers: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ---------------------------------------------------------------------------
# Per-analysis dependency inventory + matches
# ---------------------------------------------------------------------------


class Dependency(Base):
    __tablename__ = "dependencies"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(256), index=True)
    product: Mapped[str | None] = mapped_column(String(256), nullable=True)
    package_prefix: Mapped[str | None] = mapped_column(String(256), nullable=True)
    ecosystem: Mapped[str] = mapped_column(String(32), index=True)  # maven | native | android | generic
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version_strategy: Mapped[str] = mapped_column(String(16), default="GENERIC")
    architecture: Mapped[str | None] = mapped_column(String(16), nullable=True)
    artifact: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    kind: Mapped[str] = mapped_column(String(16), default="java")  # java | native
    bundled: Mapped[bool] = mapped_column(Boolean, default=False)
    identity_confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")
    version_confidence: Mapped[str] = mapped_column(String(8), default="UNKNOWN")
    cpe: Mapped[str | None] = mapped_column(String(512), nullable=True)

    analysis: Mapped["Analysis"] = relationship(back_populates="dependencies")  # noqa: F821
    evidences: Mapped[list["DependencyEvidence"]] = relationship(
        back_populates="dependency", cascade="all, delete-orphan"
    )
    matches: Mapped[list["VulnerabilityMatch"]] = relationship(
        back_populates="dependency", cascade="all, delete-orphan"
    )


class DependencyEvidence(Base):
    __tablename__ = "dependency_evidence"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    dependency_id: Mapped[UUID] = mapped_column(ForeignKey("dependencies.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str] = mapped_column(Text)
    location: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    dependency: Mapped[Dependency] = relationship(back_populates="evidences")


class VulnerabilityMatch(Base):
    __tablename__ = "vulnerability_matches"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    dependency_id: Mapped[UUID] = mapped_column(ForeignKey("dependencies.id", ondelete="CASCADE"), index=True)
    vulnerability_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True
    )
    cve_id: Mapped[str] = mapped_column(String(64), index=True)
    match_method: Mapped[str] = mapped_column(String(16), default="EXACT")  # EXACT | HEURISTIC
    match_confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")
    version_state: Mapped[str] = mapped_column(String(24))  # AFFECTED | NOT_AFFECTED | POSSIBLY_AFFECTED | UNKNOWN
    correlation_state: Mapped[str] = mapped_column(String(32), index=True)
    reachability_state: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Prompt-16 (nullable/defaulted for backward compatibility).
    identity_confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")
    signature_state: Mapped[str] = mapped_column(String(24), default="NO_SIGNATURE")  # matched granularity
    earliest_fixed_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fixed_versions: Mapped[list] = mapped_column(JSON, default=list)
    providers: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[list] = mapped_column(JSON, default=list)

    analysis: Mapped["Analysis"] = relationship(back_populates="vulnerability_matches")  # noqa: F821
    dependency: Mapped[Dependency] = relationship(back_populates="matches")
    # One-directional link to the global CVE record (for signatures/scores/explain).
    vulnerability: Mapped["Vulnerability | None"] = relationship(foreign_keys=[vulnerability_id])


Index("ix_affected_products_eco_product", AffectedProduct.ecosystem, AffectedProduct.product)
Index("ix_dependencies_analysis_eco", Dependency.analysis_id, Dependency.ecosystem)
Index("ix_vuln_matches_analysis_state", VulnerabilityMatch.analysis_id, VulnerabilityMatch.correlation_state)
Index("ix_vuln_identities_type_value", VulnerabilityIdentity.identity_type, VulnerabilityIdentity.value)
Index("ix_vuln_signatures_kind", VulnerabilitySignature.kind)
Index("ix_vuln_scores_kind", VulnerabilityScore.kind)

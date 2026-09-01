"""Relational analysis model for the first complete vertical slice.

These tables replace the single-JSON-blob approach for analysis results. The
legacy ``APKArtifact`` table is preserved as the ingested-APK identity and is
referenced by :class:`Analysis`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    apk_id: Mapped[UUID] = mapped_column(ForeignKey("apk_artifacts.id", ondelete="CASCADE"), index=True)
    apk_sha256: Mapped[str] = mapped_column(String(64), index=True)
    profile: Mapped[str] = mapped_column(String(32), default="static")
    status: Mapped[str] = mapped_column(String(16), default="PARTIAL")
    ruleset_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tool_versions: Mapped[dict] = mapped_column(JSON, default=dict)
    capabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    stages: Mapped[list] = mapped_column(JSON, default=list)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    manifest: Mapped["ManifestModel | None"] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", uselist=False
    )
    permissions: Mapped[list["PermissionModel"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    components: Mapped[list["ComponentModel"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    dex_artifacts: Mapped[list["DexArtifact"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    code_entities: Mapped[list["CodeEntity"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    findings: Mapped[list["FindingModel"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    artifacts: Mapped[list["ArtifactRecord"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    native_libraries: Mapped[list["NativeLibrary"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    native_functions: Mapped[list["NativeFunction"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    jni_bindings: Mapped[list["JNIBinding"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    code_nodes: Mapped[list["CodeNode"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    code_edges: Mapped[list["CodeEdge"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    dataflow_sources: Mapped[list["DataflowSource"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    security_sinks: Mapped[list["SecuritySink"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    entry_points: Mapped[list["EntryPointModel"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    reachability_paths: Mapped[list["ReachabilityPath"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    android_entry_points: Mapped[list["AndroidEntryPoint"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    intents: Mapped[list["IntentModel"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    deep_links: Mapped[list["DeepLink"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    ipc_transactions: Mapped[list["IpcTransaction"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    security_boundaries: Mapped[list["SecurityBoundary"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    semantic_edges: Mapped[list["SemanticEdge"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    dependencies: Mapped[list["Dependency"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    vulnerability_matches: Mapped[list["VulnerabilityMatch"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    finding_correlations: Mapped[list["FindingCorrelation"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    root_causes: Mapped[list["RootCause"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    attack_surface_nodes: Mapped[list["AttackSurfaceNode"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    attack_surface_edges: Mapped[list["AttackSurfaceEdge"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    risk_assessments: Mapped[list["RiskAssessment"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    runtime_sessions: Mapped[list["RuntimeSession"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    investigations: Mapped[list["Investigation"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    graph_snapshots: Mapped[list["GraphSnapshot"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    remediation_plans: Mapped[list["RemediationPlan"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    validation_claims: Mapped[list["ValidationClaim"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    obfuscation_observations: Mapped[list["ObfuscationObservation"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    anti_analysis_indicators: Mapped[list["AntiAnalysisIndicator"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    analysis_impacts: Mapped[list["AnalysisImpact"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
    native_analysis_runs: Mapped[list["NativeAnalysisRun"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan")
    native_binaries: Mapped[list["NativeBinary"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan")
    native_deep_functions: Mapped[list["NativeDeepFunction"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan")
    native_deep_symbols: Mapped[list["NativeDeepSymbol"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan")
    native_strings: Mapped[list["NativeString"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan")
    native_call_edges: Mapped[list["NativeCallEdge"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan")
    native_references: Mapped[list["NativeReference"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan")
    native_deep_jni_bindings: Mapped[list["NativeDeepJNIBinding"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan")
    native_api_observations: Mapped[list["NativeApiObservation"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan")
    native_deep_evidence: Mapped[list["NativeDeepEvidence"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan")
    runtime_validation_runs: Mapped[list["RuntimeValidationRun"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan")
    runtime_correlations: Mapped[list["RuntimeCorrelation"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan")
    assessments: Mapped[list["Assessment"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan")


class ArtifactRecord(Base):
    __tablename__ = "artifacts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    path: Mapped[str] = mapped_column(String(1024))
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    analysis: Mapped[Analysis] = relationship(back_populates="artifacts")


class ManifestModel(Base):
    __tablename__ = "manifests"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(32))
    source_format: Mapped[str] = mapped_column(String(16))
    package: Mapped[str | None] = mapped_column(String(512), nullable=True)
    version_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    version_code: Mapped[str | None] = mapped_column(String(256), nullable=True)
    min_sdk: Mapped[str | None] = mapped_column(String(16), nullable=True)
    target_sdk: Mapped[str | None] = mapped_column(String(16), nullable=True)
    compile_sdk: Mapped[str | None] = mapped_column(String(16), nullable=True)
    debuggable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    allow_backup: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    uses_cleartext_traffic: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    network_security_config: Mapped[str | None] = mapped_column(String(512), nullable=True)

    analysis: Mapped[Analysis] = relationship(back_populates="manifest")


class PermissionModel(Base):
    __tablename__ = "permissions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(512))
    protection_level: Mapped[str] = mapped_column(String(32))
    permission_group: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_dangerous: Mapped[bool] = mapped_column(Boolean, default=False)
    is_custom: Mapped[bool] = mapped_column(Boolean, default=False)

    analysis: Mapped[Analysis] = relationship(back_populates="permissions")


class ComponentModel(Base):
    __tablename__ = "components"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    exported: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    explicit_exported: Mapped[bool] = mapped_column(Boolean, default=False)
    effective_exported: Mapped[bool] = mapped_column(Boolean, default=False)
    exposure: Mapped[str] = mapped_column(String(32), default="INTERNAL")
    permission: Mapped[str | None] = mapped_column(String(512), nullable=True)
    authorities: Mapped[str | None] = mapped_column(String(512), nullable=True)
    intent_filters: Mapped[list] = mapped_column(JSON, default=list)

    analysis: Mapped[Analysis] = relationship(back_populates="components")


class DexArtifact(Base):
    __tablename__ = "dex_artifacts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    archive_path: Mapped[str] = mapped_column(String(512))
    filename: Mapped[str] = mapped_column(String(256))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    valid: Mapped[bool] = mapped_column(Boolean, default=False)
    class_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    method_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    field_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    string_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    workspace_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    analysis: Mapped[Analysis] = relationship(back_populates="dex_artifacts")


class CodeEntity(Base):
    __tablename__ = "code_entities"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    entity_type: Mapped[str] = mapped_column(String(16))  # class | method | field
    package: Mapped[str | None] = mapped_column(String(512), nullable=True)
    class_name: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    name: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    superclass: Mapped[str | None] = mapped_column(String(512), nullable=True)
    interfaces: Mapped[list] = mapped_column(JSON, default=list)
    source_file: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    analysis: Mapped[Analysis] = relationship(back_populates="code_entities")


class FindingModel(Base):
    __tablename__ = "findings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(256))
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(32), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list] = mapped_column(JSON, default=list)
    component: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Correlation / risk augmentation (added in migration 0011; nullable for
    # backward compatibility with pre-existing findings).
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    is_duplicate: Mapped[bool] = mapped_column(Boolean, default=False)
    primary_target: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    severity_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    root_cause_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("root_causes.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # Runtime correlation (migration 0012). NOT_OBSERVED != SAFE.
    runtime_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    runtime_evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    validation_state: Mapped[str] = mapped_column(String(16), default="NOT_RUN")  # runtime validation axis
    # Security-validation axis (migration 0017; distinct from the runtime
    # validation_state above; additive — existing values remain intact).
    security_validation_state: Mapped[str] = mapped_column(String(28), default="UNVERIFIED")
    validation_confidence: Mapped[int] = mapped_column(Integer, default=0)
    validation_claim_count: Mapped[int] = mapped_column(Integer, default=0)
    validation_evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    validation_blocker_count: Mapped[int] = mapped_column(Integer, default=0)
    validation_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Live runtime-validation axis (migration 0020; additive; distinct from the
    # prompt-12 runtime_status/validation_state and the prompt-17 security axis).
    # NOT_OBSERVED never means safe.
    runtime_validation_state: Mapped[str] = mapped_column(String(32), default="LIVE_UNAVAILABLE")

    evidence: Mapped[list["EvidenceModel"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    analysis: Mapped[Analysis] = relationship(back_populates="findings")


class EvidenceModel(Base):
    __tablename__ = "evidence"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(32))
    location: Mapped[str] = mapped_column(String(1024))
    detail: Mapped[str] = mapped_column(Text)
    artifact: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    class_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    method_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)

    finding: Mapped[FindingModel] = relationship(back_populates="evidence")


class NativeLibrary(Base):
    __tablename__ = "native_libraries"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    archive_path: Mapped[str] = mapped_column(String(512))
    abi: Mapped[str] = mapped_column(String(32), index=True)
    filename: Mapped[str] = mapped_column(String(256))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    elf_class: Mapped[str | None] = mapped_column(String(8), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(16), nullable=True)
    endianness: Mapped[str | None] = mapped_column(String(8), nullable=True)
    elf_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    entry_point: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    soname: Mapped[str | None] = mapped_column(String(256), nullable=True)
    stripped: Mapped[bool] = mapped_column(Boolean, default=False)
    symbols_available: Mapped[bool] = mapped_column(Boolean, default=False)
    functions_truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default="COMPLETE")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    workspace_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    analysis: Mapped[Analysis] = relationship(back_populates="native_libraries")
    functions: Mapped[list["NativeFunction"]] = relationship(
        back_populates="library", cascade="all, delete-orphan"
    )
    dependencies: Mapped[list["NativeDependency"]] = relationship(
        back_populates="library", cascade="all, delete-orphan"
    )


class NativeFunction(Base):
    __tablename__ = "native_functions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    library_id: Mapped[UUID] = mapped_column(ForeignKey("native_libraries.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(512), index=True)
    address: Mapped[int] = mapped_column(BigInteger, default=0)
    symbol_type: Mapped[str] = mapped_column(String(16), default="NOTYPE")
    binding: Mapped[str] = mapped_column(String(16), default="GLOBAL")
    visibility: Mapped[str] = mapped_column(String(16), default="DEFAULT")
    size: Mapped[int] = mapped_column(Integer, default=0)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # exported | imported | local
    is_jni: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(16), default="ELF")
    confidence: Mapped[str] = mapped_column(String(16), default="HIGH")

    analysis: Mapped[Analysis] = relationship(back_populates="native_functions")
    library: Mapped[NativeLibrary] = relationship(back_populates="functions")


class NativeDependency(Base):
    __tablename__ = "native_dependencies"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    library_id: Mapped[UUID] = mapped_column(ForeignKey("native_libraries.id", ondelete="CASCADE"), index=True)
    needed: Mapped[str] = mapped_column(String(256))

    library: Mapped[NativeLibrary] = relationship(back_populates="dependencies")


class JNIBinding(Base):
    __tablename__ = "jni_bindings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(16))  # ELF_EXPORT | JAVA_NATIVE | JNI_ONLOAD | LOAD_LIBRARY
    confidence: Mapped[str] = mapped_column(String(8))
    java_class: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    java_method: Mapped[str | None] = mapped_column(String(256), nullable=True)
    java_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    library_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("native_libraries.id", ondelete="SET NULL"), nullable=True
    )
    library_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    native_function_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("native_functions.id", ondelete="SET NULL"), nullable=True
    )
    native_function: Mapped[str | None] = mapped_column(String(512), nullable=True)
    evidence: Mapped[str] = mapped_column(Text, default="")

    analysis: Mapped[Analysis] = relationship(back_populates="jni_bindings")


class CodeNode(Base):
    __tablename__ = "code_nodes"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    node_key: Mapped[str] = mapped_column(String(1024), index=True)
    node_type: Mapped[str] = mapped_column(String(24), index=True)
    label: Mapped[str] = mapped_column(String(512))
    class_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    method_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    source_file: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")

    analysis: Mapped[Analysis] = relationship(back_populates="code_nodes")


class CodeEdge(Base):
    __tablename__ = "code_edges"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    src_key: Mapped[str] = mapped_column(String(1024), index=True)
    dst_key: Mapped[str] = mapped_column(String(1024), index=True)
    edge_type: Mapped[str] = mapped_column(String(24), index=True)
    evidence: Mapped[str] = mapped_column(Text, default="")
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")

    analysis: Mapped[Analysis] = relationship(back_populates="code_edges")


class DataflowSource(Base):
    __tablename__ = "dataflow_sources"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    node_key: Mapped[str] = mapped_column(String(1024))
    source_type: Mapped[str] = mapped_column(String(32))
    api: Mapped[str] = mapped_column(String(128))
    class_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    method_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")
    evidence: Mapped[str] = mapped_column(Text, default="")

    analysis: Mapped[Analysis] = relationship(back_populates="dataflow_sources")


class SecuritySink(Base):
    __tablename__ = "security_sinks"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    node_key: Mapped[str] = mapped_column(String(1024))
    sink_type: Mapped[str] = mapped_column(String(32))
    api: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(16), default="java")  # java | native
    class_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    method_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")
    evidence: Mapped[str] = mapped_column(Text, default="")

    analysis: Mapped[Analysis] = relationship(back_populates="security_sinks")


class EntryPointModel(Base):
    __tablename__ = "entry_points"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    node_key: Mapped[str] = mapped_column(String(1024))
    component: Mapped[str] = mapped_column(String(512))
    kind: Mapped[str] = mapped_column(String(32))
    exported: Mapped[bool] = mapped_column(Boolean, default=True)
    permission: Mapped[str | None] = mapped_column(String(512), nullable=True)
    intent_filters: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[str] = mapped_column(Text, default="")

    analysis: Mapped[Analysis] = relationship(back_populates="entry_points")


class ReachabilityPath(Base):
    __tablename__ = "reachability_paths"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    from_key: Mapped[str] = mapped_column(String(1024))
    from_label: Mapped[str] = mapped_column(String(512))
    to_key: Mapped[str] = mapped_column(String(1024))
    to_label: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(8))
    length: Mapped[int] = mapped_column(Integer, default=0)
    nodes: Mapped[list] = mapped_column(JSON, default=list)
    edges: Mapped[list] = mapped_column(JSON, default=list)

    analysis: Mapped[Analysis] = relationship(back_populates="reachability_paths")


class AndroidEntryPoint(Base):
    __tablename__ = "android_entry_points"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    node_key: Mapped[str] = mapped_column(String(1024))
    component: Mapped[str] = mapped_column(String(512), index=True)
    component_type: Mapped[str] = mapped_column(String(32))
    method: Mapped[str] = mapped_column(String(128))
    lifecycle_event: Mapped[str] = mapped_column(String(32))
    exported: Mapped[bool] = mapped_column(Boolean, default=False)
    permission: Mapped[str | None] = mapped_column(String(512), nullable=True)
    intent_filters: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[str] = mapped_column(String(8), default="HIGH")

    analysis: Mapped[Analysis] = relationship(back_populates="android_entry_points")


class IntentModel(Base):
    __tablename__ = "intents"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    operation: Mapped[str] = mapped_column(String(32))
    action: Mapped[str | None] = mapped_column(String(256), nullable=True)
    data_uri: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    categories: Mapped[list] = mapped_column(JSON, default=list)
    target_component: Mapped[str | None] = mapped_column(String(512), nullable=True)
    target_package: Mapped[str | None] = mapped_column(String(512), nullable=True)
    class_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    method_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")
    evidence: Mapped[str] = mapped_column(Text, default="")

    analysis: Mapped[Analysis] = relationship(back_populates="intents")


class DeepLink(Base):
    __tablename__ = "deep_links"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    node_key: Mapped[str] = mapped_column(String(1024))
    component: Mapped[str] = mapped_column(String(512))
    scheme: Mapped[str | None] = mapped_column(String(128), nullable=True)
    host: Mapped[str | None] = mapped_column(String(256), nullable=True)
    port: Mapped[str | None] = mapped_column(String(16), nullable=True)
    path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    path_prefix: Mapped[str | None] = mapped_column(String(512), nullable=True)
    path_pattern: Mapped[str | None] = mapped_column(String(512), nullable=True)
    mime_type: Mapped[str | None] = mapped_column(String(256), nullable=True)
    action: Mapped[str | None] = mapped_column(String(256), nullable=True)
    category: Mapped[str | None] = mapped_column(String(256), nullable=True)
    evidence: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[str] = mapped_column(String(8), default="HIGH")

    analysis: Mapped[Analysis] = relationship(back_populates="deep_links")


class IpcTransaction(Base):
    __tablename__ = "ipc_transactions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(24))  # SERVICE_ENTRY | CLIENT_INVOKE | AIDL_INTERFACE
    class_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    method_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    interface_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    transaction_code: Mapped[str | None] = mapped_column(String(256), nullable=True)
    confidence: Mapped[str] = mapped_column(String(8), default="LOW")
    evidence: Mapped[str] = mapped_column(Text, default="")

    analysis: Mapped[Analysis] = relationship(back_populates="ipc_transactions")


class SecurityBoundary(Base):
    __tablename__ = "security_boundaries"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    boundary_type: Mapped[str] = mapped_column(String(32), index=True)
    component: Mapped[str | None] = mapped_column(String(512), nullable=True)
    node_key: Mapped[str] = mapped_column(String(1024))
    evidence: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")

    analysis: Mapped[Analysis] = relationship(back_populates="security_boundaries")


class SemanticEdge(Base):
    __tablename__ = "semantic_edges"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    src_key: Mapped[str] = mapped_column(String(1024))
    dst_key: Mapped[str] = mapped_column(String(1024))
    edge_type: Mapped[str] = mapped_column(String(32), index=True)
    evidence: Mapped[str] = mapped_column(Text, default="")
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")

    analysis: Mapped[Analysis] = relationship(back_populates="semantic_edges")


Index("ix_findings_severity_status", FindingModel.severity, FindingModel.status)
Index("ix_code_entities_class_name_name", CodeEntity.class_name, CodeEntity.name)
Index("ix_native_functions_lib_kind", NativeFunction.library_id, NativeFunction.kind)
Index("ix_code_edges_analysis_src", CodeEdge.analysis_id, CodeEdge.src_key)
Index("ix_code_nodes_analysis_type", CodeNode.analysis_id, CodeNode.node_type)

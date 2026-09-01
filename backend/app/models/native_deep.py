"""Deep native / Ghidra-correlation models (prompt 20).

Persisted native evidence that supplements — never replaces — existing ELF/JNI
evidence. Ghidra output is imported as evidence and reconciled with ELF
observations by stable, content-derived identity (binary hash + architecture +
normalized name + entry address), never by DB ids or Ghidra temporary ids.

A native function being present never implies it is reachable from Java; a JNI
export never implies the Java side invokes it; a dangerous native API never
implies vulnerability. No `exploitable` state exists. UNKNOWN / UNKNOWN_NATIVE_TARGET
are preserved.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, BigInteger, DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Analysis modes.
MODE_GHIDRA = "GHIDRA_AVAILABLE"
MODE_FIXTURE = "FIXTURE"
MODE_ELF_ONLY = "ELF_ONLY"

# Function categories (no security impact implied).
FT_JNI_EXPORT = "JNI_EXPORT"
FT_JNI_INTERNAL = "JNI_INTERNAL"
FT_EXPORTED_NATIVE = "EXPORTED_NATIVE"
FT_IMPORTED = "IMPORTED"
FT_LIBRARY_INTERNAL = "LIBRARY_INTERNAL"
FT_UNKNOWN = "UNKNOWN"


class NativeAnalysisRun(Base):
    __tablename__ = "native_analysis_runs"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    mode: Mapped[str] = mapped_column(String(24), default=MODE_ELF_ONLY, index=True)
    ghidra_capability: Mapped[str] = mapped_column(String(16), default="UNAVAILABLE")
    ghidra_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    binaries_count: Mapped[int] = mapped_column(Integer, default=0)
    functions_count: Mapped[int] = mapped_column(Integer, default=0)
    jni_count: Mapped[int] = mapped_column(Integer, default=0)
    call_edge_count: Mapped[int] = mapped_column(Integer, default=0)
    api_observation_count: Mapped[int] = mapped_column(Integer, default=0)
    unresolved_target_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    analysis: Mapped["Analysis"] = relationship(back_populates="native_analysis_runs")  # noqa: F821


class NativeBinary(Base):
    __tablename__ = "native_binaries"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)  # sha256(sha256|arch)
    filename: Mapped[str] = mapped_column(String(256))
    abi: Mapped[str | None] = mapped_column(String(32), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    soname: Mapped[str | None] = mapped_column(String(256), nullable=True)
    stripped: Mapped[bool] = mapped_column(Boolean, default=False)
    symbols_available: Mapped[bool] = mapped_column(Boolean, default=False)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source: Mapped[str] = mapped_column(String(24), default="ELF")  # ELF | GHIDRA | ELF+GHIDRA
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)

    analysis: Mapped["Analysis"] = relationship(back_populates="native_binaries")  # noqa: F821


class NativeDeepFunction(Base):
    __tablename__ = "native_deep_functions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    binary_fp: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)  # binary_fp|normalized_name|entry
    name: Mapped[str] = mapped_column(String(512))
    normalized_name: Mapped[str] = mapped_column(String(512), index=True)
    entry_address: Mapped[str | None] = mapped_column(String(32), nullable=True)
    size: Mapped[int] = mapped_column(Integer, default=0)
    function_type: Mapped[str] = mapped_column(String(24), default=FT_UNKNOWN, index=True)
    symbol_type: Mapped[str | None] = mapped_column(String(24), nullable=True)
    is_exported: Mapped[bool] = mapped_column(Boolean, default=False)
    is_imported: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")
    source: Mapped[str] = mapped_column(String(24), default="ELF", index=True)  # ELF | GHIDRA | ELF+GHIDRA
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)

    analysis: Mapped["Analysis"] = relationship(back_populates="native_deep_functions")  # noqa: F821


class NativeDeepSymbol(Base):
    __tablename__ = "native_deep_symbols"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    binary_fp: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(512))
    symbol_type: Mapped[str | None] = mapped_column(String(24), nullable=True)
    address: Mapped[str | None] = mapped_column(String(32), nullable=True)
    kind: Mapped[str] = mapped_column(String(16), default="local")  # import | export | local
    source: Mapped[str] = mapped_column(String(24), default="ELF")

    analysis: Mapped["Analysis"] = relationship(back_populates="native_deep_symbols")  # noqa: F821


class NativeString(Base):
    __tablename__ = "native_strings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    binary_fp: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    value: Mapped[str] = mapped_column(String(1024))
    address: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str] = mapped_column(String(24), default="GHIDRA")

    analysis: Mapped["Analysis"] = relationship(back_populates="native_strings")  # noqa: F821


class NativeCallEdge(Base):
    __tablename__ = "native_call_edges"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    binary_fp: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    src_fp: Mapped[str] = mapped_column(String(64), index=True)
    src_name: Mapped[str] = mapped_column(String(512))
    dst_fp: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_name: Mapped[str] = mapped_column(String(512))
    edge_type: Mapped[str] = mapped_column(String(24), default="GHIDRA_CALLS")
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")
    source: Mapped[str] = mapped_column(String(24), default="GHIDRA")

    analysis: Mapped["Analysis"] = relationship(back_populates="native_call_edges")  # noqa: F821


class NativeReference(Base):
    __tablename__ = "native_references"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    binary_fp: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    from_fp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    to_address: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ref_type: Mapped[str] = mapped_column(String(24), default="DATA")
    source: Mapped[str] = mapped_column(String(24), default="GHIDRA")

    analysis: Mapped["Analysis"] = relationship(back_populates="native_references")  # noqa: F821


class NativeDeepJNIBinding(Base):
    __tablename__ = "native_deep_jni_bindings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    java_class: Mapped[str | None] = mapped_column(String(512), nullable=True)
    java_method: Mapped[str | None] = mapped_column(String(256), nullable=True)
    java_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    native_symbol: Mapped[str | None] = mapped_column(String(512), nullable=True)
    native_function_fp: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    binary_fp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    registration_type: Mapped[str] = mapped_column(String(24), default="STATIC_NAMING")  # STATIC_NAMING|DYNAMIC_REGISTER|UNRESOLVED
    state: Mapped[str] = mapped_column(String(16), default="UNKNOWN", index=True)  # RESOLVED | UNKNOWN
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")
    source: Mapped[str] = mapped_column(String(24), default="JNI")
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)

    analysis: Mapped["Analysis"] = relationship(back_populates="native_deep_jni_bindings")  # noqa: F821


class NativeApiObservation(Base):
    __tablename__ = "native_api_observations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    binary_fp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    function_fp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    api: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(32), default="NATIVE_API_PRESENT", index=True)
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")
    source: Mapped[str] = mapped_column(String(24), default="ELF")
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)

    analysis: Mapped["Analysis"] = relationship(back_populates="native_api_observations")  # noqa: F821


class NativeDeepEvidence(Base):
    __tablename__ = "native_deep_evidence"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    subject_fp: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    source_type: Mapped[str] = mapped_column(String(16), index=True)  # ELF | GHIDRA | JNI
    artifact: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    file: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    function: Mapped[str | None] = mapped_column(String(512), nullable=True)
    address: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    analysis: Mapped["Analysis"] = relationship(back_populates="native_deep_evidence")  # noqa: F821


Index("ix_native_deep_functions_analysis_type", NativeDeepFunction.analysis_id, NativeDeepFunction.function_type)
Index("ix_native_call_edges_analysis_src", NativeCallEdge.analysis_id, NativeCallEdge.src_fp)
Index("ix_native_api_observations_analysis_state", NativeApiObservation.analysis_id, NativeApiObservation.state)

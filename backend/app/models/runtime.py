"""Runtime Lab models (ADB / Frida / observations / audit).

Runtime evidence is a separate source from static evidence and never overwrites
it. Every runtime operation is auditable; every observation carries provenance
(session, device, timestamp, source, confidence).
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class RuntimeDevice(Base):
    __tablename__ = "runtime_devices"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    serial: Mapped[str] = mapped_column(String(128), index=True)
    state: Mapped[str] = mapped_column(String(24))  # device | offline | unauthorized
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    manufacturer: Mapped[str | None] = mapped_column(String(128), nullable=True)
    android_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sdk_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(32), nullable=True)
    abi: Mapped[str | None] = mapped_column(String(32), nullable=True)
    rooted: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_emulator: Mapped[bool] = mapped_column(Boolean, default=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class RuntimeSession(Base):
    __tablename__ = "runtime_sessions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    analysis_id: Mapped[UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[UUID | None] = mapped_column(ForeignKey("runtime_devices.id", ondelete="SET NULL"), nullable=True)
    device_serial: Mapped[str | None] = mapped_column(String(128), nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    apk_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    session_state: Mapped[str] = mapped_column(String(24), default="CREATED", index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    requested_by: Mapped[str] = mapped_column(String(128), default="cli")
    instrumentation_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    launch_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    install_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    uninstall_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    workspace_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    analysis: Mapped["Analysis"] = relationship(back_populates="runtime_sessions")  # noqa: F821
    observations: Mapped[list["RuntimeObservation"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    events: Mapped[list["RuntimeEvent"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    processes: Mapped[list["RuntimeProcess"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    artifacts: Mapped[list["RuntimeArtifact"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    audit_events: Mapped[list["RuntimeAuditEvent"]] = relationship(back_populates="session", cascade="all, delete-orphan")


class RuntimeObservation(Base):
    __tablename__ = "runtime_observations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    session_id: Mapped[UUID] = mapped_column(ForeignKey("runtime_sessions.id", ondelete="CASCADE"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    observation_type: Mapped[str] = mapped_column(String(24), index=True)
    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    class_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    method_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    native_library: Mapped[str | None] = mapped_column(String(256), nullable=True)
    symbol: Mapped[str | None] = mapped_column(String(512), nullable=True)
    arguments_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    return_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    stack_trace_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(24), default="FRIDA")
    confidence: Mapped[str] = mapped_column(String(8), default="MEDIUM")
    # Higher-level runtime observation taxonomy (migration 0020; additive).
    taxonomy: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    redacted: Mapped[bool] = mapped_column(Boolean, default=False)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    session: Mapped[RuntimeSession] = relationship(back_populates="observations")


class RuntimeEvent(Base):
    __tablename__ = "runtime_events"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    session_id: Mapped[UUID] = mapped_column(ForeignKey("runtime_sessions.id", ondelete="CASCADE"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    event_type: Mapped[str] = mapped_column(String(24), index=True)  # LOGCAT | PROCESS | ...
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tag: Mapped[str | None] = mapped_column(String(256), nullable=True)
    priority: Mapped[str | None] = mapped_column(String(8), nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    message: Mapped[str] = mapped_column(Text, default="")

    session: Mapped[RuntimeSession] = relationship(back_populates="events")


class RuntimeProcess(Base):
    __tablename__ = "runtime_processes"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    session_id: Mapped[UUID] = mapped_column(ForeignKey("runtime_sessions.id", ondelete="CASCADE"), index=True)
    pid: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(512))
    uid: Mapped[str | None] = mapped_column(String(32), nullable=True)
    abi: Mapped[str | None] = mapped_column(String(32), nullable=True)
    start_info: Mapped[str | None] = mapped_column(String(256), nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    session: Mapped[RuntimeSession] = relationship(back_populates="processes")


class RuntimeArtifact(Base):
    __tablename__ = "runtime_artifacts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    session_id: Mapped[UUID] = mapped_column(ForeignKey("runtime_sessions.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    path: Mapped[str] = mapped_column(String(1024))
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    session: Mapped[RuntimeSession] = relationship(back_populates="artifacts")


class RuntimeHookProfile(Base):
    __tablename__ = "runtime_hook_profiles"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(48), index=True)
    category: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text, default="")
    targets: Mapped[list] = mapped_column(JSON, default=list)
    observation_only: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class RuntimeAuditEvent(Base):
    __tablename__ = "runtime_audit_events"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    session_id: Mapped[UUID | None] = mapped_column(ForeignKey("runtime_sessions.id", ondelete="CASCADE"), nullable=True, index=True)
    analysis_id: Mapped[UUID | None] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=True, index=True)
    operation: Mapped[str] = mapped_column(String(24), index=True)
    device_serial: Mapped[str | None] = mapped_column(String(128), nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    requested_by: Mapped[str] = mapped_column(String(128), default="cli")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    result: Mapped[str] = mapped_column(String(16))
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)

    session: Mapped[RuntimeSession] = relationship(back_populates="audit_events")


Index("ix_runtime_observations_session_type", RuntimeObservation.session_id, RuntimeObservation.observation_type)
Index("ix_runtime_events_session_type", RuntimeEvent.session_id, RuntimeEvent.event_type)

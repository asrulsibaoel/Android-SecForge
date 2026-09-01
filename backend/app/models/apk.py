from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class APKArtifact(Base):
    __tablename__ = "apk_artifacts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    original_filename: Mapped[str] = mapped_column(String(512))
    artifact_type: Mapped[str] = mapped_column(String(8), default="apk")
    storage_path: Mapped[str] = mapped_column(String(1024), unique=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    sha1: Mapped[str] = mapped_column(String(40))
    md5: Mapped[str] = mapped_column(String(32))
    size_bytes: Mapped[int] = mapped_column(Integer)
    package_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    version_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    version_code: Mapped[str | None] = mapped_column(String(256), nullable=True)
    manifest_status: Mapped[str] = mapped_column(String(32), default="unavailable")
    status: Mapped[str] = mapped_column(String(32), default="READY")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    structure: Mapped[dict] = mapped_column(JSON, default=dict)
    manifest: Mapped[dict] = mapped_column(JSON, default=dict)
    findings: Mapped[list] = mapped_column(JSON, default=list)
    framework: Mapped[dict] = mapped_column(JSON, default=dict)
    ipc: Mapped[dict] = mapped_column(JSON, default=dict)
    dex: Mapped[list] = mapped_column(JSON, default=list)
    workspace_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
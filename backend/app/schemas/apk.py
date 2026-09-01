from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class APKArtifactResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    original_filename: str
    artifact_type: str
    sha256: str
    sha1: str
    md5: str
    size_bytes: int
    package_name: str | None
    version_name: str | None
    version_code: str | None
    manifest_status: str
    status: str
    created_at: datetime
    structure: dict
    manifest: dict
    findings: list
    framework: dict
    ipc: dict
    dex: list
    workspace_path: str | None
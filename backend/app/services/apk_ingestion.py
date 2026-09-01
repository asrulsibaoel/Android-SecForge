import hashlib
import shutil
import tempfile
import zipfile
from pathlib import Path
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.apk import APKArtifact
from app.services.inspection import inspect_artifact
from app.services.dex import analyze_dex


class APKIngestionError(ValueError):
    pass


def _hashes(path: Path) -> tuple[str, str, str, int]:
    digests = [hashlib.sha256(), hashlib.sha1(), hashlib.md5()]
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            for digest in digests:
                digest.update(chunk)
    return digests[0].hexdigest(), digests[1].hexdigest(), digests[2].hexdigest(), size


def ingest_apk(source: Path, db: Session) -> APKArtifact:
    if not source.is_file():
        raise APKIngestionError(f"Android artifact does not exist: {source}")
    artifact_type = source.suffix.lower().lstrip(".")
    if artifact_type not in {"apk", "aab", "apks", "apkm"}:
        raise APKIngestionError("Input must have an .apk, .aab, .apks, or .apkm extension")
    if not zipfile.is_zipfile(source):
        raise APKIngestionError("Android artifact is not a valid ZIP archive")

    sha256, sha1, md5, size = _hashes(source)
    existing = db.scalar(select(APKArtifact).where(APKArtifact.sha256 == sha256))
    if existing:
        inspect_apk = Path(existing.storage_path)
        if inspect_apk.exists():
            inspect_artifact(inspect_apk, existing)
            analyze_dex(inspect_apk, existing)
            db.commit()
            db.refresh(existing)
        return existing

    storage_root = Path(settings.artifact_storage_path)
    storage_root.mkdir(parents=True, exist_ok=True)
    stored_path = storage_root / f"{sha256}.{artifact_type}"
    if not stored_path.exists():
        with tempfile.NamedTemporaryFile(dir=storage_root, suffix=".part", delete=False) as temp:
            temp_path = Path(temp.name)
        try:
            shutil.copyfile(source, temp_path)
            temp_path.replace(stored_path)
        finally:
            temp_path.unlink(missing_ok=True)

    with zipfile.ZipFile(source) as archive:
        names = set(archive.namelist())
    artifact = APKArtifact(
        original_filename=source.name,
        artifact_type=artifact_type,
        storage_path=str(stored_path),
        sha256=sha256,
        sha1=sha1,
        md5=md5,
        size_bytes=size,
        manifest_status="present" if "AndroidManifest.xml" in names else "unavailable",
        status="READY",
    )
    db.add(artifact)
    db.commit()
    db.refresh(artifact)
    inspect_artifact(source, artifact)
    analyze_dex(source, artifact)
    db.commit()
    db.refresh(artifact)
    return artifact


def get_artifact(artifact_id: UUID, db: Session) -> APKArtifact | None:
    return db.get(APKArtifact, artifact_id)


def get_artifact_by_filename(filename: str, db: Session) -> APKArtifact | None:
    return db.scalar(
        select(APKArtifact)
        .where(APKArtifact.original_filename == filename)
        .order_by(APKArtifact.created_at.desc())
    )
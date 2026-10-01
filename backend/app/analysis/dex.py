"""DEX extraction and header parsing.

Extracts every ``classes*.dex`` from an APK into a hash-derived workspace and
records structural counts from the DEX header. The original APK is copied, never
modified.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from app.core.config import settings

_WORKSPACE_SUBDIRS = ("extracted", "dex", "smali", "java", "native", "reports", "evidence")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def parse_dex_header(data: bytes) -> dict:
    result = {
        "magic": data[:8].decode("ascii", errors="replace"),
        "valid": data[:4] == b"dex\n" and data[7:8] == b"\0",
        "size": len(data),
        "checksum": data[8:12].hex() if len(data) >= 12 else None,
        "sha256": hashlib.sha256(data).hexdigest(),
        "class_count": None,
        "method_count": None,
        "field_count": None,
        "string_count": None,
    }
    if not result["valid"] or len(data) < 112:
        return result
    result.update(
        {
            "declared_size": _u32(data, 32),
            "header_size": _u32(data, 36),
            "string_count": _u32(data, 56),
            "field_count": _u32(data, 80),
            "method_count": _u32(data, 88),
            "class_count": _u32(data, 96),
        }
    )
    return result


def workspace_root(sha256: str) -> Path:
    return Path(settings.workspace_path) / sha256


def prepare_workspace(sha256: str, apk_path: Path, artifact_type: str = "apk") -> Path:
    root = workspace_root(sha256)
    for directory in (root, *(root / name for name in _WORKSPACE_SUBDIRS)):
        directory.mkdir(parents=True, exist_ok=True)
    original = root / f"original.{artifact_type}"
    if not original.exists() or original.stat().st_size != apk_path.stat().st_size:
        original.write_bytes(apk_path.read_bytes())
    return root


def extract_dex(apk_path: Path, sha256: str, artifact_type: str = "apk") -> tuple[Path, list[dict]]:
    """Extract valid DEX files to the workspace and return their records."""
    root = prepare_workspace(sha256, apk_path, artifact_type)
    records: list[dict] = []
    with zipfile.ZipFile(apk_path) as archive:
        for name in archive.namelist():
            basename = Path(name).name
            if not basename.startswith("classes") or not basename.endswith(".dex"):
                continue
            data = archive.read(name)
            record = {"archive_path": name, "filename": basename, **parse_dex_header(data)}
            if record["valid"]:
                output = root / "dex" / basename
                output.write_bytes(data)
                record["workspace_path"] = str(output)
            records.append(record)
    records.sort(key=lambda item: item["archive_path"])
    return root, records

import shutil
import subprocess
from pathlib import Path

from app.analysis.dex import extract_dex, parse_dex_header
from app.models.apk import APKArtifact

# Re-exported for backward compatibility with existing imports/tests.
parse_dex = parse_dex_header


def _jadx() -> dict:
    path = shutil.which("jadx")
    if path is None:
        return {"name": "jadx", "status": "unavailable", "version": None}
    try:
        result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10, check=False)
        version = (result.stdout or result.stderr).strip() or "unknown"
        return {"name": "jadx", "status": "available", "version": version}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"name": "jadx", "status": "error", "version": None, "error": str(error)}


def analyze_dex(source: Path, artifact: APKArtifact) -> APKArtifact:
    root, records = extract_dex(source, artifact.sha256, artifact.artifact_type)
    artifact.dex = records
    artifact.workspace_path = str(root)
    artifact.structure["dex"] = [record["archive_path"] for record in records]
    artifact.structure["jadx"] = _jadx()
    return artifact

"""Optional Ghidra headless integration for native libraries.

Ghidra is never required: ELF parsing works without it. When present, each
library is imported into an isolated, throwaway project and analyzed via
``analyzeHeadless`` with a post-script that emits normalized function records as
JSON. Invocation uses an argument array (never ``shell=True``), a timeout, and
captured stdout/stderr/exit-code. Ghidra is never installed silently.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings

AVAILABLE = "AVAILABLE"
UNAVAILABLE = "UNAVAILABLE"
SUCCESS = "SUCCESS"
FAILED = "FAILED"
TIMEOUT = "TIMEOUT"

_POST_SCRIPT = Path(__file__).resolve().parent / "ghidra_scripts" / "ExportFunctions.py"


@dataclass
class GhidraFunction:
    name: str
    address: str
    size: int
    namespace: str
    source: str = "Ghidra"
    confidence: str = "MEDIUM"


@dataclass
class GhidraResult:
    status: str
    version: str | None = None
    executable: str | None = None
    duration_seconds: float = 0.0
    exit_code: int | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    error: str | None = None
    functions: list[GhidraFunction] = field(default_factory=list)


def analyze_headless_executable() -> str | None:
    """Locate Ghidra's analyzeHeadless launcher."""
    if settings.ghidra_path:
        candidate = Path(settings.ghidra_path)
        if candidate.is_file():
            return str(candidate)
        headless = candidate / "support" / "analyzeHeadless"
        if headless.is_file():
            return str(headless)
    for env in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        value = os.environ.get(env)
        if value:
            headless = Path(value) / "support" / "analyzeHeadless"
            if headless.is_file():
                return str(headless)
    return shutil.which("analyzeHeadless")


def is_available() -> bool:
    return analyze_headless_executable() is not None


def _tail(text: str | None, limit: int = 2000) -> str:
    return (text or "")[-limit:]


def analyze_library(so_path: Path, project_dir: Path, timeout: int | None = None) -> GhidraResult:
    executable = analyze_headless_executable()
    if executable is None:
        return GhidraResult(status=UNAVAILABLE, error="Ghidra analyzeHeadless not found")

    timeout = timeout or int(getattr(settings, "ghidra_timeout_seconds", 900))
    project_dir.mkdir(parents=True, exist_ok=True)
    output_json = project_dir / f"{so_path.name}.functions.json"
    arguments = [
        executable,
        str(project_dir),
        "asf_tmp_project",
        "-import",
        str(so_path),
        "-scriptPath",
        str(_POST_SCRIPT.parent),
        "-postScript",
        _POST_SCRIPT.name,
        str(output_json),
        "-deleteProject",
        "-analysisTimeoutPerFile",
        str(timeout),
    ]
    started = time.monotonic()
    try:
        completed = subprocess.run(
            arguments, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as error:
        return GhidraResult(status=TIMEOUT, executable=executable, error=str(error),
                            duration_seconds=round(time.monotonic() - started, 3))
    except OSError as error:
        return GhidraResult(status=FAILED, executable=executable, error=str(error))

    duration = round(time.monotonic() - started, 3)
    functions = _load_functions(output_json)
    status = SUCCESS if (completed.returncode == 0 and output_json.exists()) else FAILED
    return GhidraResult(
        status=status,
        executable=executable,
        version=_version(executable),
        duration_seconds=duration,
        exit_code=completed.returncode,
        stdout_tail=_tail(completed.stdout),
        stderr_tail=_tail(completed.stderr),
        error=None if status == SUCCESS else "Ghidra produced no function output",
        functions=functions,
    )


def _load_functions(output_json: Path) -> list[GhidraFunction]:
    if not output_json.exists():
        return []
    try:
        raw = json.loads(output_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    functions = []
    for entry in raw.get("functions", []):
        functions.append(
            GhidraFunction(
                name=str(entry.get("name", "")),
                address=str(entry.get("address", "")),
                size=int(entry.get("size", 0) or 0),
                namespace=str(entry.get("namespace", "")),
            )
        )
    return functions


def _version(executable: str) -> str | None:
    # analyzeHeadless has no simple --version; read application.properties near it.
    try:
        base = Path(executable).resolve().parent.parent
        props = base / "Ghidra" / "application.properties"
        if props.is_file():
            for line in props.read_text(encoding="utf-8").splitlines():
                if line.startswith("application.version="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        return None
    return None

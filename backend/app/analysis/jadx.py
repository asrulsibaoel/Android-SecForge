"""Real JADX decompiler integration with honest capability states.

JADX is optional. When it is not installed the adapter reports ``UNAVAILABLE``
and the pipeline degrades gracefully — it never fabricates decompiled output.
When present, JADX is invoked as a subprocess with an argument array (never
``shell=True``), a timeout, and an isolated output directory.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings

SUCCESS = "SUCCESS"
TIMEOUT = "TIMEOUT"
FAILED = "FAILED"
UNAVAILABLE = "UNAVAILABLE"


@dataclass
class JadxResult:
    status: str
    version: str | None = None
    output_dir: str | None = None
    duration_seconds: float = 0.0
    exit_code: int | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    error: str | None = None
    executable: str | None = None
    sources_dir: str | None = None


def jadx_executable() -> str | None:
    configured = getattr(settings, "jadx_path", None)
    if configured:
        candidate = Path(configured)
        if candidate.is_file():
            return str(candidate)
    return shutil.which("jadx")


def jadx_version(executable: str | None = None) -> str | None:
    executable = executable or jadx_executable()
    if executable is None:
        return None
    try:
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (result.stdout or result.stderr).strip()
    return output.splitlines()[0] if output else "unknown"


def run_jadx(apk_path: Path, output_dir: Path, timeout: int | None = None) -> JadxResult:
    executable = jadx_executable()
    if executable is None:
        return JadxResult(status=UNAVAILABLE, error="jadx not found on PATH or configured path")

    timeout = timeout or int(getattr(settings, "jadx_timeout_seconds", 600))
    version = jadx_version(executable)
    output_dir.mkdir(parents=True, exist_ok=True)
    arguments = [
        executable,
        "--no-res",
        "--no-debug-info",
        "--deobf",
        "-d",
        str(output_dir),
        str(apk_path),
    ]
    started = time.monotonic()
    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        return JadxResult(
            status=TIMEOUT,
            version=version,
            output_dir=str(output_dir),
            duration_seconds=round(time.monotonic() - started, 3),
            error=f"jadx exceeded {timeout}s timeout",
            executable=executable,
            stderr_tail=_tail(error.stderr),
        )
    except OSError as error:
        return JadxResult(status=FAILED, version=version, error=str(error), executable=executable)

    duration = round(time.monotonic() - started, 3)
    sources = output_dir / "sources"
    # JADX can exit non-zero yet still emit partial sources; treat produced
    # sources as success-with-warnings, otherwise a hard failure.
    produced = sources.exists() and any(sources.rglob("*.java"))
    status = SUCCESS if (completed.returncode == 0 or produced) else FAILED
    return JadxResult(
        status=status,
        version=version,
        output_dir=str(output_dir),
        sources_dir=str(sources) if produced else None,
        duration_seconds=duration,
        exit_code=completed.returncode,
        stdout_tail=_tail(completed.stdout),
        stderr_tail=_tail(completed.stderr),
        executable=executable,
        error=None if status == SUCCESS else "jadx returned no sources",
    )


def _tail(text: str | None, limit: int = 2000) -> str:
    if not text:
        return ""
    return text[-limit:]

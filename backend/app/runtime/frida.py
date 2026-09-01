"""Optional Frida adapter (observation-only).

Frida is never started silently, never downloads binaries, and never selects a
process automatically. When Frida is unavailable the adapter degrades to
UNAVAILABLE. Attach requires an explicit device + process/package.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings

AVAILABLE, UNAVAILABLE, UNKNOWN = "AVAILABLE", "UNAVAILABLE", "UNKNOWN"


def frida_cli() -> str | None:
    configured = getattr(settings, "frida_path", "") or ""
    if configured and Path(configured).is_file():
        return configured
    return shutil.which("frida")


def frida_python_available() -> bool:
    import importlib.util

    return importlib.util.find_spec("frida") is not None


@dataclass
class FridaStatus:
    cli: str
    cli_path: str | None
    version: str | None
    python_binding: str
    server_on_device: str  # UNKNOWN until a device is checked
    reason: str = ""


@dataclass
class FridaObservation:
    observation_type: str
    class_name: str | None = None
    method_name: str | None = None
    symbol: str | None = None
    native_library: str | None = None
    arguments_summary: str | None = None
    return_summary: str | None = None
    metadata: dict = field(default_factory=dict)


class FridaAdapter:
    def __init__(self, adb=None):
        self.cli = frida_cli()
        self.adb = adb

    @property
    def available(self) -> bool:
        return self.cli is not None or frida_python_available()

    def version(self) -> str | None:
        if self.cli is None:
            try:
                import frida
                return getattr(frida, "__version__", None)
            except Exception:
                return None
        try:
            result = subprocess.run([self.cli, "--version"], capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return (result.stdout or result.stderr).strip() or None

    def server_status(self, serial: str | None) -> str:
        """frida-server presence on the device (UNKNOWN without a live device)."""
        if self.adb is None or serial is None or not getattr(self.adb, "available", False):
            return UNKNOWN
        result = self.adb._run(["-s", serial, "shell", "ls", settings.frida_server_path_on_device], timeout=10)
        combined = result.stdout + result.stderr
        # A confirmed-absent file is UNAVAILABLE even though `ls` exits non-zero.
        if "No such file" in combined or "not found" in combined:
            return UNAVAILABLE
        if not result.ok:
            return UNKNOWN
        return AVAILABLE if settings.frida_server_path_on_device.split("/")[-1] in result.stdout else UNKNOWN

    def status(self, serial: str | None = None) -> FridaStatus:
        if not self.available:
            return FridaStatus("frida", None, None, UNAVAILABLE, UNKNOWN,
                               reason="frida CLI and Python binding both absent")
        return FridaStatus(
            cli="frida", cli_path=self.cli, version=self.version(),
            python_binding=AVAILABLE if frida_python_available() else UNAVAILABLE,
            server_on_device=self.server_status(serial))

    def attach_and_observe(self, serial: str, package: str, script: str,
                           duration: int = 10) -> tuple[str, list[FridaObservation]]:
        """Attach with an observation-only script and collect messages.

        Returns (status, observations). Requires the Python frida binding and a
        live device+process; otherwise returns UNAVAILABLE with no observations.
        This is never invoked automatically — only on explicit user request.
        """
        if not frida_python_available():
            return UNAVAILABLE, []
        try:
            import frida  # type: ignore
        except Exception:
            return UNAVAILABLE, []
        observations: list[FridaObservation] = []
        try:
            device = frida.get_device(serial, timeout=5)
            pid = device.spawn([package])
            session = device.attach(pid)
            frida_script = session.create_script(script)

            def on_message(message, data):
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    observations.append(_from_payload(payload))

            frida_script.on("message", on_message)
            frida_script.load()
            device.resume(pid)
            import time
            time.sleep(min(duration, settings.runtime_command_timeout_seconds))
            session.detach()
            return "COMPLETED", observations
        except Exception as error:  # never crash the framework on a runtime failure
            return f"FAILED: {error}", observations


def _from_payload(payload: dict) -> FridaObservation:
    if payload.get("type") == "NATIVE":
        return FridaObservation("NATIVE", symbol=payload.get("symbol"))
    return FridaObservation(
        "JAVA", class_name=payload.get("clazz"), method_name=payload.get("method"),
        arguments_summary=", ".join(payload.get("args", []))[:500],
        return_summary=(payload.get("ret") or "")[:500])

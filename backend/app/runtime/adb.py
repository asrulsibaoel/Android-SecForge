"""Safe ADB adapter.

Every invocation uses an argument array (never ``shell=True``), a strict timeout,
and captures stdout/stderr/exit-code. It never escalates privilege, never
auto-connects, and never installs/launches unless an explicit method is called.
Subclass/duck-type ``AdbAdapter`` for deterministic mock testing without a device.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings


@dataclass
class AdbResult:
    ok: bool
    exit_code: int | None
    stdout: str
    stderr: str
    command: list[str] = field(default_factory=list)
    error: str | None = None


def adb_executable() -> str | None:
    configured = getattr(settings, "adb_path", "") or ""
    if configured and Path(configured).is_file():
        return configured
    return shutil.which("adb")


@dataclass
class Device:
    serial: str
    state: str
    model: str | None = None
    manufacturer: str | None = None
    brand: str | None = None
    android_version: str | None = None
    sdk_version: str | None = None
    architecture: str | None = None
    abi: str | None = None
    build_fingerprint: str | None = None
    build_type: str | None = None
    rooted: bool | None = None
    is_emulator: bool = False


class AdbAdapter:
    """Real ADB adapter. Available only when the adb executable is present."""

    def __init__(self, executable: str | None = None):
        self.executable = executable or adb_executable()

    @property
    def available(self) -> bool:
        return self.executable is not None

    def _run(self, args: list[str], timeout: int | None = None) -> AdbResult:
        if self.executable is None:
            return AdbResult(False, None, "", "", args, error="adb not available")
        cmd = [self.executable, *args]
        timeout = timeout or settings.runtime_command_timeout_seconds
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            return AdbResult(False, None, "", "", cmd, error=f"timeout after {timeout}s: {error}")
        except OSError as error:
            return AdbResult(False, None, "", "", cmd, error=str(error))
        return AdbResult(completed.returncode == 0, completed.returncode, completed.stdout, completed.stderr, cmd)

    def version(self) -> str | None:
        result = self._run(["version"], timeout=10)
        if not result.ok:
            return None
        line = result.stdout.strip().splitlines()
        return line[0] if line else None

    def list_devices(self) -> list[Device]:
        result = self._run(["devices", "-l"], timeout=15)
        if not result.ok:
            return []
        devices: list[Device] = []
        for line in result.stdout.splitlines()[1:]:  # skip "List of devices attached"
            line = line.strip()
            if not line or line.startswith("*"):
                continue
            parts = line.split()
            serial, state = parts[0], parts[1] if len(parts) > 1 else "unknown"
            model = next((p.split(":", 1)[1] for p in parts[2:] if p.startswith("model:")), None)
            device = Device(serial=serial, state=state, model=model,
                            is_emulator=serial.startswith("emulator-") or serial.startswith("emu"))
            devices.append(device)
        return devices

    def enrich_device(self, device: Device) -> Device:
        """Fetch device properties (best-effort, read-only getprop)."""
        if device.state != "device":
            return device
        props = self._getprops(device.serial)
        device.model = device.model or props.get("ro.product.model")
        device.manufacturer = props.get("ro.product.manufacturer")
        device.brand = props.get("ro.product.brand")
        device.android_version = props.get("ro.build.version.release")
        device.sdk_version = props.get("ro.build.version.sdk")
        device.abi = props.get("ro.product.cpu.abi")
        device.architecture = props.get("ro.product.cpu.abi")
        device.build_fingerprint = props.get("ro.build.fingerprint")
        device.build_type = props.get("ro.build.type")
        if props.get("ro.build.characteristics", "").find("emulator") >= 0 or props.get("ro.kernel.qemu") == "1":
            device.is_emulator = True
        secure = props.get("ro.secure")
        debuggable = props.get("ro.debuggable")
        # Conservative rooted signal: only from safely observable build props.
        if debuggable == "1" and secure == "0":
            device.rooted = True
        return device

    def responsive(self, serial: str) -> bool:
        """A single read-only shell ping to confirm the device answers commands."""
        result = self._run(["-s", serial, "shell", "echo", "ASF_PING"], timeout=10)
        return result.ok and "ASF_PING" in result.stdout

    def _getprops(self, serial: str) -> dict[str, str]:
        result = self._run(["-s", serial, "shell", "getprop"], timeout=15)
        props: dict[str, str] = {}
        if not result.ok:
            return props
        for match in re.finditer(r"\[([^\]]+)\]:\s*\[([^\]]*)\]", result.stdout):
            props[match.group(1)] = match.group(2)
        return props

    # Explicit, auditable operations -------------------------------------

    def install(self, serial: str, apk_path: str) -> AdbResult:
        return self._run(["-s", serial, "install", "-r", apk_path], timeout=settings.runtime_command_timeout_seconds)

    def uninstall(self, serial: str, package: str) -> AdbResult:
        return self._run(["-s", serial, "uninstall", package])

    def package_info(self, serial: str, package: str) -> AdbResult:
        return self._run(["-s", serial, "shell", "dumpsys", "package", package])

    def launch(self, serial: str, package: str, activity: str | None = None) -> AdbResult:
        if activity:
            component = activity if "/" in activity else f"{package}/{activity}"
            return self._run(["-s", serial, "shell", "am", "start", "-n", component])
        return self._run(["-s", serial, "shell", "monkey", "-p", package, "-c",
                          "android.intent.category.LAUNCHER", "1"])

    def force_stop(self, serial: str, package: str) -> AdbResult:
        return self._run(["-s", serial, "shell", "am", "force-stop", package])

    def logcat_dump(self, serial: str, timeout: int | None = None) -> AdbResult:
        # -d dumps and exits (bounded); never a persistent stream.
        return self._run(["-s", serial, "logcat", "-d", "-v", "threadtime"],
                         timeout=timeout or settings.runtime_logcat_timeout_seconds)

    def clear_logcat(self, serial: str) -> AdbResult:
        return self._run(["-s", serial, "logcat", "-c"], timeout=10)

    def processes(self, serial: str) -> AdbResult:
        return self._run(["-s", serial, "shell", "ps", "-A"], timeout=15)

    def pidof(self, serial: str, package: str) -> AdbResult:
        return self._run(["-s", serial, "shell", "pidof", package], timeout=10)


# ---------------------------------------------------------------------------
# Parsers (pure functions; unit-testable without a device)
# ---------------------------------------------------------------------------

_LOGCAT_RE = re.compile(
    r"^\d{2}-\d{2}\s+[\d:.]+\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<pri>[VDIWEFS])\s+(?P<tag>[^:]*):\s?(?P<msg>.*)$"
)


def parse_logcat(text: str, max_lines: int = 5000) -> list[dict]:
    events: list[dict] = []
    for line in text.splitlines():
        if len(events) >= max_lines:
            break
        m = _LOGCAT_RE.match(line.strip())
        if m:
            events.append({"pid": int(m.group("pid")), "priority": m.group("pri"),
                           "tag": m.group("tag").strip(), "message": m.group("msg")})
    return events


_PS_RE = re.compile(r"^(?P<user>\S+)\s+(?P<pid>\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<name>\S+)\s*$")


def parse_ps(text: str) -> list[dict]:
    processes: list[dict] = []
    for line in text.splitlines()[1:]:  # skip header
        m = _PS_RE.match(line.strip())
        if m:
            processes.append({"uid": m.group("user"), "pid": int(m.group("pid")), "name": m.group("name")})
    return processes

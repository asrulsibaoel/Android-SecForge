"""Runtime capability detection (adb / frida / frida-server / device / emulator).

Never reports READY on mere detection — availability reflects actual usability,
and a device is CONNECTED only if ``adb devices`` lists one in the ``device``
state.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.runtime.adb import AdbAdapter
from app.runtime.frida import FridaAdapter


def _cap(name, availability, version=None, path=None, reason="", remediation=""):
    return {
        "name": name, "availability": availability, "version": version, "path": path,
        "detected_at": datetime.now(timezone.utc).isoformat(), "reason": reason, "remediation": remediation,
    }


def runtime_capabilities(adb: AdbAdapter | None = None, frida: FridaAdapter | None = None) -> list[dict]:
    adb = adb or AdbAdapter()
    frida = frida or FridaAdapter(adb=adb)
    caps: list[dict] = []

    if adb.available:
        version = adb.version()
        caps.append(_cap("adb", "AVAILABLE" if version else "UNAVAILABLE", version=version, path=adb.executable,
                         reason="adb executable detected and responsive" if version else "adb present but not responsive",
                         remediation="" if version else "check platform-tools installation"))
        devices = adb.list_devices()
        connected = [d for d in devices if d.state == "device"]
        caps.append(_cap("device", "CONNECTED" if connected else "NOT_CONNECTED",
                         reason=f"{len(connected)} device(s) in 'device' state" if connected else "no devices attached",
                         remediation="connect a device/emulator and run 'adb devices'" if not connected else ""))
        if connected:
            caps.append(_cap("emulator", "AVAILABLE" if any(d.is_emulator for d in connected) else "UNAVAILABLE",
                             reason="emulator detected among attached devices" if any(d.is_emulator for d in connected)
                             else "no emulator among attached devices"))
        else:
            caps.append(_cap("emulator", "NOT_CONNECTED", reason="no attached devices to classify"))
    else:
        caps.append(_cap("adb", "UNAVAILABLE", reason="adb not found on PATH or ASF_ADB_PATH",
                         remediation="install Android platform-tools and add adb to PATH"))
        caps.append(_cap("device", "NOT_CONNECTED", reason="adb unavailable"))
        caps.append(_cap("emulator", "NOT_CONNECTED", reason="adb unavailable"))

    status = frida.status()
    caps.append(_cap("frida", "AVAILABLE" if frida.available else "UNAVAILABLE", version=status.version,
                     path=status.cli_path,
                     reason="frida CLI or Python binding detected" if frida.available else status.reason,
                     remediation="" if frida.available else "pip install frida-tools (explicit, user opt-in)"))
    caps.append(_cap("frida-server", status.server_on_device,
                     reason="checked on device" if status.server_on_device != "UNKNOWN"
                     else "cannot verify without a connected device"))

    # Prompt 21: independent runtime-validation + native-runtime-correlation states.
    device_connected = adb.available and any(d.state == "device" for d in (adb.list_devices() if adb.available else []))
    if device_connected:
        rv_state, rv_reason = "READY", "device connected; LIVE runtime validation available"
    elif adb.available:
        rv_state = "PARTIAL"
        rv_reason = "adb present but no device; offline correlation over existing evidence works, LIVE is UNAVAILABLE"
    else:
        rv_state, rv_reason = "UNAVAILABLE", "adb unavailable; LIVE runtime validation not possible"
    caps.append(_cap("runtime-validation", rv_state, reason=rv_reason,
                     remediation="" if device_connected else "connect a device/emulator for LIVE validation"))

    if device_connected and frida.available:
        nrc_state, nrc_reason = "READY", "device + frida available; native/JNI runtime invocation can be observed live"
    elif device_connected:
        nrc_state = "PARTIAL"
        nrc_reason = "device connected but frida unavailable; native invocation cannot be hooked (ADB-only)"
    else:
        nrc_state, nrc_reason = "UNAVAILABLE", "no device; native-runtime correlation cannot observe LIVE invocations"
    caps.append(_cap("native-runtime-correlation", nrc_state, reason=nrc_reason,
                     remediation="" if nrc_state == "READY" else "connect a device and install frida for live native hooks"))
    return caps

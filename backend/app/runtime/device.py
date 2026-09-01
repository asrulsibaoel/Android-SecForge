"""Real-device capability discovery (prompt 23).

A safe, read-only discovery flow around the existing ADB/Frida adapters that
classifies the connection from ACTUAL adb output. It never infers frida-server
availability from host Frida being installed, never fabricates metadata, and
attaches to nothing. Every field carries provenance (the adb commands used).

Explicit states (reusing existing conventions):
  device:  CONNECTED | UNAUTHORIZED | OFFLINE | NOT_CONNECTED | ADB_UNAVAILABLE
  frida (host):        AVAILABLE | FRIDA_UNAVAILABLE
  frida-server:        AVAILABLE | FRIDA_SERVER_UNAVAILABLE | UNKNOWN
  runtime-validation:  READY | PARTIAL | UNAVAILABLE
  native-runtime:      READY | PARTIAL | UNAVAILABLE
"""

from __future__ import annotations

from app.runtime.adb import AdbAdapter, Device
from app.runtime.frida import FridaAdapter

STATE_BY_ADB = {"device": "CONNECTED", "unauthorized": "UNAUTHORIZED", "offline": "OFFLINE"}


def classify_device_state(adb_state: str) -> str:
    return STATE_BY_ADB.get((adb_state or "").lower(), "NOT_CONNECTED")


def _redacted_device(d: Device, authorized: bool, responsive: bool) -> dict:
    # Only safe, non-personal device metadata (no full getprop dump, no user data).
    return {
        "serial": d.serial,
        "model": d.model,
        "manufacturer": d.manufacturer,
        "brand": d.brand,
        "android_version": d.android_version,
        "api_level": d.sdk_version,
        "abi": d.abi,
        "architecture": d.architecture,
        "build_fingerprint": d.build_fingerprint,
        "build_type": d.build_type,
        "is_emulator": d.is_emulator,
        "rooted_signal": d.rooted,
        "authorized": authorized,
        "responsive": responsive,
    }


def discover_device(serial: str | None = None, adb: AdbAdapter | None = None,
                    frida: FridaAdapter | None = None) -> dict:
    adb = adb or AdbAdapter()
    frida = frida or FridaAdapter(adb=adb)
    provenance: list[str] = []

    if not adb.available:
        return {
            "adb": "ADB_UNAVAILABLE", "device_state": "NOT_CONNECTED",
            "frida_host": "AVAILABLE" if frida.available else "FRIDA_UNAVAILABLE",
            "frida_server": "UNKNOWN", "runtime_validation": "UNAVAILABLE",
            "native_runtime_correlation": "UNAVAILABLE", "device": None,
            "provenance": provenance, "reason": "adb executable not found on host",
        }

    provenance.append("adb devices -l")
    devices = adb.list_devices()
    match = next((d for d in devices if d.serial == serial), None) if serial else (devices[0] if devices else None)

    if match is None:
        return {
            "adb": "AVAILABLE", "device_state": "NOT_CONNECTED",
            "frida_host": "AVAILABLE" if frida.available else "FRIDA_UNAVAILABLE",
            "frida_server": "UNKNOWN", "runtime_validation": "UNAVAILABLE",
            "native_runtime_correlation": "UNAVAILABLE", "device": None,
            "provenance": provenance,
            "reason": f"device {serial} not attached" if serial else "no devices attached",
        }

    device_state = classify_device_state(match.state)
    frida_host = "AVAILABLE" if frida.available else "FRIDA_UNAVAILABLE"

    if device_state != "CONNECTED":
        # UNAUTHORIZED / OFFLINE — cannot query the device; never guess metadata.
        return {
            "adb": "AVAILABLE", "device_state": device_state, "serial": match.serial,
            "frida_host": frida_host, "frida_server": "UNKNOWN",
            "runtime_validation": "UNAVAILABLE", "native_runtime_correlation": "UNAVAILABLE",
            "device": {"serial": match.serial, "authorized": False},
            "provenance": provenance,
            "reason": "device is UNAUTHORIZED — accept the USB debugging prompt on the device"
            if device_state == "UNAUTHORIZED" else "device is OFFLINE",
        }

    enriched = adb.enrich_device(match)
    provenance.append("adb -s <serial> shell getprop")
    responsive = adb.responsive(match.serial)
    provenance.append("adb -s <serial> shell echo ASF_PING")

    server_status = frida.server_status(match.serial)  # AVAILABLE | UNAVAILABLE | UNKNOWN
    provenance.append("adb -s <serial> shell ls <frida-server-path>")
    frida_server = {"AVAILABLE": "AVAILABLE", "UNAVAILABLE": "FRIDA_SERVER_UNAVAILABLE"}.get(server_status, "UNKNOWN")

    runtime_validation = "READY" if responsive else "PARTIAL"
    # Native runtime correlation needs a reachable frida-server to observe JNI/native
    # invocation live; host Frida alone is NOT sufficient (never inferred).
    if frida.available and frida_server == "AVAILABLE":
        native_runtime = "READY"
    elif responsive:
        native_runtime = "PARTIAL"
    else:
        native_runtime = "UNAVAILABLE"

    return {
        "adb": "AVAILABLE", "device_state": "CONNECTED", "serial": match.serial,
        "frida_host": frida_host, "frida_host_version": frida.version(),
        "frida_server": frida_server,
        "runtime_validation": runtime_validation,
        "native_runtime_correlation": native_runtime,
        "device": _redacted_device(enriched, authorized=True, responsive=responsive),
        "provenance": provenance,
        "note": "device metadata is read-only; frida-server availability is checked on the device and is never "
                "inferred from host Frida. No process was attached during discovery.",
    }

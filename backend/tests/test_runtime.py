"""Runtime Lab tests — fully offline (mock ADB/Frida adapters).

These mocks stand in for a device; they are clearly not real runtime capability.
No test requires an Android device, emulator, ADB, or Frida to be present.
"""

import hashlib
import uuid

import pytest

from app.analysis.runtime_correlation import correlate_runtime
from app.models.analysis import Analysis, EvidenceModel, FindingModel, ManifestModel
from app.models.runtime import RuntimeObservation
from app.runtime.adb import AdbAdapter, AdbResult, Device, parse_logcat, parse_ps
from app.runtime.frida import FridaAdapter, FridaObservation, FridaStatus
from app.runtime.session import RuntimeLab, mask

_LOGCAT = "08-27 10:00:00.000  1234  1234 I MockTag: password=hunter2secret loaded url\n"
_PS = "USER            PID   PPID     VSZ    RSS WCHAN            ADDR S NAME\n" \
      "u0_a100         1234   900   12345   6789 0                   0 S com.androidsecforge.testapp\n"


class MockAdb(AdbAdapter):
    def __init__(self, available=True, device=True):
        self.executable = "/mock/adb" if available else None
        self._device = device

    @property
    def available(self):
        return self.executable is not None

    def version(self):
        return "mock-adb 1.0" if self.available else None

    def list_devices(self):
        if not (self.available and self._device):
            return []
        return [Device("emulator-5554", "device", model="MockPixel", is_emulator=True)]

    def enrich_device(self, d):
        d.android_version, d.sdk_version, d.abi, d.architecture = "13", "33", "arm64-v8a", "arm64-v8a"
        return d

    def install(self, serial, apk):
        return AdbResult(True, 0, "Success\n", "", ["adb", "-s", serial, "install", "-r", apk])

    def uninstall(self, serial, package):
        return AdbResult(True, 0, "Success\n", "", ["adb", "uninstall", package])

    def launch(self, serial, package, activity=None):
        return AdbResult(True, 0, "Starting: Intent {...}\n", "", ["adb", "am", "start"])

    def force_stop(self, serial, package):
        return AdbResult(True, 0, "", "", ["adb", "am", "force-stop", package])

    def logcat_dump(self, serial, timeout=None):
        return AdbResult(True, 0, _LOGCAT, "", ["adb", "logcat", "-d"])

    def processes(self, serial):
        return AdbResult(True, 0, _PS, "", ["adb", "ps", "-A"])


class MockFrida(FridaAdapter):
    def __init__(self, available=True):
        self.cli = "/mock/frida" if available else None
        self.adb = None
        self._avail = available

    @property
    def available(self):
        return self._avail

    def status(self, serial=None):
        return FridaStatus("frida", self.cli, "16.0", "AVAILABLE" if self._avail else "UNAVAILABLE", "UNKNOWN")

    def attach_and_observe(self, serial, package, script, duration=10):
        return "COMPLETED", [
            FridaObservation("JAVA", class_name="android.webkit.WebView", method_name="loadUrl",
                             arguments_summary="https://example.test?token=abcdefghijklmnopqrstuvwxyz012345"),
            FridaObservation("NATIVE", symbol="strcpy"),
        ]


def _analysis(db, package="com.androidsecforge.testapp", sha="a" * 64):
    a = Analysis(apk_id=uuid.uuid4(), apk_sha256=sha, profile="static", status="PARTIAL")
    a.manifest = ManifestModel(status="parsed", source_format="binary_axml", package=package)
    db.add(a)
    db.flush()
    return a


# ---- pure parsers (no device) ----

def test_parse_logcat():
    events = parse_logcat(_LOGCAT)
    assert events and events[0]["pid"] == 1234 and events[0]["tag"] == "MockTag"


def test_parse_ps():
    procs = parse_ps(_PS)
    assert any(p["name"] == "com.androidsecforge.testapp" and p["pid"] == 1234 for p in procs)


def test_mask_redacts_secrets():
    assert "hunter2secret" not in mask("password=hunter2secret")
    assert "***" in mask("password=hunter2secret")
    # long non-token text is truncated with an ellipsis
    assert mask("data " * 100).endswith("…")


# ---- session lifecycle (mocked device) ----

def test_session_lifecycle_and_audit(db_session, tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04 mock apk")
    sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    a = _analysis(db_session, sha=sha)
    lab = RuntimeLab(db_session, adb=MockAdb(), frida=MockFrida())

    session = lab.create_session(a)
    assert session.session_state == "CREATED"
    assert lab.select_device(session, "emulator-5554")["status"] == "OK"
    assert session.session_state == "DEVICE_SELECTED"
    assert lab.install(session, str(apk))["status"] == "OK"
    assert session.session_state == "INSTALLED"
    assert lab.launch(session, ".MainActivity")["status"] == "OK"
    assert session.session_state == "RUNNING"
    assert lab.collect_logcat(session)["events"] >= 1
    assert lab.collect_processes(session)["processes"] >= 1
    assert lab.stop(session)["status"] == "OK"
    assert session.session_state == "COMPLETED"
    db_session.commit()

    ops = {e.operation for e in session.audit_events}
    assert {"CREATE", "SELECT_DEVICE", "INSTALL", "LAUNCH", "STOP", "LOGCAT_START", "LOGCAT_STOP", "PROCESS"} <= ops
    # logcat secret masking persisted
    assert all("hunter2secret" not in e.message for e in session.events)


def test_install_sha_mismatch_fails(db_session, tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"real bytes")
    a = _analysis(db_session, sha="b" * 64)  # analysis expects a different hash
    lab = RuntimeLab(db_session, adb=MockAdb())
    session = lab.create_session(a)
    lab.select_device(session, "emulator-5554")
    result = lab.install(session, str(apk))
    assert result["status"] == "FAILED"
    assert "SHA-256" in result["error"]


def test_offline_no_adb_degrades_honestly(db_session, tmp_path):
    apk = tmp_path / "app.apk"; apk.write_bytes(b"x")
    a = _analysis(db_session)
    lab = RuntimeLab(db_session, adb=MockAdb(available=False))
    session = lab.create_session(a)
    assert lab.select_device(session, "emulator-5554")["status"] == "FAILED"
    assert lab.install(session, str(apk))["status"] == "FAILED"
    assert session.observations == []  # nothing fabricated


def test_frida_attach_persists_masked_observations(db_session):
    a = _analysis(db_session)
    lab = RuntimeLab(db_session, adb=MockAdb(), frida=MockFrida())
    session = lab.create_session(a)
    lab.select_device(session, "emulator-5554")
    result = lab.frida_attach(session, ["webview", "native_dangerous"], duration=1)
    assert result["observations"] == 2
    assert session.instrumentation_enabled is True
    webview_obs = next(o for o in session.observations if o.method_name == "loadUrl")
    assert "abcdefghijklmnopqrstuvwxyz012345" not in (webview_obs.arguments_summary or "")  # token masked


def test_frida_unavailable_degrades(db_session):
    a = _analysis(db_session)
    lab = RuntimeLab(db_session, adb=MockAdb(), frida=MockFrida(available=False))
    session = lab.create_session(a)
    lab.select_device(session, "emulator-5554")
    assert lab.frida_attach(session, ["webview"])["status"] == "FAILED"


# ---- static <-> runtime correlation ----

def _finding(a, rule_id, category, component, evidence_detail):
    f = FindingModel(rule_id=rule_id, title=f"{rule_id}", category=category, severity="medium",
                     confidence="medium", status="POTENTIAL", component=component,
                     confidence_score=60)
    f.evidence.append(EvidenceModel(source="reachability", location="x", detail=evidence_detail))
    a.findings.append(f)
    return f


def test_runtime_confirms_static(db_session):
    a = _analysis(db_session)
    finding = _finding(a, "ANDROID-REACH-001", "reachability", ".Web",
                       "[2] SECURITY_SINK WebView.loadUrl (INVOKES)")
    lab = RuntimeLab(db_session, adb=MockAdb(), frida=MockFrida())
    session = lab.create_session(a)
    session.instrumentation_enabled = True
    session.observations.append(RuntimeObservation(observation_type="JAVA", class_name="android.webkit.WebView",
                                                   method_name="loadUrl", source="FRIDA", confidence="MEDIUM"))
    db_session.flush()
    summary = correlate_runtime(a)
    assert summary["confirmed"] >= 1
    assert finding.runtime_status == "STATIC_RUNTIME_CONFIRMED"
    assert finding.validation_state == "OBSERVED"
    assert finding.confidence_score == 75  # bounded +15 bump


def test_not_observed_is_not_safe(db_session):
    a = _analysis(db_session)
    finding = _finding(a, "ANDROID-WEBVIEW-001", "webview", ".Web", "setJavaScriptEnabled(true)")
    lab = RuntimeLab(db_session, adb=MockAdb(), frida=MockFrida())
    session = lab.create_session(a)
    session.instrumentation_enabled = True  # instrumentation ran, but nothing observed for this finding
    db_session.flush()
    correlate_runtime(a)
    assert finding.validation_state == "NOT_OBSERVED"   # explicitly NOT "SAFE"
    assert finding.runtime_status == "STATIC_ONLY"      # static evidence not downgraded


def test_native_observation_supports_static_path(db_session):
    a = _analysis(db_session)
    finding = _finding(a, "ASF-NATIVE-STR-001", "native", "libx.so", "imports strcpy (indicator only)")
    lab = RuntimeLab(db_session, adb=MockAdb())
    session = lab.create_session(a)
    session.instrumentation_enabled = True
    session.observations.append(RuntimeObservation(observation_type="NATIVE", symbol="strcpy",
                                                   source="FRIDA", confidence="MEDIUM"))
    db_session.flush()
    correlate_runtime(a)
    assert finding.runtime_status == "RUNTIME_SUPPORTS_STATIC_PATH"

"""Real-device runtime validation tests (prompt 23) — fully offline via mock
ADB/Frida adapters. These exercise device-capability classification, LIVE
ADB-only observation, LIVE vs MOCKED separation, redaction, bounds/TRUNCATED, and
the guarantee that runtime evidence never overwrites static truth. No test
requires a physical device.
"""

import uuid

import pytest

from app.runtime.adb import AdbAdapter, AdbResult, Device
from app.runtime.device import classify_device_state, discover_device
from app.runtime.frida import FridaAdapter
from app.runtime.session import RuntimeLab, _parse_component_line, mask
from app.models.runtime import RuntimeSession


class FakeAdb(AdbAdapter):
    def __init__(self, available=True, device_state="device", serial="TESTSERIAL", pids="", logcat=""):
        self.executable = "/fake/adb" if available else None
        self._state = device_state
        self._serial = serial
        self._pids = pids
        self._logcat = logcat

    @property
    def available(self):
        return self.executable is not None

    def list_devices(self):
        if not self.available or self._state is None:
            return []
        return [Device(serial=self._serial, state=self._state, model="FakeModel")]

    def enrich_device(self, d):
        d.model, d.manufacturer, d.brand = "FakeModel", "FakeCo", "FB"
        d.android_version, d.sdk_version = "16", "36"
        d.abi = d.architecture = "arm64-v8a"
        d.build_fingerprint = "FB/fake_global/fake:16/BUILD:user/release-keys"
        d.build_type = "user"
        return d

    def responsive(self, serial):
        return True

    def pidof(self, serial, package):
        return AdbResult(bool(self._pids), 0 if self._pids else 1, self._pids, "", [])

    def logcat_dump(self, serial, timeout=None):
        return AdbResult(True, 0, self._logcat, "", [])

    def clear_logcat(self, serial):
        return AdbResult(True, 0, "", "", [])


class FakeFrida(FridaAdapter):
    def __init__(self, available=True, server="UNAVAILABLE"):
        self.cli = "/fake/frida" if available else None
        self.adb = None
        self._avail = available
        self._server = server

    @property
    def available(self):
        return self._avail

    def version(self):
        return "17.17.0" if self._avail else None

    def server_status(self, serial=None):
        return self._server


# --- device capability classification --------------------------------------

def test_classify_device_state():
    assert classify_device_state("device") == "CONNECTED"
    assert classify_device_state("unauthorized") == "UNAUTHORIZED"
    assert classify_device_state("offline") == "OFFLINE"
    assert classify_device_state("something") == "NOT_CONNECTED"


def test_discover_connected_frida_server_unavailable():
    d = discover_device("TESTSERIAL", adb=FakeAdb(), frida=FakeFrida(available=True, server="UNAVAILABLE"))
    assert d["device_state"] == "CONNECTED"
    assert d["frida_host"] == "AVAILABLE"
    # frida-server availability is NEVER inferred from host Frida
    assert d["frida_server"] == "FRIDA_SERVER_UNAVAILABLE"
    assert d["runtime_validation"] == "READY"
    assert d["native_runtime_correlation"] == "PARTIAL"
    assert d["device"]["authorized"] is True and d["device"]["api_level"] == "36"
    assert "provenance" in d and d["provenance"]


def test_discover_native_ready_only_with_server():
    d = discover_device("TESTSERIAL", adb=FakeAdb(), frida=FakeFrida(available=True, server="AVAILABLE"))
    assert d["frida_server"] == "AVAILABLE"
    assert d["native_runtime_correlation"] == "READY"


def test_discover_frida_host_unavailable():
    d = discover_device("TESTSERIAL", adb=FakeAdb(), frida=FakeFrida(available=False))
    assert d["frida_host"] == "FRIDA_UNAVAILABLE"
    assert d["native_runtime_correlation"] == "PARTIAL"  # device responsive, but no native live


def test_discover_unauthorized_leaks_no_metadata():
    d = discover_device("TESTSERIAL", adb=FakeAdb(device_state="unauthorized"), frida=FakeFrida())
    assert d["device_state"] == "UNAUTHORIZED"
    assert d["runtime_validation"] == "UNAVAILABLE"
    assert d["device"].get("authorized") is False
    assert "build_fingerprint" not in d["device"]  # never query an unauthorized device


def test_discover_offline_and_not_connected_and_adb_unavailable():
    assert discover_device(None, adb=FakeAdb(device_state="offline"), frida=FakeFrida())["device_state"] == "OFFLINE"
    assert discover_device(None, adb=FakeAdb(device_state=None), frida=FakeFrida())["device_state"] == "NOT_CONNECTED"
    down = discover_device(None, adb=FakeAdb(available=False), frida=FakeFrida())
    assert down["adb"] == "ADB_UNAVAILABLE" and down["runtime_validation"] == "UNAVAILABLE"


# --- component-line parsing -------------------------------------------------

def test_parse_component_line():
    pkg = "com.x"
    cls, method, taxo = _parse_component_line(f"START u0 {{cmp={pkg}/.ui.MainActivity}}", pkg)
    assert cls == "com.x.ui.MainActivity" and method == "onCreate" and taxo == "ACTIVITY_LAUNCH"
    assert _parse_component_line(f"Displayed {pkg}/.Main", pkg)[2] == "ACTIVITY_LAUNCH"
    assert _parse_component_line("some broadcast line com.x", pkg)[2] == "BROADCAST_DISPATCH"
    assert _parse_component_line("unrelated com.x noise", pkg)[2] == "COMPONENT_DISPATCH"


# --- LIVE ADB observation (scoped, sourced, redacted, bounded) --------------

def _live_session(db, analysis, serial="TESTSERIAL"):
    s = RuntimeSession(analysis_id=analysis.id, session_state="RUNNING", device_serial=serial,
                       package_name=analysis.manifest.package, instrumentation_enabled=False,
                       metadata_={"adapter": "adb"})
    analysis.runtime_sessions.append(s)
    db.flush()
    return s


def test_observe_package_adb_live_scoped(db_session, make_analysis):
    a = make_analysis(package="com.x")
    a.runtime_sessions.clear(); db_session.flush()
    logcat = ("START u0 {cmp=com.x/.ui.Main}\n"
              "line about com.other.app should be ignored\n"
              "broadcast com.x received\n")
    lab = RuntimeLab(db_session, adb=FakeAdb(pids="4242", logcat=logcat), requested_by="test")
    s = _live_session(db_session, a)
    res = lab.observe_package_adb(s, "com.x")
    assert res["status"] == "OK" and res["running"] is True and res["observations"] >= 2
    # every observation is LIVE (adb adapter), source ADB, and about com.x only
    assert all(o.source == "ADB" for o in s.observations)
    assert all((o.package_name == "com.x") for o in s.observations)
    assert any(o.taxonomy == "PROCESS_LIFECYCLE" for o in s.observations)
    assert any(o.taxonomy == "ACTIVITY_LAUNCH" for o in s.observations)
    # unrelated app never produces an observation
    assert not any("com.other" in (o.arguments_summary or "") for o in s.observations)


def test_observe_is_live_never_mocked(db_session, make_analysis):
    from app.analysis import runtime_validation as RV
    a = make_analysis(package="com.x")
    a.runtime_sessions.clear(); db_session.flush()
    lab = RuntimeLab(db_session, adb=FakeAdb(pids="10", logcat="START u0 {cmp=com.x/.Main}\n"), requested_by="test")
    s = _live_session(db_session, a)
    lab.observe_package_adb(s, "com.x")
    run = RV.build_runtime_validation(db_session, a)
    assert run.mode == "LIVE" and run.live_claim_count >= 1
    assert all(c.mode == "LIVE" and c.provenance == "RUNTIME_ADB" for c in a.runtime_correlations)


def test_observe_redaction_and_bounds(db_session, make_analysis, monkeypatch):
    from app.core.config import settings
    a = make_analysis(package="com.x")
    a.runtime_sessions.clear(); db_session.flush()
    logcat = "START u0 {cmp=com.x/.Main} password=hunter2secret token=abcdefghijklmnopqrstuvwxyz\n"
    lab = RuntimeLab(db_session, adb=FakeAdb(pids="1 2 3 4 5", logcat=logcat), requested_by="test")
    s = _live_session(db_session, a)
    monkeypatch.setattr(settings, "runtime_observation_limit", 2)
    res = lab.observe_package_adb(s, "com.x")
    assert res["truncated"] >= 1  # bound hit -> TRUNCATED recorded, never silent
    assert (s.metadata_ or {}).get("observations_truncated", 0) >= 1
    # secrets masked in any component observation argument summary
    for o in s.observations:
        if o.arguments_summary:
            assert "hunter2secret" not in o.arguments_summary


def test_runtime_never_overwrites_static_truth_live(db_session, make_analysis):
    from app.analysis import runtime_validation as RV
    a = make_analysis(package="com.x")
    a.runtime_sessions.clear(); db_session.flush()
    before = [(f.id, f.severity, f.severity_score, f.confidence_score, f.status) for f in a.findings]
    lab = RuntimeLab(db_session, adb=FakeAdb(pids="99", logcat="START u0 {cmp=com.x/.Main}\n"), requested_by="test")
    s = _live_session(db_session, a)
    lab.observe_package_adb(s, "com.x")
    RV.build_runtime_validation(db_session, a)
    after = [(f.id, f.severity, f.severity_score, f.confidence_score, f.status) for f in a.findings]
    assert before == after  # LIVE runtime never rewrites static severity/score/status


def test_artifact_hash_and_redaction(db_session, make_analysis):
    a = make_analysis(package="com.x")
    a.runtime_sessions.clear(); db_session.flush()
    lab = RuntimeLab(db_session, adb=FakeAdb(), requested_by="test")
    s = _live_session(db_session, a)
    res = lab.persist_artifact(s, "runtime_event_summary", "password=topsecret summary", redacted=True)
    assert res["status"] == "OK" and len(res["sha256"]) == 64 and res["redacted"] is True
    assert "topsecret" not in (s.artifacts[-1].path or "")

"""Runtime session lifecycle service (explicit, auditable, bounded).

Every mutating operation records a RuntimeAuditEvent and only proceeds on
explicit invocation. Nothing is installed, launched, connected, or instrumented
automatically. Observations are masked/truncated and never fabricated — if the
adapter fails or no device is present, the operation is recorded as FAILED.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.runtime import (
    RuntimeAuditEvent,
    RuntimeDevice,
    RuntimeEvent,
    RuntimeObservation,
    RuntimeProcess,
    RuntimeSession,
)
from app.runtime.adb import AdbAdapter, parse_logcat, parse_ps
from app.runtime.frida import FridaAdapter
from app.runtime.hooks import build_frida_script, profiles_by_name

_SECRET_RE = re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key|authorization|bearer)\s*[=:]\s*(\S+)")
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-]{24,}\b")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def mask(value: str | None, limit: int = 300) -> str | None:
    """Redact secret-looking substrings and truncate. Never persist secrets verbatim."""
    if value is None:
        return None
    text = _SECRET_RE.sub(lambda m: f"{m.group(1)}=***", value)
    text = _LONG_TOKEN_RE.sub(lambda m: m.group(0)[:4] + "***" + m.group(0)[-2:], text)
    return text[:limit] + ("…" if len(text) > limit else "")


class RuntimeLab:
    def __init__(self, db: Session, adb: AdbAdapter | None = None, frida: FridaAdapter | None = None,
                 requested_by: str = "cli"):
        self.db = db
        self.adb = adb or AdbAdapter()
        self.frida = frida or FridaAdapter(adb=self.adb)
        self.requested_by = requested_by

    # -- audit ----------------------------------------------------------
    def _audit(self, session, operation, result, device=None, package=None, error=None, command=None):
        self.db.add(RuntimeAuditEvent(
            session_id=session.id if session else None,
            analysis_id=session.analysis_id if session else None,
            operation=operation, device_serial=device, package_name=package,
            requested_by=self.requested_by, timestamp=_now(), result=result, error=error, command=command))

    # -- session --------------------------------------------------------
    def create_session(self, analysis) -> RuntimeSession:
        adapter_kind = "mock" if type(self.adb).__name__.lower().startswith("mock") else "adb"
        session = RuntimeSession(
            analysis_id=analysis.id, package_name=(analysis.manifest.package if analysis.manifest else None),
            apk_sha256=analysis.apk_sha256, session_state="CREATED", requested_by=self.requested_by,
            workspace_path=str(Path(settings.workspace_path) / analysis.apk_sha256 / "runtime"),
            metadata_={"adapter": adapter_kind})
        analysis.runtime_sessions.append(session)
        self.db.flush()
        self._audit(session, "CREATE", "OK")
        return session

    def select_device(self, session: RuntimeSession, serial: str) -> dict:
        devices = self.adb.list_devices() if self.adb.available else []
        match = next((d for d in devices if d.serial == serial), None)
        if match is None:
            session.error = f"device {serial} not attached"
            self._audit(session, "SELECT_DEVICE", "FAILED", device=serial, error=session.error)
            return {"status": "FAILED", "error": session.error}
        enriched = self.adb.enrich_device(match)
        device = RuntimeDevice(
            serial=enriched.serial, state=enriched.state, model=enriched.model, manufacturer=enriched.manufacturer,
            android_version=enriched.android_version, sdk_version=enriched.sdk_version,
            architecture=enriched.architecture, abi=enriched.abi, rooted=enriched.rooted,
            is_emulator=enriched.is_emulator, metadata_={})
        self.db.add(device)
        self.db.flush()
        session.device_id = device.id
        session.device_serial = serial
        session.session_state = "DEVICE_SELECTED"
        self._audit(session, "SELECT_DEVICE", "OK", device=serial)
        return {"status": "OK", "device": _device_dict(device)}

    def install(self, session: RuntimeSession, apk_path: str) -> dict:
        session.install_requested = True
        session.session_state = "INSTALL_REQUESTED"
        if not session.device_serial:
            return self._fail(session, "INSTALL", "no device selected")
        apk = Path(apk_path)
        if not apk.is_file():
            return self._fail(session, "INSTALL", f"APK not found: {apk_path}", device=session.device_serial)
        digest = hashlib.sha256(apk.read_bytes()).hexdigest()
        if session.apk_sha256 and digest != session.apk_sha256:
            return self._fail(session, "INSTALL", "APK SHA-256 mismatch with analysis",
                              device=session.device_serial)
        result = self.adb.install(session.device_serial, str(apk))
        if not result.ok or "Success" not in (result.stdout + result.stderr):
            return self._fail(session, "INSTALL", result.error or result.stderr.strip() or "adb install failed",
                              device=session.device_serial, command=" ".join(result.command))
        session.session_state = "INSTALLED"
        self._audit(session, "INSTALL", "OK", device=session.device_serial, package=session.package_name,
                    command=" ".join(result.command))
        return {"status": "OK", "sha256": digest}

    def uninstall(self, session: RuntimeSession) -> dict:
        session.uninstall_requested = True
        if not (session.device_serial and session.package_name):
            return self._fail(session, "UNINSTALL", "device and package required")
        result = self.adb.uninstall(session.device_serial, session.package_name)
        status = "OK" if result.ok else "FAILED"
        self._audit(session, "UNINSTALL", status, device=session.device_serial, package=session.package_name,
                    error=None if result.ok else result.stderr, command=" ".join(result.command))
        return {"status": status}

    def launch(self, session: RuntimeSession, activity: str | None = None) -> dict:
        session.launch_requested = True
        session.session_state = "LAUNCH_REQUESTED"
        if not (session.device_serial and session.package_name):
            return self._fail(session, "LAUNCH", "device and package required")
        result = self.adb.launch(session.device_serial, session.package_name, activity)
        if not result.ok:
            return self._fail(session, "LAUNCH", result.error or result.stderr.strip() or "launch failed",
                              device=session.device_serial, package=session.package_name)
        session.session_state = "RUNNING"
        session.metadata_ = {**(session.metadata_ or {}), "launch_activity": activity, "launch_command": " ".join(result.command)}
        self._audit(session, "LAUNCH", "OK", device=session.device_serial, package=session.package_name,
                    command=" ".join(result.command))
        return {"status": "OK", "activity": activity}

    def stop(self, session: RuntimeSession) -> dict:
        session.session_state = "STOPPING"
        result = self.adb.force_stop(session.device_serial, session.package_name) if session.device_serial else None
        session.session_state = "COMPLETED"
        session.ended_at = _now()
        ok = result.ok if result else False
        self._audit(session, "STOP", "OK" if ok else "FAILED", device=session.device_serial,
                    package=session.package_name, command=" ".join(result.command) if result else None)
        return {"status": "OK" if ok else "FAILED"}

    def collect_logcat(self, session: RuntimeSession) -> dict:
        if not session.device_serial:
            return self._fail(session, "LOGCAT_START", "no device selected")
        self._audit(session, "LOGCAT_START", "OK", device=session.device_serial)
        result = self.adb.logcat_dump(session.device_serial)
        if not result.ok:
            self._audit(session, "LOGCAT_STOP", "FAILED", device=session.device_serial, error=result.error)
            return {"status": "FAILED", "error": result.error}
        text = result.stdout[: settings.runtime_logcat_max_bytes]
        events = parse_logcat(text, settings.runtime_logcat_max_lines)
        for ev in events:
            session.events.append(RuntimeEvent(
                event_type="LOGCAT", pid=ev["pid"], priority=ev["priority"], tag=mask(ev["tag"], 200),
                message=mask(ev["message"]) or "", timestamp=_now()))
        self._audit(session, "LOGCAT_STOP", "OK", device=session.device_serial)
        return {"status": "OK", "events": len(events)}

    def collect_processes(self, session: RuntimeSession) -> dict:
        if not session.device_serial:
            return self._fail(session, "PROCESS", "no device selected")
        result = self.adb.processes(session.device_serial)
        if not result.ok:
            return self._fail(session, "PROCESS", result.error or "ps failed", device=session.device_serial)
        processes = parse_ps(result.stdout)
        cap = settings.runtime_max_processes
        for proc in processes[:cap]:
            session.processes.append(RuntimeProcess(pid=proc["pid"], name=proc["name"], uid=proc.get("uid"),
                                                    metadata_={}))
        truncated = max(0, len(processes) - cap)
        if truncated:
            session.metadata_ = {**(session.metadata_ or {}),
                                 "processes_truncated": truncated}
        self._audit(session, "PROCESS", "OK", device=session.device_serial)
        return {"status": "OK", "processes": min(len(processes), cap), "truncated": truncated}

    def frida_attach(self, session: RuntimeSession, profile_names: list[str], duration: int = 10) -> dict:
        if not self.frida.available:
            return self._fail(session, "FRIDA_ATTACH", "frida unavailable")
        if not (session.device_serial and session.package_name):
            return self._fail(session, "FRIDA_ATTACH", "device and package required")
        profiles = profiles_by_name(profile_names) or list()
        if not profiles:
            return self._fail(session, "FRIDA_ATTACH", "no valid hook profiles selected")
        session.instrumentation_enabled = True
        session.session_state = "INSTRUMENTING"
        script = build_frida_script(profiles, settings.runtime_observation_limit)
        self._audit(session, "FRIDA_ATTACH", "OK", device=session.device_serial, package=session.package_name)
        status, observations = self.frida.attach_and_observe(session.device_serial, session.package_name, script,
                                                             duration=duration)
        self._persist_observations(session, observations)
        self._audit(session, "FRIDA_DETACH", "OK" if status.startswith("COMPLETED") else "FAILED",
                    device=session.device_serial, package=session.package_name,
                    error=None if status.startswith("COMPLETED") else status)
        return {"status": status, "observations": len(observations)}

    def record_observations(self, session: RuntimeSession, observations) -> int:
        """Explicitly ingest observations (used by adapters/tests). Masked + bounded."""
        return self._persist_observations(session, observations)

    def observe_package_adb(self, session: RuntimeSession, package: str | None = None) -> dict:
        """Collect LIVE, ADB-only observations SCOPED TO THE SELECTED PACKAGE only
        (prompt 23 §4/§15) — process presence + package-filtered logcat component
        dispatch. Never attaches to unrelated processes; sensitive lines are masked;
        bounds are enforced and TRUNCATED is recorded. ADB observations carry
        source=ADB (never Frida) so LIVE provenance stays accurate."""
        package = package or session.package_name
        serial = session.device_serial
        if not (serial and package):
            return self._fail(session, "OBSERVE", "device and package required")
        self._audit(session, "OBSERVE", "OK", device=serial, package=package)
        limit = settings.runtime_observation_limit
        added = 0
        truncated = 0

        # 1) process presence for THIS package only (metadata only; no user data)
        pidres = self.adb.pidof(serial, package)
        pids = [p for p in (pidres.stdout or "").split() if p.strip().isdigit()] if pidres.ok else []
        for pid in pids:
            if added >= limit:
                truncated += 1
                continue
            session.observations.append(RuntimeObservation(
                observation_type="PROCESS", package_name=package, process_id=int(pid),
                source="ADB", confidence="HIGH", taxonomy="PROCESS_LIFECYCLE", redacted=False,
                arguments_summary=None, timestamp=_now(),
                metadata_={"pid": pid, "adapter": "adb", "live": True}))
            added += 1

        # 2) package-scoped logcat: only lines mentioning the selected package are
        #    considered — unrelated apps are never observed. Component/activity
        #    dispatch is derived from ActivityTaskManager "Displayed <pkg>/<act>".
        logcat = self.adb.logcat_dump(serial)
        seen: set[str] = set()
        if logcat.ok:
            for line in logcat.stdout.splitlines():
                if package not in line:
                    continue
                cls, method, taxo = _parse_component_line(line, package)
                key = f"{cls}.{method}"
                if key in seen:
                    continue
                seen.add(key)
                if added >= limit:
                    truncated += 1
                    break
                session.observations.append(RuntimeObservation(
                    observation_type="COMPONENT", package_name=package, class_name=cls, method_name=method,
                    source="ADB", confidence="MEDIUM", taxonomy=taxo, redacted=True,
                    arguments_summary=mask(line, 200), timestamp=_now(),
                    metadata_={"adapter": "adb", "live": True, "logcat": True}))
                added += 1
        if truncated:
            session.metadata_ = {**(session.metadata_ or {}), "observations_truncated": truncated}
        return {"status": "OK", "observations": added, "running": bool(pids), "truncated": truncated}

    # -- artifacts ------------------------------------------------------
    def persist_artifact(self, session: RuntimeSession, kind: str, content: str, redacted: bool = True) -> dict:
        """Persist a bounded, redacted, security-relevant artifact with SHA-256.
        Reaching the artifact bound records TRUNCATED; nothing is silently dropped."""
        from app.models.runtime import RuntimeArtifact
        if len(session.artifacts) >= settings.runtime_max_artifacts:
            session.metadata_ = {**(session.metadata_ or {}),
                                 "artifacts_truncated": (session.metadata_ or {}).get("artifacts_truncated", 0) + 1}
            return {"status": "TRUNCATED", "reason": "runtime_max_artifacts reached"}
        body = mask(content) if redacted else content
        body = (body or "")[: settings.runtime_artifact_max_bytes]
        digest = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()
        path = str(Path(session.workspace_path or ".") / "artifacts" / f"{kind}-{digest[:12]}.txt")
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        except OSError:
            pass  # persistence is best-effort; the row still records sha256/size/redaction
        session.artifacts.append(RuntimeArtifact(kind=kind, path=path, sha256=digest, size_bytes=len(body)))
        self._audit(session, "ARTIFACT", "OK", device=session.device_serial, package=session.package_name)
        return {"status": "OK", "kind": kind, "sha256": digest, "size": len(body), "redacted": redacted}

    # -- full validation lifecycle -------------------------------------
    def validate(self, analysis, device: str, apk_path: str | None = None,
                 profiles: list[str] | None = None, duration: int = 10, activity: str | None = None) -> dict:
        """Explicit end-to-end live validation: select device → verify APK hash →
        install → launch → observe (ADB + optional Frida) → collect → stop →
        correlate. Never auto-runs; returns LIVE_RUNTIME_UNAVAILABLE when no
        device is attached. All operations are audited."""
        session = self.create_session(analysis)
        sel = self.select_device(session, device)
        if sel["status"] != "OK":
            self._audit(session, "VALIDATE", "FAILED", device=device, error="LIVE_RUNTIME_UNAVAILABLE")
            return {"status": "LIVE_RUNTIME_UNAVAILABLE", "session_id": str(session.id),
                    "reason": sel.get("error", "device not attached"), "mode": "UNAVAILABLE"}
        steps: dict = {"select_device": sel}
        if apk_path:
            steps["install"] = self.install(session, apk_path)
        steps["launch"] = self.launch(session, activity)
        steps["logcat"] = self.collect_logcat(session)
        steps["processes"] = self.collect_processes(session)
        # LIVE, package-scoped ADB observations (targets only the selected app).
        steps["observe"] = self.observe_package_adb(session)
        frida_status = "UNAVAILABLE"
        if self.frida.available and profiles:
            fr = self.frida_attach(session, profiles, duration)
            frida_status = fr.get("status", "UNAVAILABLE")
            steps["frida"] = fr
        else:
            self._audit(session, "FRIDA_ATTACH", "SKIPPED", device=session.device_serial,
                        error="frida unavailable — continuing ADB-only")
        self.stop(session)
        # persist a bounded correlation-summary artifact + correlate
        from app.analysis.runtime_validation import build_runtime_validation
        run = build_runtime_validation(self.db, analysis, requested_by=self.requested_by)
        self.persist_artifact(session, "runtime_event_summary",
                              f"observations={run.observation_count} correlations={run.correlation_count} "
                              f"mode={run.mode}")
        self._audit(session, "VALIDATE", "OK", device=session.device_serial, package=session.package_name)
        return {"status": "OK", "session_id": str(session.id), "mode": run.mode,
                "frida": frida_status, "observations": run.observation_count,
                "correlations": run.correlation_count, "live_claims": run.live_claim_count,
                "corroborated_findings": run.corroborated_finding_count, "steps": steps}

    def finalize(self, session: RuntimeSession, analysis=None) -> dict:
        """Stop the session (if running) and (re)build the runtime validation run."""
        if session.session_state not in ("COMPLETED", "FAILED"):
            self.stop(session)
        result = {"status": "OK", "session_state": session.session_state}
        if analysis is not None:
            from app.analysis.runtime_validation import build_runtime_validation
            run = build_runtime_validation(self.db, analysis, requested_by=self.requested_by)
            result["mode"] = run.mode
            result["correlations"] = run.correlation_count
        self._audit(session, "FINALIZE", "OK", device=session.device_serial, package=session.package_name)
        return result

    def _persist_observations(self, session, observations) -> int:
        limit = settings.runtime_observation_limit
        added = 0
        for obs in observations:
            if added >= limit:
                break
            session.observations.append(RuntimeObservation(
                observation_type=obs.observation_type, class_name=obs.class_name, method_name=obs.method_name,
                native_library=obs.native_library, symbol=obs.symbol,
                arguments_summary=mask(obs.arguments_summary), return_summary=mask(obs.return_summary),
                package_name=session.package_name, source="FRIDA", confidence="MEDIUM",
                timestamp=_now(), metadata_=dict(getattr(obs, "metadata", {}) or {})))
            added += 1
        return added

    def _fail(self, session, operation, reason, device=None, package=None, command=None) -> dict:
        session.error = reason
        session.session_state = "FAILED"
        self._audit(session, operation, "FAILED", device=device or session.device_serial,
                    package=package or session.package_name, error=reason, command=command)
        return {"status": "FAILED", "error": reason}


_DISPLAYED_RE = re.compile(r"Displayed\s+([\w.]+)/([\w.$]+)")
_CMP_RE = re.compile(r"cmp=([\w.]+)/([\w.$]+)")


def _parse_component_line(line: str, package: str) -> tuple[str, str, str]:
    """Derive (class, method, taxonomy) from a package-scoped logcat line. Only
    structural component/activity dispatch is recognised — never argument values.
    Returns a generic COMPONENT_DISPATCH when the specific shape is unknown."""
    m = _DISPLAYED_RE.search(line) or _CMP_RE.search(line)
    if m and m.group(1) == package:
        activity = m.group(2)
        cls = activity if activity.startswith(package) else (package + activity if activity.startswith(".")
                                                             else f"{package}.{activity}")
        return cls, "onCreate", "ACTIVITY_LAUNCH"
    lower = line.lower()
    if "broadcast" in lower:
        return package, "onReceive", "BROADCAST_DISPATCH"
    if "service" in lower:
        return package, "onStartCommand", "SERVICE_START"
    if "provider" in lower:
        return package, "query", "CONTENT_PROVIDER_ACCESS"
    return package, "dispatch", "COMPONENT_DISPATCH"


def _device_dict(device: RuntimeDevice) -> dict:
    return {"serial": device.serial, "state": device.state, "model": device.model,
            "android_version": device.android_version, "sdk_version": device.sdk_version,
            "abi": device.abi, "is_emulator": device.is_emulator, "rooted": device.rooted}

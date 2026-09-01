"""Runtime Lab CLI (explicit, auditable). Registered under `androidsecforge runtime`.

Every operation is user-invoked; nothing installs/launches/connects/instruments
automatically. With no device attached, operations report honest FAILED/UNAVAILABLE.
"""

from __future__ import annotations

import json
from uuid import UUID


def _db():
    from app.db.session import SessionLocal, initialize_database

    initialize_database()
    return SessionLocal()


def _load_analysis(db, analysis_id):
    from app.models.analysis import Analysis

    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise ValueError("Analysis not found")
    return analysis


def _load_session(db, session_id):
    from app.models.runtime import RuntimeSession

    session = db.get(RuntimeSession, session_id)
    if session is None:
        raise ValueError("Runtime session not found")
    return session


def _print(data, as_json, human):
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    else:
        human(data)


def add_parser(commands) -> None:
    runtime = commands.add_parser("runtime", help="Runtime Lab (ADB / Frida) — explicit, optional")
    sub = runtime.add_subparsers(dest="runtime_command", required=True)

    sub.add_parser("doctor").add_argument("--json", action="store_true", dest="as_json")
    sub.add_parser("devices").add_argument("--json", action="store_true", dest="as_json")

    dev = sub.add_parser("device", help="Real-device capability discovery (read-only, no attach)")
    dev.add_argument("--serial", dest="serial", default=None)
    dev.add_argument("--json", action="store_true", dest="as_json")

    di = sub.add_parser("device-info"); di.add_argument("serial"); di.add_argument("--json", action="store_true", dest="as_json")

    se = sub.add_parser("sessions"); se.add_argument("analysis_id", type=UUID); se.add_argument("--json", action="store_true", dest="as_json")

    cr = sub.add_parser("session")
    cr.add_argument("--analysis", dest="analysis_id", type=UUID, required=True)
    cr.add_argument("--device", dest="device", default=None)
    cr.add_argument("--json", action="store_true", dest="as_json")

    inst = sub.add_parser("install")
    inst.add_argument("--analysis", dest="analysis_id", type=UUID, required=True)
    inst.add_argument("--device", dest="device", required=True)
    inst.add_argument("--json", action="store_true", dest="as_json")

    for name in ("uninstall", "stop", "logcat", "processes", "observations"):
        s = sub.add_parser(name); s.add_argument("--session", dest="session_id", type=UUID, required=True)
        s.add_argument("--json", action="store_true", dest="as_json")

    la = sub.add_parser("launch"); la.add_argument("--session", dest="session_id", type=UUID, required=True)
    la.add_argument("--activity", dest="activity", default=None); la.add_argument("--json", action="store_true", dest="as_json")

    frida = sub.add_parser("frida"); frida_sub = frida.add_subparsers(dest="frida_command", required=True)
    fst = frida_sub.add_parser("status"); fst.add_argument("--device", dest="device", default=None); fst.add_argument("--json", action="store_true", dest="as_json")
    fat = frida_sub.add_parser("attach"); fat.add_argument("--session", dest="session_id", type=UUID, required=True)
    fat.add_argument("--profiles", dest="profiles", default="lifecycle,intents,webview"); fat.add_argument("--duration", type=int, default=10)
    fat.add_argument("--json", action="store_true", dest="as_json")
    fdt = frida_sub.add_parser("detach"); fdt.add_argument("--session", dest="session_id", type=UUID, required=True); fdt.add_argument("--json", action="store_true", dest="as_json")

    co = sub.add_parser("correlate"); co.add_argument("--analysis", dest="analysis_id", type=UUID, required=True)
    co.add_argument("--json", action="store_true", dest="as_json")

    # --- live runtime validation (prompt 21) ---
    va = sub.add_parser("validate", help="Explicit end-to-end live validation (never auto-runs)")
    va.add_argument("--analysis", dest="analysis_id", type=UUID, required=True)
    va.add_argument("--device", dest="device", required=True)
    va.add_argument("--apk", dest="apk_path", default=None)
    va.add_argument("--profiles", dest="profiles", default="lifecycle,intents,webview")
    va.add_argument("--duration", type=int, default=10)
    va.add_argument("--activity", dest="activity", default=None)
    va.add_argument("--json", action="store_true", dest="as_json")

    for name in ("observe", "events", "artifacts"):
        s = sub.add_parser(name); s.add_argument("--session", dest="session_id", type=UUID, required=True)
        s.add_argument("--json", action="store_true", dest="as_json")

    vf = sub.add_parser("validate-finding")
    vf.add_argument("--analysis", dest="analysis_id", type=UUID, required=True)
    vf.add_argument("--finding", dest="finding", required=True)
    vf.add_argument("--json", action="store_true", dest="as_json")

    vp = sub.add_parser("validate-path")
    vp.add_argument("--analysis", dest="analysis_id", type=UUID, required=True)
    vp.add_argument("--from", dest="from_query", required=True)
    vp.add_argument("--to", dest="to_query", default="")
    vp.add_argument("--json", action="store_true", dest="as_json")

    ex = sub.add_parser("explain")
    ex.add_argument("--analysis", dest="analysis_id", type=UUID, required=True)
    ex.add_argument("--subject", dest="subject", required=True)
    ex.add_argument("--json", action="store_true", dest="as_json")

    fi = sub.add_parser("finalize")
    fi.add_argument("--session", dest="session_id", type=UUID, required=True)
    fi.add_argument("--json", action="store_true", dest="as_json")


def dispatch(args) -> None:
    cmd = args.runtime_command
    if cmd == "doctor":
        from app.runtime.capability import runtime_capabilities
        caps = runtime_capabilities()
        _print(caps, args.as_json, lambda c: [print(f"  {x['name']:<14} {x['availability']:<14} {x.get('version') or ''}  {x['reason']}") for x in c])
        return
    if cmd == "devices":
        _runtime_devices(args); return
    if cmd == "device":
        _device_capability(args); return
    if cmd == "device-info":
        _device_info(args); return
    if cmd == "sessions":
        _sessions(args); return
    if cmd == "session":
        _create_session(args); return
    if cmd == "install":
        _install(args); return
    if cmd in ("uninstall", "launch", "stop", "logcat", "processes", "observations"):
        _session_op(args, cmd); return
    if cmd == "frida":
        _frida(args); return
    if cmd == "correlate":
        _correlate(args); return
    if cmd == "validate":
        _validate(args); return
    if cmd in ("observe", "events", "artifacts"):
        _session_listing(args, cmd); return
    if cmd == "validate-finding":
        _validate_finding(args); return
    if cmd == "validate-path":
        _validate_path(args); return
    if cmd == "explain":
        _explain(args); return
    if cmd == "finalize":
        _finalize(args); return


def _runtime_devices(args) -> None:
    from app.runtime.adb import AdbAdapter
    from app.models.runtime import RuntimeDevice
    adb = AdbAdapter()
    devices = adb.list_devices() if adb.available else []
    rows = []
    db = _db()
    try:
        for d in devices:
            d = adb.enrich_device(d)
            db.add(RuntimeDevice(serial=d.serial, state=d.state, model=d.model, manufacturer=d.manufacturer,
                                 android_version=d.android_version, sdk_version=d.sdk_version, architecture=d.architecture,
                                 abi=d.abi, rooted=d.rooted, is_emulator=d.is_emulator, metadata_={}))
            rows.append({"serial": d.serial, "state": d.state, "model": d.model, "android_version": d.android_version,
                         "abi": d.abi, "is_emulator": d.is_emulator})
        db.commit()
    finally:
        db.close()
    _print({"adb_available": adb.available, "devices": rows}, args.as_json,
           lambda x: (print(f"adb_available={x['adb_available']} devices={len(x['devices'])}"),
                      [print(f"  {r['serial']} {r['state']} {r['model'] or ''} {r['abi'] or ''}") for r in x["devices"]]))


def _device_capability(args) -> None:
    from app.runtime.device import discover_device
    data = discover_device(getattr(args, "serial", None))
    _print(data, args.as_json, lambda x: (
        print(f"adb={x['adb']} device={x['device_state']} serial={x.get('serial')}"),
        print(f"frida_host={x['frida_host']} frida_server={x['frida_server']}"),
        print(f"runtime-validation={x['runtime_validation']} native-runtime-correlation={x['native_runtime_correlation']}"),
        [print(f"  {k}={v}") for k, v in (x.get('device') or {}).items()] if x.get('device') else None,
        print(f"reason: {x.get('reason') or x.get('note')}")))


def _device_info(args) -> None:
    from app.runtime.adb import AdbAdapter, Device
    adb = AdbAdapter()
    devices = adb.list_devices() if adb.available else []
    match = next((d for d in devices if d.serial == args.serial), None)
    if match is None:
        _print({"status": "NOT_FOUND", "serial": args.serial}, args.as_json,
               lambda x: print(f"device {x['serial']} not attached"))
        return
    d = adb.enrich_device(match)
    data = {"serial": d.serial, "state": d.state, "model": d.model, "manufacturer": d.manufacturer,
            "android_version": d.android_version, "sdk_version": d.sdk_version, "abi": d.abi,
            "is_emulator": d.is_emulator, "rooted": d.rooted}
    _print(data, args.as_json, lambda x: [print(f"  {k}={v}") for k, v in x.items()])


def _sessions(args) -> None:
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        rows = [{"id": str(s.id), "state": s.session_state, "device": s.device_serial, "package": s.package_name,
                 "instrumented": s.instrumentation_enabled, "error": s.error} for s in analysis.runtime_sessions]
        _print(rows, args.as_json, lambda r: (print(f"sessions={len(r)}"),
               [print(f"  {x['id']} {x['state']} device={x['device']} pkg={x['package']}") for x in r]))
    finally:
        db.close()


def _create_session(args) -> None:
    from app.runtime.session import RuntimeLab
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        lab = RuntimeLab(db)
        session = lab.create_session(analysis)
        result = {"session_id": str(session.id), "state": session.session_state, "package": session.package_name}
        if args.device:
            result["device"] = lab.select_device(session, args.device)
        db.commit()
        _print(result, args.as_json, lambda x: print(f"session_id={x['session_id']} state={x['state']}"
                                                     + (f" device={args.device}" if args.device else "")))
    finally:
        db.close()


def _install(args) -> None:
    from pathlib import Path
    from app.runtime.session import RuntimeLab
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        from app.models.apk import APKArtifact
        apk = db.get(APKArtifact, analysis.apk_id)
        lab = RuntimeLab(db)
        session = lab.create_session(analysis)
        sel = lab.select_device(session, args.device)
        result = {"session_id": str(session.id), "select": sel}
        if sel["status"] == "OK":
            result["install"] = lab.install(session, apk.storage_path if apk else "")
        db.commit()
        _print(result, args.as_json, lambda x: print(json.dumps(x, indent=2, default=str)))
    finally:
        db.close()


def _session_op(args, op) -> None:
    from app.runtime.session import RuntimeLab
    db = _db()
    try:
        session = _load_session(db, args.session_id)
        lab = RuntimeLab(db)
        if op == "observations":
            rows = [{"type": o.observation_type, "class": o.class_name, "method": o.method_name,
                     "symbol": o.symbol, "args": o.arguments_summary, "ret": o.return_summary,
                     "source": o.source, "confidence": o.confidence, "timestamp": o.timestamp.isoformat()}
                    for o in session.observations]
            _print(rows, args.as_json, lambda r: (print(f"observations={len(r)}"),
                   [print(f"  [{x['type']}] {x['class'] or ''}.{x['method'] or ''}{x['symbol'] or ''} src={x['source']}") for x in r]))
            return
        result = {
            "uninstall": lambda: lab.uninstall(session),
            "launch": lambda: lab.launch(session, getattr(args, "activity", None)),
            "stop": lambda: lab.stop(session),
            "logcat": lambda: lab.collect_logcat(session),
            "processes": lambda: lab.collect_processes(session),
        }[op]()
        db.commit()
        _print(result, args.as_json, lambda x: print(json.dumps(x, default=str)))
    finally:
        db.close()


def _frida(args) -> None:
    if args.frida_command == "status":
        from app.runtime.frida import FridaAdapter
        st = FridaAdapter().status(args.device)
        data = {"available": st.cli_path is not None or st.python_binding == "AVAILABLE", "version": st.version,
                "cli_path": st.cli_path, "python_binding": st.python_binding, "server_on_device": st.server_on_device,
                "reason": st.reason}
        _print(data, args.as_json, lambda x: [print(f"  {k}={v}") for k, v in x.items()])
        return
    from app.runtime.session import RuntimeLab
    db = _db()
    try:
        session = _load_session(db, args.session_id)
        lab = RuntimeLab(db)
        if args.frida_command == "attach":
            result = lab.frida_attach(session, [p.strip() for p in args.profiles.split(",") if p.strip()], args.duration)
        else:  # detach
            session.instrumentation_enabled = False
            lab._audit(session, "FRIDA_DETACH", "OK", device=session.device_serial, package=session.package_name)
            result = {"status": "OK"}
        db.commit()
        _print(result, args.as_json, lambda x: print(json.dumps(x, default=str)))
    finally:
        db.close()


def _correlate(args) -> None:
    from app.analysis.runtime_correlation import correlate_runtime
    from app.analysis.runtime_validation import build_runtime_validation
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        legacy = correlate_runtime(analysis)          # prompt-12 static↔runtime correlation
        run = build_runtime_validation(db, analysis)  # prompt-21 persisted correlation run
        db.commit()
        summary = {"legacy_correlation": legacy, "runtime_validation": {
            "mode": run.mode, "correlations": run.correlation_count, "live_claims": run.live_claim_count,
            "corroborated_findings": run.corroborated_finding_count, "fingerprint": run.fingerprint}}
        _print(summary, args.as_json, lambda x: print(json.dumps(x, indent=2, default=str)))
    finally:
        db.close()


def _validate(args) -> None:
    from app.runtime.session import RuntimeLab
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        lab = RuntimeLab(db)
        profiles = [p.strip() for p in (args.profiles or "").split(",") if p.strip()]
        result = lab.validate(analysis, args.device, apk_path=args.apk_path, profiles=profiles,
                              duration=args.duration, activity=args.activity)
        db.commit()
        _print(result, args.as_json, lambda x: print(json.dumps(x, indent=2, default=str)))
    finally:
        db.close()


def _session_listing(args, kind) -> None:
    db = _db()
    try:
        session = _load_session(db, args.session_id)
        if kind == "observe":
            rows = [{"type": o.observation_type, "taxonomy": o.taxonomy, "class": o.class_name,
                     "method": o.method_name, "symbol": o.symbol, "source": o.source,
                     "confidence": o.confidence, "redacted": o.redacted} for o in session.observations]
            _print(rows, args.as_json, lambda r: (print(f"observations={len(r)}"),
                   [print(f"  [{x['taxonomy'] or x['type']}] {x['class'] or ''}.{x['method'] or ''}"
                          f"{x['symbol'] or ''} src={x['source']}") for x in r]))
        elif kind == "events":
            rows = [{"type": e.event_type, "tag": e.tag, "priority": e.priority, "message": e.message}
                    for e in session.events]
            _print(rows, args.as_json, lambda r: (print(f"events={len(r)}"),
                   [print(f"  [{x['type']}/{x['priority'] or ''}] {x['tag'] or ''}: {x['message'][:80]}")
                    for x in r[:100]]))
        else:  # artifacts
            rows = [{"kind": a.kind, "sha256": a.sha256, "size": a.size_bytes, "path": a.path}
                    for a in session.artifacts]
            _print(rows, args.as_json, lambda r: (print(f"artifacts={len(r)}"),
                   [print(f"  {x['kind']:<26} sha256={x['sha256']} size={x['size']}") for x in r]))
    finally:
        db.close()


def _validate_finding(args) -> None:
    from app.analysis.runtime_validation import runtime_explain
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        data = runtime_explain(analysis, args.finding)
        _print(data, args.as_json, lambda x: (print(f"RUNTIME VALIDATION for {x['subject']} (mode={x['mode']}):"),
               [print(f"  {i + 1}. [{s['step']}] {s['detail']}"
                      + (f" ({s.get('mode')})" if s.get('mode') else "")) for i, s in enumerate(x["chain"])],
               print(f"note: {x['note']}")))
    finally:
        db.close()


def _validate_path(args) -> None:
    from app.analysis.runtime_validation import runtime_validation_view
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        view = runtime_validation_view(analysis)
        fq, tq = args.from_query.lower(), (args.to_query or "").lower()
        matched = [c for c in view["correlations"]
                   if (fq in (c["subject_ref"] or "").lower() or fq in (c["detail"] or "").lower())
                   and (not tq or tq in (c["detail"] or "").lower() or tq in (c["subject_ref"] or "").lower())]
        data = {"mode": view["mode"], "from": args.from_query, "to": args.to_query,
                "count": len(matched), "correlations": matched, "note": view["note"]}
        _print(data, args.as_json, lambda x: (print(f"runtime path correlations={x['count']} (mode={x['mode']})"),
               [print(f"  {c['correlation_type']} {c['subject_type']} [{c['mode']}] {c['detail'][:80]}")
                for c in x["correlations"][:60]]))
    finally:
        db.close()


def _explain(args) -> None:
    from app.analysis.runtime_validation import runtime_explain
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        data = runtime_explain(analysis, args.subject)
        _print(data, args.as_json, lambda x: (print(f"EXPLAIN {x['subject']} (mode={x['mode']}):"),
               [print(f"  {i + 1}. [{s['step']}] {s['detail']}") for i, s in enumerate(x["chain"])],
               print(f"note: {x['note']}")))
    finally:
        db.close()


def _finalize(args) -> None:
    from app.runtime.session import RuntimeLab
    db = _db()
    try:
        session = _load_session(db, args.session_id)
        from app.models.analysis import Analysis
        analysis = db.get(Analysis, session.analysis_id)
        lab = RuntimeLab(db)
        result = lab.finalize(session, analysis)
        db.commit()
        _print(result, args.as_json, lambda x: print(json.dumps(x, indent=2, default=str)))
    finally:
        db.close()

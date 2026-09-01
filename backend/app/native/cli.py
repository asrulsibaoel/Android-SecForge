"""CLI for deep native / Ghidra correlation (prompt 20). Registered as
`native-deep`. Read-only views over persisted native-deep evidence, plus an
opt-in `analyze` that (re)builds the deep-native projection for one analysis.

Ghidra is optional; ELF-only mode is fully functional. No exploitability is
asserted; UNKNOWN_NATIVE_TARGET is preserved."""

from __future__ import annotations

import json
from uuid import UUID


def _db():
    from app.db.session import SessionLocal, initialize_database

    initialize_database()
    return SessionLocal()


def _load_analysis(db, analysis_id):
    from app.models.analysis import Analysis

    a = db.get(Analysis, analysis_id)
    if a is None:
        raise ValueError(f"Analysis not found: {analysis_id}")
    return a


def _emit(data, as_json, human):
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    else:
        human(data)


def add_parser(commands) -> None:
    nd = commands.add_parser("native-deep", help="Deep native / Ghidra correlation (offline; Ghidra optional)")
    sub = nd.add_subparsers(dest="native_deep_command", required=True)

    sub.add_parser("doctor").add_argument("--json", action="store_true", dest="as_json")

    an = sub.add_parser("analyze", help="Build/refresh the deep-native projection (uses Ghidra if enabled)")
    an.add_argument("analysis_id", type=UUID)
    an.add_argument("--json", action="store_true", dest="as_json")

    for name in ("summary", "binaries", "functions", "symbols", "imports", "exports",
                 "jni", "calls", "sinks", "evidence", "cve"):
        s = sub.add_parser(name)
        s.add_argument("analysis_id", type=UUID)
        s.add_argument("--json", action="store_true", dest="as_json")

    pa = sub.add_parser("paths", help="Java→JNI→native→API path investigation (bounded)")
    pa.add_argument("analysis_id", type=UUID)
    pa.add_argument("--from", dest="from_query", required=True)
    pa.add_argument("--to", dest="to_query", default="")
    pa.add_argument("--max-depth", dest="max_depth", type=int, default=None)
    pa.add_argument("--json", action="store_true", dest="as_json")

    ex = sub.add_parser("explain")
    ex.add_argument("analysis_id", type=UUID)
    ex.add_argument("target")
    ex.add_argument("--json", action="store_true", dest="as_json")

    xp = sub.add_parser("export")
    xp.add_argument("analysis_id", type=UUID)
    xp.add_argument("--format", dest="fmt", default="json", choices=["json", "markdown", "md"])


def dispatch(args) -> None:
    {"doctor": _doctor, "analyze": _analyze, "summary": _summary, "binaries": _binaries,
     "functions": _functions, "symbols": _symbols, "imports": _imports, "exports": _exports,
     "jni": _jni, "calls": _calls, "sinks": _sinks, "evidence": _evidence, "cve": _cve,
     "paths": _paths, "explain": _explain, "export": _export}[args.native_deep_command](args)


def _view(db, args):
    from app.native.deep_native import native_deep_view
    return native_deep_view(_load_analysis(db, args.analysis_id))


def _doctor(args) -> None:
    from app.native.ghidra_adapter import capability
    cap = capability()
    _emit(cap, getattr(args, "as_json", False), lambda c: (
        print(f"ghidra: {c['state']} — {c['reason']}"),
        print(f"headless={c.get('headless')} version={c.get('version')} path={c.get('path')}")))


def _analyze(args) -> None:
    from app.native.deep_native import build_deep_native
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        run = build_deep_native(db, analysis, requested_by="cli")
        db.commit()
        data = {"mode": run.mode, "ghidra_capability": run.ghidra_capability, "binaries": run.binaries_count,
                "functions": run.functions_count, "jni": run.jni_count, "call_edges": run.call_edge_count,
                "api_observations": run.api_observation_count, "unresolved_targets": run.unresolved_target_count,
                "fingerprint": run.fingerprint}
        _emit(data, args.as_json, lambda x: (
            print(f"mode={x['mode']} ghidra={x['ghidra_capability']}"),
            print(f"binaries={x['binaries']} functions={x['functions']} jni={x['jni']} "
                  f"call_edges={x['call_edges']} api_observations={x['api_observations']}"),
            print(f"unresolved_targets={x['unresolved_targets']} fingerprint={x['fingerprint']}")))
    finally:
        db.close()


def _summary(args) -> None:
    db = _db()
    try:
        view = _view(db, args)
        data = {"capability": view["capability"], "summary": view["summary"], "fingerprint": view["fingerprint"]}
        _emit(data, args.as_json, lambda x: (
            print(f"mode={x['capability']['mode']} ghidra={x['capability']['ghidra']}"),
            print(f"binaries={x['summary']['binaries']} functions={x['summary']['functions']} "
                  f"jni={x['summary']['jni_bindings']} call_edges={x['summary']['call_edges']} "
                  f"api_observations={x['summary']['api_observations']}"),
            print(f"resolved_jni={x['summary']['resolved_jni']} unresolved_jni={x['summary']['unresolved_jni']} "
                  f"unresolved_targets={x['summary']['unresolved_targets']}"),
            print(f"by_function_type={x['summary']['by_function_type']}"),
            print(f"fingerprint={x['fingerprint']}")))
    finally:
        db.close()


def _binaries(args) -> None:
    db = _db()
    try:
        rows = _view(db, args)["binaries"]
        _emit(rows, args.as_json, lambda r: (print(f"binaries={len(r)}"),
              [print(f"  {b['filename']:<28} {b['architecture'] or b['abi'] or '?':<10} "
                     f"stripped={b['stripped']} source={b['source']}") for b in r]))
    finally:
        db.close()


def _functions(args) -> None:
    db = _db()
    try:
        rows = _view(db, args)["functions"]
        _emit(rows, args.as_json, lambda r: (print(f"functions={len(r)}"),
              [print(f"  [{f['function_type']:<16}] {f['name']:<40} src={f['source']} "
                     f"exp={f['is_exported']} imp={f['is_imported']}") for f in r[:200]]))
    finally:
        db.close()


def _symbols(args) -> None:
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        rows = [{"name": s.name, "kind": s.kind, "source": s.source} for s in analysis.native_deep_symbols]
        _emit(rows, args.as_json, lambda r: (print(f"symbols={len(r)}"),
              [print(f"  {s['kind']:<12} {s['name']:<40} src={s['source']}") for s in r[:200]]))
    finally:
        db.close()


def _imports(args) -> None:
    db = _db()
    try:
        rows = [f for f in _view(db, args)["functions"] if f["is_imported"]]
        _emit(rows, args.as_json, lambda r: (print(f"imports={len(r)}"),
              [print(f"  {f['name']}") for f in r[:300]]))
    finally:
        db.close()


def _exports(args) -> None:
    db = _db()
    try:
        rows = [f for f in _view(db, args)["functions"] if f["is_exported"]]
        _emit(rows, args.as_json, lambda r: (print(f"exports={len(r)}"),
              [print(f"  {f['name']} ({f['function_type']})") for f in r[:300]]))
    finally:
        db.close()


def _jni(args) -> None:
    db = _db()
    try:
        rows = _view(db, args)["jni_bindings"]
        _emit(rows, args.as_json, lambda r: (print(f"jni_bindings={len(r)}"),
              [print(f"  {j['java_class']}.{j['java_method']} → "
                     f"{j['native_symbol'] or j['native_target'] or 'UNKNOWN_NATIVE_TARGET'} "
                     f"[{j['registration_type']}/{j['state']}]") for j in r]))
    finally:
        db.close()


def _calls(args) -> None:
    db = _db()
    try:
        rows = _view(db, args)["call_edges"]
        _emit(rows, args.as_json, lambda r: (print(f"call_edges={len(r)}"),
              [print(f"  {e['src']} -> {e['dst']} (resolved={e['resolved']}, src={e['source']})")
               for e in r[:200]]))
    finally:
        db.close()


def _sinks(args) -> None:
    db = _db()
    try:
        rows = _view(db, args)["api_observations"]
        _emit(rows, args.as_json, lambda r: (print(f"api_observations={len(r)}"),
              [print(f"  {o['api']:<24} {o['category']:<12} [{o['state']}] src={o['source']}") for o in r]))
    finally:
        db.close()


def _cve(args) -> None:
    from app.native.deep_native import native_cve_signatures
    db = _db()
    try:
        rows = native_cve_signatures(_load_analysis(db, args.analysis_id))
        _emit(rows, args.as_json, lambda r: (print(f"native_cve_signatures={len(r)}"),
              [print(f"  {s['native_symbol']:<24} {s['state']:<18} {s['cve_id']} ({s['version_state']})")
               for s in r]))
    finally:
        db.close()


def _evidence(args) -> None:
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        rows = [{"subject": e.subject_fp, "source_type": e.source_type, "detail": e.detail,
                 "confidence": e.confidence} for e in analysis.native_deep_evidence]
        _emit(rows, args.as_json, lambda r: (print(f"evidence={len(r)}"),
              [print(f"  [{e['source_type']:<6}] {e['detail']} (conf {e['confidence']})") for e in r[:200]]))
    finally:
        db.close()


def _paths(args) -> None:
    from app.native.deep_native import native_paths
    db = _db()
    try:
        data = native_paths(_load_analysis(db, args.analysis_id), args.from_query, args.to_query, args.max_depth)
        _emit(data, args.as_json, lambda x: (print(f"paths={x['count']} (from='{x['from']}' to='{x['to']}')"),
              [print(f"  {' → '.join(n['label'] for n in p['nodes'])} [{p['status']}]") for p in x["paths"][:60]],
              print(f"note: {x['note']}")))
    finally:
        db.close()


def _explain(args) -> None:
    from app.native.deep_native import native_explain
    db = _db()
    try:
        data = native_explain(_load_analysis(db, args.analysis_id), args.target)
        _emit(data, args.as_json, lambda x: (print(f"EXPLAIN {x['target']}:"),
              [print(f"  {i + 1}. {s}") for i, s in enumerate(x["explanation"])],
              print(f"note: {x['note']}")))
    finally:
        db.close()


def _export(args) -> None:
    from app.reports.native_report import export_native
    db = _db()
    try:
        print(export_native(_load_analysis(db, args.analysis_id), args.fmt))
    finally:
        db.close()

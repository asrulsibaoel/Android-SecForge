"""CLI for obfuscation & anti-analysis intelligence (prompt 19). Registered as
`obfuscation`. Read-only; computes the deterministic in-memory view."""

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
    obf = commands.add_parser("obfuscation", help="Obfuscation & anti-analysis intelligence (offline)")
    sub = obf.add_subparsers(dest="obfuscation_command", required=True)

    for name in ("summary", "list", "impacts", "anti-analysis", "paths"):
        s = sub.add_parser(name); s.add_argument("analysis_id", type=UUID)
        _filters(s); s.add_argument("--json", action="store_true", dest="as_json")

    sh = sub.add_parser("show"); sh.add_argument("analysis_id", type=UUID); sh.add_argument("observation_id")
    sh.add_argument("--json", action="store_true", dest="as_json")
    ex = sub.add_parser("explain"); ex.add_argument("analysis_id", type=UUID); ex.add_argument("observation_id")
    ex.add_argument("--json", action="store_true", dest="as_json")
    xp = sub.add_parser("export"); xp.add_argument("analysis_id", type=UUID)
    xp.add_argument("--format", dest="fmt", default="json", choices=["json", "markdown", "md"])


def _filters(p) -> None:
    p.add_argument("--category", default=None)
    p.add_argument("--target", default=None)
    p.add_argument("--confidence", default=None)
    p.add_argument("--state", default=None)
    p.add_argument("--component", default=None)


def _apply(rows: list[dict], args) -> list[dict]:
    out = []
    for r in rows:
        if getattr(args, "category", None) and args.category.upper() not in (r.get("category") or "").upper():
            continue
        if getattr(args, "state", None) and (r.get("state") or "").upper() != args.state.upper():
            continue
        if getattr(args, "confidence", None) and (r.get("confidence") or "").upper() != args.confidence.upper():
            continue
        if getattr(args, "target", None) and args.target.lower() not in (r.get("target") or "").lower():
            continue
        if getattr(args, "component", None) and args.component.lower() not in (r.get("target") or "").lower():
            continue
        out.append(r)
    return out


def dispatch(args) -> None:
    {"summary": _summary, "list": _list, "impacts": _impacts, "anti-analysis": _anti,
     "paths": _paths, "show": _show, "explain": _explain, "export": _export}[args.obfuscation_command](args)


def _view(db, args):
    from app.analysis.obfuscation import obfuscation_view
    return obfuscation_view(_load_analysis(db, args.analysis_id))


def _summary(args) -> None:
    db = _db()
    try:
        view = _view(db, args)
        data = {"summary": view["summary"], "score": view["score"], "fingerprint": view["fingerprint"]}
        _emit(data, args.as_json, lambda x: (
            print(f"observations={x['summary']['observations']} anti_analysis="
                  f"{x['summary']['anti_analysis_indicators']} impacts={x['summary']['analysis_impacts']}"),
            print(f"score={x['score']['score']}/100 ({x['score']['band']}) — analysis complexity, not severity"),
            print(f"by_category={x['summary']['by_category']}"),
            print(f"availability={x['summary']['availability']}")))
    finally:
        db.close()


def _list(args) -> None:
    db = _db()
    try:
        rows = _apply(_view(db, args)["observations"], args)
        _emit(rows, args.as_json, lambda r: (print(f"observations={len(r)}"),
              [print(f"  [{x['state']:<22}] {x['category']:<24} {x['indicator']} conf={x['confidence']} "
                     f"target={x['target'] or 'APK'}") for x in r]))
    finally:
        db.close()


def _impacts(args) -> None:
    db = _db()
    try:
        rows = _view(db, args)["analysis_impacts"]
        _emit(rows, args.as_json, lambda r: (print(f"analysis_impacts={len(r)}"),
              [print(f"  {x['impact_category']:<34} {x['description']}") for x in r]))
    finally:
        db.close()


def _anti(args) -> None:
    db = _db()
    try:
        rows = _apply(_view(db, args)["anti_analysis"], args)
        _emit(rows, args.as_json, lambda r: (print(f"anti_analysis_indicators={len(r)}"),
              [print(f"  [{x['evidence_level']:<16}] {x['category']:<18} {x['indicator']} "
                     f"(conf {x['confidence']})") for x in r]))
    finally:
        db.close()


def _paths(args) -> None:
    db = _db()
    try:
        # obfuscation "paths": observations that mark uncertainty boundaries
        rows = [o for o in _view(db, args)["observations"]
                if o["state"] in ("UNRESOLVED", "EXTERNALLY_INFLUENCED", "UNKNOWN")]
        _emit(rows, args.as_json, lambda r: (print(f"uncertainty_boundaries={len(r)}"),
              [print(f"  {o['target'] or 'APK'} → {o['indicator']} [{o['state']}]") for o in r]))
    finally:
        db.close()


def _show(args) -> None:
    db = _db()
    try:
        view = _view(db, args)
        allobs = view["observations"] + view["anti_analysis"] + view["analysis_impacts"]
        item = next((x for x in allobs if x["id"] == args.observation_id or x["id"].startswith(args.observation_id)),
                    None)
        if item is None:
            raise ValueError("observation not found")
        _emit(item, args.as_json, lambda x: print(json.dumps(x, indent=2, default=str)))
    finally:
        db.close()


def _explain(args) -> None:
    from app.analysis.obfuscation import explain_observation
    db = _db()
    try:
        view = _view(db, args)
        item = next((o for o in view["observations"]
                     if o["id"] == args.observation_id or o["id"].startswith(args.observation_id)), None)
        if item is None:
            raise ValueError("observation not found")
        data = explain_observation(_load_analysis(db, args.analysis_id), item)
        _emit(data, args.as_json, lambda x: (
            print("WHY_THIS_OBSERVATION:"),
            [print(f"  {i + 1}. {r}") for i, r in enumerate(x["WHY_THIS_OBSERVATION"])],
            print(f"note: {x['note']}")))
    finally:
        db.close()


def _export(args) -> None:
    from app.reports.obfuscation_report import export_obfuscation
    db = _db()
    try:
        print(export_obfuscation(_load_analysis(db, args.analysis_id), args.fmt))
    finally:
        db.close()

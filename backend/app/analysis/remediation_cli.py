"""CLI for remediation intelligence (prompt 17). Registered as `remediation`.

Read-only over source evidence; `remediation plan` persists a plan. All other
subcommands compute the deterministic in-memory plan view.
"""

from __future__ import annotations

import json
from uuid import UUID

_CONF_RANK = {"UNKNOWN": -1, "LOW": 0, "MEDIUM": 1, "HIGH": 2, "EXACT": 3}


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
    rem = commands.add_parser("remediation", help="Deterministic remediation planning (static, offline)")
    sub = rem.add_subparsers(dest="remediation_command", required=True)

    pl = sub.add_parser("plan"); pl.add_argument("analysis_id", type=UUID)
    pl.add_argument("--json", action="store_true", dest="as_json")

    for name in ("list", "summary", "paths"):
        s = sub.add_parser(name); s.add_argument("analysis_id", type=UUID)
        _filters(s); s.add_argument("--json", action="store_true", dest="as_json")

    sh = sub.add_parser("show"); sh.add_argument("analysis_id", type=UUID); sh.add_argument("item_id")
    sh.add_argument("--json", action="store_true", dest="as_json")

    ex = sub.add_parser("explain"); ex.add_argument("analysis_id", type=UUID); ex.add_argument("item_id")
    ex.add_argument("--json", action="store_true", dest="as_json")

    xp = sub.add_parser("export"); xp.add_argument("analysis_id", type=UUID)
    xp.add_argument("--format", dest="fmt", default="json", choices=["json", "markdown", "md"])


def _filters(p) -> None:
    p.add_argument("--priority", default=None)
    p.add_argument("--status", default=None)
    p.add_argument("--action", default=None)
    p.add_argument("--fixability", default=None)
    p.add_argument("--component", default=None)
    p.add_argument("--dependency", default=None)
    p.add_argument("--cve", default=None)
    p.add_argument("--min-confidence", dest="min_confidence", default=None)


def _apply_filters(items: list[dict], args) -> list[dict]:
    out = []
    for it in items:
        if getattr(args, "priority", None) and it["priority"] != args.priority.upper():
            continue
        if getattr(args, "status", None) and it["status"] != args.status.upper():
            continue
        if getattr(args, "action", None) and args.action.upper() not in it["action"].upper():
            continue
        if getattr(args, "fixability", None) and it["fixability"] != args.fixability.upper():
            continue
        if getattr(args, "component", None) and args.component.lower() not in (it.get("target") or "").lower():
            continue
        if getattr(args, "dependency", None) and (it["target_type"] not in ("DEPENDENCY", "NATIVE_LIBRARY")
                                                   or args.dependency.lower() not in (it.get("target") or "").lower()):
            continue
        if getattr(args, "cve", None) and not any(e.get("source_type") == "CVE" and args.cve.upper() in
                                                   (e.get("source_id") or "").upper() for e in it["evidence"]):
            continue
        if getattr(args, "min_confidence", None) and \
                _CONF_RANK.get((it["confidence"] or "UNKNOWN").upper(), -1) < \
                _CONF_RANK.get(args.min_confidence.upper(), -1):
            continue
        out.append(it)
    return out


def dispatch(args) -> None:
    {"plan": _plan, "list": _list, "summary": _summary, "show": _show, "explain": _explain,
     "paths": _paths, "export": _export}[args.remediation_command](args)


def _plan(args) -> None:
    from app.analysis.remediation import build_plan
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        plan = build_plan(db, analysis, requested_by="cli")
        db.commit()
        data = {"plan_id": str(plan.id), "fingerprint": plan.fingerprint, "items": plan.item_count,
                "priority_distribution": plan.priority_distribution, "summary": plan.summary}
        _emit(data, args.as_json, lambda x: (
            print(f"plan_id={x['plan_id']} fingerprint={x['fingerprint'][:16]} items={x['items']}"),
            print(f"priority: {x['priority_distribution']}"),
            print(f"status: {x['summary'].get('by_status')}"),
            print(f"actions: {x['summary'].get('by_action')}")))
    finally:
        db.close()


def _view(db, args):
    from app.analysis.remediation import plan_view
    analysis = _load_analysis(db, args.analysis_id)
    return plan_view(analysis)


def _list(args) -> None:
    db = _db()
    try:
        view = _view(db, args)
        items = _apply_filters(view["items"], args)
        rows = [{"id": i["id"], "priority": i["priority"], "status": i["status"], "action": i["action"],
                 "fixability": i["fixability"], "target": i["target"], "confidence": i["confidence"]}
                for i in items]
        _emit(rows, args.as_json, lambda r: (print(f"remediation_items={len(r)}"),
              [print(f"  [{x['priority']:<12}] {x['status']:<26} {x['action']:<28} {x['target'] or ''} "
                     f"({x['fixability']})") for x in r]))
    finally:
        db.close()


def _summary(args) -> None:
    db = _db()
    try:
        view = _view(db, args)
        _emit(view["summary"], args.as_json, lambda s: (
            print(f"total={s['total']}"),
            print(f"by_priority={s['by_priority']}"),
            print(f"by_status={s['by_status']}"),
            print(f"by_fixability={s['by_fixability']}"),
            print(f"version_unverified={s['version_unverified']} conditional={s['conditional']} "
                  f"recommended={s['recommended']}"),
            [print(f"  uncertainty: {u}") for u in s["uncertainties"]]))
    finally:
        db.close()


def _show(args) -> None:
    db = _db()
    try:
        view = _view(db, args)
        item = next((i for i in view["items"] if i["id"] == args.item_id or i["id"].startswith(args.item_id)), None)
        if item is None:
            raise ValueError("remediation item not found")
        _emit(item, args.as_json, lambda x: print(json.dumps(x, indent=2, default=str)))
    finally:
        db.close()


def _explain(args) -> None:
    from app.analysis.remediation import build_items, explain_item
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        items = build_items(analysis)
        item = next((i for i in items if i.fingerprint == args.item_id or i.fingerprint.startswith(args.item_id)), None)
        if item is None:
            raise ValueError("remediation item not found")
        data = explain_item(analysis, item)
        _emit(data, args.as_json, lambda x: (
            print(f"{x['action']} [{x['priority']}/{x['status']}] target={x['target']}"),
            print("WHY_THIS_RECOMMENDATION_EXISTS:"),
            [print(f"  {n + 1}. {s}") for n, s in enumerate(x["WHY_THIS_RECOMMENDATION_EXISTS"])],
            print("uncertainties:"), [print(f"  - {u}") for u in x["uncertainties"]]))
    finally:
        db.close()


def _paths(args) -> None:
    db = _db()
    try:
        view = _view(db, args)
        deps = view["dependencies"]
        _emit(deps, args.as_json, lambda d: (print(f"remediation_dependencies={len(d)}"),
              [print(f"  {x['from'][:12]} {x['relation']} {x['to'][:12]}") for x in d]))
    finally:
        db.close()


def _export(args) -> None:
    from app.reports.remediation_report import export_remediation
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        print(export_remediation(analysis, args.fmt))
    finally:
        db.close()

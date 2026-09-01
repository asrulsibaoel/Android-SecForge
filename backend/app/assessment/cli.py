"""CLI for the security assessment / decision-intelligence layer (prompt 24).

Registered as `assess`. `build` (re)computes and persists the deterministic
assessment; the read views project persisted conclusions. No decision is an
exploitability verdict and none is collapsed to SAFE/UNSAFE.
"""

from __future__ import annotations

import json
from uuid import UUID


def _db():
    from app.db.session import SessionLocal, initialize_database

    initialize_database()
    return SessionLocal()


def _load(db, analysis_id):
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
    asm = commands.add_parser("assess", help="Security assessment & decision intelligence (offline projection)")
    sub = asm.add_subparsers(dest="assess_command", required=True)

    b = sub.add_parser("build", help="Compute + persist the deterministic assessment")
    b.add_argument("analysis_id", type=UUID)
    b.add_argument("--json", action="store_true", dest="as_json")

    for name in ("summary", "conclusions"):
        s = sub.add_parser(name)
        s.add_argument("analysis_id", type=UUID)
        s.add_argument("--state", default=None)
        s.add_argument("--type", dest="ctype", default=None)
        s.add_argument("--subject", dest="subject_type", default=None)
        s.add_argument("--json", action="store_true", dest="as_json")

    ex = sub.add_parser("explain")
    ex.add_argument("analysis_id", type=UUID)
    ex.add_argument("ref")
    ex.add_argument("--json", action="store_true", dest="as_json")

    xp = sub.add_parser("export")
    xp.add_argument("analysis_id", type=UUID)
    xp.add_argument("--format", dest="fmt", default="json", choices=["json", "markdown", "md"])


def dispatch(args) -> None:
    {"build": _build, "summary": _summary, "conclusions": _conclusions,
     "explain": _explain, "export": _export}[args.assess_command](args)


def _build(args) -> None:
    from app.assessment.engine import build_assessment
    db = _db()
    try:
        a = _load(db, args.analysis_id)
        asm = build_assessment(db, a, requested_by="cli")
        db.commit()
        data = {"status": asm.status, "fingerprint": asm.fingerprint, "subjects": asm.subject_count,
                "conclusions": asm.conclusion_count, "open": asm.open_count, "blockers": asm.blocker_count,
                "summary": asm.summary}
        _emit(data, args.as_json, lambda x: (
            print(f"status={x['status']} fingerprint={x['fingerprint']}"),
            print(f"subjects={x['subjects']} conclusions={x['conclusions']} open={x['open']} blockers={x['blockers']}"),
            print(f"by_decision_state={x['summary'].get('by_decision_state', {})}")))
    finally:
        db.close()


def _view(db, args):
    from app.assessment.engine import assessment_view
    return assessment_view(_load(db, args.analysis_id))


def _summary(args) -> None:
    db = _db()
    try:
        v = _view(db, args)
        _emit({"status": v["status"], "fingerprint": v["fingerprint"], "summary": v["summary"]}, args.as_json,
              lambda x: (print(f"status={x['status']} fingerprint={x['fingerprint']}"),
                         print(f"summary={x['summary']}")))
    finally:
        db.close()


def _conclusions(args) -> None:
    db = _db()
    try:
        rows = _view(db, args)["conclusions"]
        if getattr(args, "state", None):
            rows = [c for c in rows if c["decision_state"] == args.state.upper()]
        if getattr(args, "ctype", None):
            rows = [c for c in rows if args.ctype.upper() in c["conclusion_type"]]
        if getattr(args, "subject_type", None):
            rows = [c for c in rows if c["subject_type"] == args.subject_type.upper()]
        _emit(rows, args.as_json, lambda r: (print(f"conclusions={len(r)}"),
              [print(f"  [{c['decision_state']:<22}] {c['conclusion_type']:<34} {c['subject_type']}:"
                     f"{c['subject_ref'][:40]}  (rule {c['rule_id']})") for c in r]))
    finally:
        db.close()


def _explain(args) -> None:
    from app.assessment.engine import explain_conclusion
    db = _db()
    try:
        data = explain_conclusion(_load(db, args.analysis_id), args.ref)
        _emit(data, args.as_json, lambda x: (print(f"EXPLAIN {x['ref']}:"),
              [print(f"  {i + 1}. [{s['step']}] {s['detail']}"
                     + (f" ({s.get('mode')})" if s.get('mode') else "")) for i, s in enumerate(x["chain"])],
              print(f"note: {x['note']}")))
    finally:
        db.close()


def _export(args) -> None:
    from app.reports.assessment_report import export_assessment
    db = _db()
    try:
        print(export_assessment(_load(db, args.analysis_id), args.fmt))
    finally:
        db.close()

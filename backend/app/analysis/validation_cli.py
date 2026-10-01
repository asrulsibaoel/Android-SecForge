"""CLI for security validation intelligence (prompt 18). Registered as `validation`.

Read-only over source evidence; computes the deterministic in-memory validation
view (the orchestrator persists claims during analysis).
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
    val = commands.add_parser("validation", help="Security verification & validation intelligence (offline)")
    sub = val.add_subparsers(dest="validation_command", required=True)

    for name in ("claims", "summary", "blockers", "requirements", "findings", "remediation", "paths"):
        s = sub.add_parser(name); s.add_argument("analysis_id", type=UUID)
        _filters(s); s.add_argument("--json", action="store_true", dest="as_json")

    sh = sub.add_parser("show"); sh.add_argument("analysis_id", type=UUID); sh.add_argument("claim_id")
    sh.add_argument("--json", action="store_true", dest="as_json")

    ex = sub.add_parser("explain"); ex.add_argument("analysis_id", type=UUID); ex.add_argument("claim_id")
    ex.add_argument("--json", action="store_true", dest="as_json")

    xp = sub.add_parser("export"); xp.add_argument("analysis_id", type=UUID)
    xp.add_argument("--format", dest="fmt", default="json", choices=["json", "markdown", "md"])


def _filters(p) -> None:
    p.add_argument("--state", default=None)
    p.add_argument("--min-confidence", dest="min_confidence", type=int, default=None)
    p.add_argument("--finding", default=None)
    p.add_argument("--component", default=None)
    p.add_argument("--claim-type", dest="claim_type", default=None)
    p.add_argument("--blocker", default=None)


def _apply_filters(claims: list[dict], args) -> list[dict]:
    out = []
    for c in claims:
        if getattr(args, "state", None) and c["validation_state"] != args.state.upper():
            continue
        if getattr(args, "min_confidence", None) is not None and c["confidence"] < args.min_confidence:
            continue
        if getattr(args, "finding", None) and (c.get("finding_id") or "") != args.finding:
            continue
        if getattr(args, "component", None) and args.component.lower() not in (c.get("target") or "").lower():
            continue
        if getattr(args, "claim_type", None) and args.claim_type.upper() not in c["claim_type"].upper():
            continue
        if getattr(args, "blocker", None) and not any(args.blocker.upper() in b["blocker"].upper()
                                                      for b in c["blockers"]):
            continue
        out.append(c)
    return out


def dispatch(args) -> None:
    {"claims": _claims, "summary": _summary, "blockers": _blockers, "requirements": _requirements,
     "findings": _findings, "remediation": _remediation, "paths": _paths, "show": _show,
     "explain": _explain, "export": _export}[args.validation_command](args)


def _view(db, args):
    from app.analysis.validation import validation_view
    return validation_view(_load_analysis(db, args.analysis_id))


def _claims(args) -> None:
    db = _db()
    try:
        claims = _apply_filters(_view(db, args)["claims"], args)
        rows = [{"id": c["id"], "state": c["validation_state"], "confidence": c["confidence"],
                 "claim_type": c["claim_type"], "target": c["target"],
                 "independent": c["independent_source_count"], "families": c["source_families"]}
                for c in claims]
        _emit(rows, args.as_json, lambda r: (print(f"validation_claims={len(r)}"),
              [print(f"  [{x['state']:<26}] conf={x['confidence']:>3} {x['claim_type']:<28} {x['target'] or ''} "
                     f"({x['independent']} fam)") for x in r]))
    finally:
        db.close()


def _summary(args) -> None:
    db = _db()
    try:
        s = _view(db, args)["summary"]
        _emit(s, args.as_json, lambda x: (
            print(f"total={x['total']} live_runtime_validation={x['live_runtime_validation']}"),
            print(f"by_state={x['by_state']}"),
            print(f"static_supported={x['static_supported']} multi_source={x['multi_source']} "
                  f"runtime_corroborated={x['runtime_corroborated']} unverified={x['unverified']} "
                  f"blocked={x['blocked']}"),
            print(f"blockers={x['blockers']}")))
    finally:
        db.close()


def _blockers(args) -> None:
    db = _db()
    try:
        view = _view(db, args)
        rows = view["blockers"]
        if getattr(args, "blocker", None):
            rows = [b for b in rows if args.blocker.upper() in b["blocker"].upper()]
        _emit(rows, args.as_json, lambda r: (print(f"blockers={len(r)}"),
              [print(f"  {b['blocker']:<24} {b['reason']} (missing: {b['missing']})") for b in r]))
    finally:
        db.close()


def _requirements(args) -> None:
    db = _db()
    try:
        rows = _view(db, args)["requirements"]
        _emit(rows, args.as_json, lambda r: (print(f"requirements={len(r)}"),
              [print(f"  [{'OK ' if x['satisfied'] else 'MISS'}] {x['requirement']} ({x['detail']})")
               for x in r[:80]]))
    finally:
        db.close()


def _findings(args) -> None:
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        rows = [{"rule_id": f.rule_id, "component": f.component,
                 "validation_state": getattr(f, "security_validation_state", "UNVERIFIED"),
                 "confidence": getattr(f, "validation_confidence", 0),
                 "claims": getattr(f, "validation_claim_count", 0),
                 "blockers": getattr(f, "validation_blocker_count", 0)}
                for f in analysis.findings if not f.is_duplicate]
        _emit(rows, args.as_json, lambda r: (print(f"findings={len(r)}"),
              [print(f"  {x['validation_state']:<26} conf={x['confidence']:>3} {x['rule_id']} "
                     f"@ {x['component'] or '-'}") for x in r]))
    finally:
        db.close()


def _remediation(args) -> None:
    db = _db()
    try:
        claims = [c for c in _view(db, args)["claims"] if c["claim_type"] == "REMEDIATION_STATE_SUPPORTED"]
        _emit(claims, args.as_json, lambda r: (print(f"remediation_validation={len(r)}"),
              [print(f"  [{c['validation_state']:<26}] {c['target']} conf={c['confidence']}") for c in r]))
    finally:
        db.close()


def _paths(args) -> None:
    db = _db()
    try:
        # validation "paths" surfaces claims whose evidence spans multiple families
        claims = [c for c in _view(db, args)["claims"] if c["independent_source_count"] >= 2]
        _emit(claims, args.as_json, lambda r: (print(f"multi_source_claims={len(r)}"),
              [print(f"  {c['claim_type']} {c['target']} families={c['source_families']}") for c in r]))
    finally:
        db.close()


def _show(args) -> None:
    db = _db()
    try:
        claim = next((c for c in _view(db, args)["claims"]
                      if c["id"] == args.claim_id or c["id"].startswith(args.claim_id)), None)
        if claim is None:
            raise ValueError("validation claim not found")
        _emit(claim, args.as_json, lambda x: print(json.dumps(x, indent=2, default=str)))
    finally:
        db.close()


def _explain(args) -> None:
    from app.analysis.validation import build_claims, explain_claim
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        claim = next((c for c in build_claims(analysis)
                      if c.fingerprint == args.claim_id or c.fingerprint.startswith(args.claim_id)), None)
        if claim is None:
            raise ValueError("validation claim not found")
        data = explain_claim(analysis, claim)
        header = next(k for k in data if k.startswith("WHY_"))
        _emit(data, args.as_json, lambda x: (
            print(f"{x['claim']} [{x['validation_state']}] target={x['target']} confidence={x['confidence']}"),
            print(f"{header}:"), [print(f"  {i + 1}. {r}") for i, r in enumerate(x[header])],
            print("blockers:"), [print(f"  - {b['blocker']}") for b in x["blockers"]]))
    finally:
        db.close()


def _export(args) -> None:
    from app.reports.validation_report import export_validation
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        print(export_validation(analysis, args.fmt))
    finally:
        db.close()

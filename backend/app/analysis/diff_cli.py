"""CLI for comparative APK analysis (prompt 15). Registered as `diff`.

Read-only against analyses; `diff create` persists a comparison. All commands
support `--json` and common filters.
"""

from __future__ import annotations

import json
from uuid import UUID

_CONF_RANK = {"UNKNOWN": -1, "LOW": 0, "MEDIUM": 1, "HIGH": 2}


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


def _load_comparison(db, comparison_id):
    from app.models.comparison import AnalysisComparison

    c = db.get(AnalysisComparison, comparison_id)
    if c is None:
        raise ValueError("Comparison not found")
    return c


def _emit(data, as_json, human):
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    else:
        human(data)


def add_parser(commands) -> None:
    diff = commands.add_parser("diff", help="Comparative APK / security analysis (A → B)")
    sub = diff.add_subparsers(dest="diff_command", required=True)

    cr = sub.add_parser("create"); cr.add_argument("baseline", type=UUID); cr.add_argument("candidate", type=UUID)
    cr.add_argument("--json", action="store_true", dest="as_json")

    for name in ("show", "summary", "findings", "attack-surface", "risk", "paths"):
        s = sub.add_parser(name); s.add_argument("comparison_id", type=UUID)
        s.add_argument("--json", action="store_true", dest="as_json")

    ch = sub.add_parser("changes"); ch.add_argument("comparison_id", type=UUID)
    ch.add_argument("--category", default=None); ch.add_argument("--change-type", dest="change_type", default=None)
    ch.add_argument("--min-confidence", dest="min_confidence", default=None)
    ch.add_argument("--security-impact", dest="security_only", action="store_true")
    ch.add_argument("--json", action="store_true", dest="as_json")

    li = sub.add_parser("list"); li.add_argument("--json", action="store_true", dest="as_json")

    xp = sub.add_parser("export"); xp.add_argument("comparison_id", type=UUID)
    xp.add_argument("--format", dest="fmt", default="report", choices=["report", "json", "graphml", "dot"])


def dispatch(args) -> None:
    cmd = args.diff_command
    {
        "create": _create, "show": _show, "summary": _summary, "changes": _changes,
        "findings": _findings, "attack-surface": _attack_surface, "risk": _risk, "paths": _paths,
        "list": _list, "export": _export,
    }[cmd](args)


def _create(args) -> None:
    from app.analysis.diff import compare_analyses
    db = _db()
    try:
        baseline = _load_analysis(db, args.baseline)
        candidate = _load_analysis(db, args.candidate)
        comparison = compare_analyses(db, baseline, candidate, requested_by="cli")
        db.commit()
        data = {"comparison_id": str(comparison.id), "status": comparison.status,
                "snapshot_mode": comparison.snapshot_mode, "security_impact": comparison.security_impact,
                "impact_confidence": comparison.impact_confidence, "fingerprint": comparison.fingerprint,
                "error": comparison.error, "summary": comparison.summary}
        _emit(data, args.as_json, lambda x: (
            print(f"comparison_id={x['comparison_id']} status={x['status']} mode={x['snapshot_mode']}"),
            print(f"security_impact={x['security_impact']} ({x['impact_confidence']})"),
            print(f"total_changes={x['summary'].get('total_changes')} "
                  f"security_relevant={x['summary'].get('security_relevant_changes')}")
            if not x["error"] else print(f"FAILED: {x['error']}")))
    finally:
        db.close()


def _show(args) -> None:
    from app.reports.comparison_report import build_comparison_report
    db = _db()
    try:
        c = _load_comparison(db, args.comparison_id)
        report = build_comparison_report(c)
        _emit(report, args.as_json, lambda r: print(json.dumps(r, indent=2, default=str)))
    finally:
        db.close()


def _summary(args) -> None:
    db = _db()
    try:
        c = _load_comparison(db, args.comparison_id)
        data = {"comparison_id": str(c.id), "status": c.status, "snapshot_mode": c.snapshot_mode,
                "security_impact": c.security_impact, "impact_confidence": c.impact_confidence,
                "summary": c.summary,
                "category_summaries": [{"category": s.category, "added": s.added, "removed": s.removed,
                                        "changed": s.changed, "unchanged": s.unchanged,
                                        "security_relevant": s.security_relevant}
                                       for s in sorted(c.category_summaries, key=lambda s: s.category)]}
        _emit(data, args.as_json, lambda x: (
            print(f"status={x['status']} mode={x['snapshot_mode']} impact={x['security_impact']} "
                  f"({x['impact_confidence']})"),
            print(f"total_changes={x['summary'].get('total_changes')}"),
            [print(f"  {s['category']:<16} +{s['added']} -{s['removed']} ~{s['changed']} "
                   f"(sec {s['security_relevant']})") for s in x["category_summaries"]]))
    finally:
        db.close()


def _changes(args) -> None:
    db = _db()
    try:
        c = _load_comparison(db, args.comparison_id)
        rows = []
        for ch in c.changes:
            if args.category and ch.category != args.category:
                continue
            if args.change_type and ch.change_type != args.change_type.upper():
                continue
            if args.min_confidence and _CONF_RANK.get((ch.confidence or "UNKNOWN").upper(), -1) < \
                    _CONF_RANK.get(args.min_confidence.upper(), -1):
                continue
            if getattr(args, "security_only", False) and not ch.security_relevant:
                continue
            rows.append({"category": ch.category, "entity_type": ch.entity_type, "identity": ch.entity_identity,
                         "change_type": ch.change_type, "confidence": ch.confidence,
                         "security_relevant": ch.security_relevant, "baseline": ch.baseline_value,
                         "candidate": ch.candidate_value, "provenance": ch.provenance, "evidence": ch.evidence})
        _emit(rows, args.as_json, lambda r: (print(f"changes={len(r)}"),
              [print(f"  [{x['change_type']:<9}] {x['category']}/{x['entity_type']} {x['identity']} "
                     f"({x['confidence']}{', SEC' if x['security_relevant'] else ''})") for x in r[:200]]))
    finally:
        db.close()


def _findings(args) -> None:
    db = _db()
    try:
        c = _load_comparison(db, args.comparison_id)
        rows = [{"change_type": f.change_type, "rule_id": f.rule_id, "component": f.component,
                 "changed_dimensions": f.changed_dimensions, "confidence": f.confidence,
                 "security_relevant": f.security_relevant,
                 "disposition": "NO_LONGER_DETECTED" if f.change_type == "REMOVED" else None}
                for f in c.finding_changes]
        _emit(rows, args.as_json, lambda r: (print(f"finding_changes={len(r)}"),
              [print(f"  [{x['change_type']:<9}] {x['rule_id']} @ {x['component'] or '-'}"
                     f"{' ' + str(x['changed_dimensions']) if x['changed_dimensions'] else ''}"
                     f"{' (' + x['disposition'] + ')' if x['disposition'] else ''}") for x in r]))
    finally:
        db.close()


def _attack_surface(args) -> None:
    db = _db()
    try:
        c = _load_comparison(db, args.comparison_id)
        rows = [{"change_type": ch.change_type, "entity_type": ch.entity_type, "identity": ch.entity_identity,
                 "baseline": ch.baseline_value, "candidate": ch.candidate_value, "evidence": ch.evidence}
                for ch in c.changes if ch.category == "attack_surface"]
        delta = _attack_surface_delta(rows)
        _emit({"delta": delta, "changes": rows}, args.as_json, lambda x: (
            print("attack-surface delta:"),
            [print(f"  {k}: {v:+d}") for k, v in x["delta"].items()],
            print(f"changes={len(x['changes'])}")))
    finally:
        db.close()


def _attack_surface_delta(rows) -> dict:
    delta = {"PUBLIC_NODES": 0, "AS_EDGES": 0}
    for r in rows:
        if r["entity_type"] == "as_node":
            exp = (r.get("evidence") or {}).get("exposure")
            if r["change_type"] == "ADDED" and exp == "PUBLIC":
                delta["PUBLIC_NODES"] += 1
            elif r["change_type"] == "REMOVED" and exp == "PUBLIC":
                delta["PUBLIC_NODES"] -= 1
        elif r["entity_type"] == "as_edge":
            delta["AS_EDGES"] += 1 if r["change_type"] == "ADDED" else (-1 if r["change_type"] == "REMOVED" else 0)
    return delta


def _risk(args) -> None:
    db = _db()
    try:
        c = _load_comparison(db, args.comparison_id)
        rd = c.risk_delta
        if rd is None:
            _emit({"status": "NO_RISK_DELTA"}, args.as_json, lambda x: print("no risk delta"))
            return
        data = {"baseline_score": rd.baseline_score, "candidate_score": rd.candidate_score, "delta": rd.delta,
                "severity_transition": rd.severity_transition, "confidence_transition": rd.confidence_transition,
                "factor_changes": rd.factor_changes,
                "note": "Risk changed according to the configured scoring model; not a claim about exploitability."}
        _emit(data, args.as_json, lambda x: (
            print(f"risk {x['baseline_score']} → {x['candidate_score']} ({x['delta']:+d})"),
            print(f"severity: {x['severity_transition']}  confidence: {x['confidence_transition']}"),
            print(f"factors +{x['factor_changes']['added']} -{x['factor_changes']['removed']}"),
            print(f"note: {x['note']}")))
    finally:
        db.close()


def _paths(args) -> None:
    db = _db()
    try:
        c = _load_comparison(db, args.comparison_id)
        rows = [{"change_type": ch.change_type, "identity": ch.entity_identity, "confidence": ch.confidence,
                 "security_relevant": ch.security_relevant, "evidence": ch.evidence}
                for ch in c.changes if ch.category == "reachability"]
        _emit(rows, args.as_json, lambda r: (print(f"reachability_path_changes={len(r)}"),
              [print(f"  [{x['change_type']:<9}] {x['evidence'].get('status')} "
                     f"{x['evidence'].get('from')} → {x['evidence'].get('to')}") for x in r]))
    finally:
        db.close()


def _list(args) -> None:
    from sqlalchemy import select
    from app.models.comparison import AnalysisComparison
    db = _db()
    try:
        rows = [{"id": str(c.id), "baseline": str(c.baseline_analysis_id),
                 "candidate": str(c.candidate_analysis_id), "status": c.status,
                 "security_impact": c.security_impact, "created_at": c.created_at.isoformat()}
                for c in db.scalars(select(AnalysisComparison).order_by(AnalysisComparison.created_at.desc()))]
        _emit(rows, args.as_json, lambda r: (print(f"comparisons={len(r)}"),
              [print(f"  {x['id']} {x['status']} {x['security_impact']} {x['baseline'][:8]}→{x['candidate'][:8]}")
               for x in r]))
    finally:
        db.close()


def _export(args) -> None:
    from app.reports.comparison_report import export_comparison_graph
    db = _db()
    try:
        c = _load_comparison(db, args.comparison_id)
        print(export_comparison_graph(c, args.fmt))
    finally:
        db.close()

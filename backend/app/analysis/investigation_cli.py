"""CLI for the knowledge graph + investigation workspace (prompt 14).

Registered under `androidsecforge investigate ...`; the deterministic graph
queries and snapshots are also wired into the existing `graph` group by cli.py.
Every command is read-only against analytical truth except the investigation
workspace mutations (which touch only investigation state).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
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


def _load_investigation(db, investigation_id):
    from app.models.investigation import Investigation

    inv = db.get(Investigation, investigation_id)
    if inv is None:
        raise ValueError("Investigation not found")
    return inv


def _load_finding(db, finding_id):
    from app.models.analysis import FindingModel

    f = db.get(FindingModel, finding_id)
    if f is None:
        raise ValueError("Finding not found")
    return f


def _emit(data, as_json, human):
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    else:
        human(data)


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------


def add_parser(commands) -> None:
    inv = commands.add_parser("investigate", help="Knowledge-graph investigation workspace")
    sub = inv.add_subparsers(dest="investigate_command", required=True)

    c = sub.add_parser("create"); c.add_argument("analysis_id", type=UUID)
    c.add_argument("--name", default=None); c.add_argument("--description", default="")
    c.add_argument("--json", action="store_true", dest="as_json")

    li = sub.add_parser("list"); li.add_argument("analysis_id", type=UUID)
    li.add_argument("--json", action="store_true", dest="as_json")

    sh = sub.add_parser("show"); sh.add_argument("investigation_id", type=UUID)
    sh.add_argument("--json", action="store_true", dest="as_json")

    rn = sub.add_parser("rename"); rn.add_argument("investigation_id", type=UUID); rn.add_argument("name")
    rn.add_argument("--json", action="store_true", dest="as_json")

    af = sub.add_parser("add-finding"); af.add_argument("investigation_id", type=UUID)
    af.add_argument("finding_id", type=UUID); af.add_argument("--json", action="store_true", dest="as_json")

    an = sub.add_parser("add-node"); an.add_argument("investigation_id", type=UUID)
    an.add_argument("node_ref"); an.add_argument("--type", dest="node_type", default="")
    an.add_argument("--label", default=""); an.add_argument("--note", default="")
    an.add_argument("--json", action="store_true", dest="as_json")

    nt = sub.add_parser("note"); nt.add_argument("investigation_id", type=UUID); nt.add_argument("body")
    nt.add_argument("--author", default="researcher"); nt.add_argument("--target", dest="target_ref", default=None)
    nt.add_argument("--json", action="store_true", dest="as_json")

    hy = sub.add_parser("hypothesis"); hy.add_argument("investigation_id", type=UUID); hy.add_argument("statement")
    hy.add_argument("--status", default="OPEN"); hy.add_argument("--rationale", default="")
    hy.add_argument("--json", action="store_true", dest="as_json")

    hs = sub.add_parser("hypothesis-status"); hs.add_argument("hypothesis_id", type=UUID); hs.add_argument("status")
    hs.add_argument("--rationale", default=None); hs.add_argument("--json", action="store_true", dest="as_json")

    he = sub.add_parser("hypothesis-evidence"); he.add_argument("hypothesis_id", type=UUID)
    he.add_argument("ref_type"); he.add_argument("ref_id"); he.add_argument("--detail", default="")
    he.add_argument("--json", action="store_true", dest="as_json")

    bm = sub.add_parser("bookmark"); bm.add_argument("investigation_id", type=UUID)
    bm.add_argument("ref_type"); bm.add_argument("ref_id"); bm.add_argument("--label", default="")
    bm.add_argument("--json", action="store_true", dest="as_json")

    tl = sub.add_parser("timeline"); tl.add_argument("investigation_id", type=UUID)
    tl.add_argument("--json", action="store_true", dest="as_json")

    gr = sub.add_parser("graph"); gr.add_argument("investigation_id", type=UUID)
    gr.add_argument("--json", action="store_true", dest="as_json")

    pa = sub.add_parser("path"); pa.add_argument("investigation_id", type=UUID)
    pa.add_argument("--from", dest="from_query", required=True); pa.add_argument("--to", dest="to_query", required=True)
    pa.add_argument("--max-depth", dest="max_depth", type=int, default=None)
    pa.add_argument("--min-confidence", dest="min_confidence", default=None)
    pa.add_argument("--json", action="store_true", dest="as_json")

    ex = sub.add_parser("explain"); ex.add_argument("finding_id", type=UUID)
    ex.add_argument("--json", action="store_true", dest="as_json")

    ec = sub.add_parser("evidence-chain"); ec.add_argument("finding_id", type=UUID)
    ec.add_argument("--json", action="store_true", dest="as_json")

    xp = sub.add_parser("export"); xp.add_argument("investigation_id", type=UUID)
    xp.add_argument("--format", dest="fmt", default="json", choices=["json", "graphml", "dot", "markdown", "md"])

    sn = sub.add_parser("snapshot"); sn.add_argument("analysis_id", type=UUID)
    sn.add_argument("--json", action="store_true", dest="as_json")


def dispatch(args) -> None:
    cmd = args.investigate_command
    handler = {
        "create": _create, "list": _list, "show": _show, "rename": _rename,
        "add-finding": _add_finding, "add-node": _add_node, "note": _note,
        "hypothesis": _hypothesis, "hypothesis-status": _hypothesis_status,
        "hypothesis-evidence": _hypothesis_evidence, "bookmark": _bookmark, "timeline": _timeline,
        "graph": _graph, "path": _path, "explain": _explain, "evidence-chain": _evidence_chain,
        "export": _export, "snapshot": _snapshot,
    }[cmd]
    handler(args)


# ---------------------------------------------------------------------------
# handlers
# ---------------------------------------------------------------------------


def _create(args) -> None:
    from app.analysis import investigation as INV
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        inv = INV.create_investigation(db, analysis, name=args.name, description=args.description)
        db.commit()
        _emit({"investigation_id": str(inv.id), "name": inv.name, "analysis_id": str(analysis.id)},
              args.as_json, lambda x: print(f"investigation_id={x['investigation_id']} name={x['name']}"))
    finally:
        db.close()


def _list(args) -> None:
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        rows = [{"id": str(i.id), "name": i.name, "status": i.status,
                 "findings": len(i.findings), "hypotheses": len(i.hypotheses)} for i in analysis.investigations]
        _emit(rows, args.as_json, lambda r: (print(f"investigations={len(r)}"),
              [print(f"  {x['id']} {x['name']} [{x['status']}] findings={x['findings']}") for x in r]))
    finally:
        db.close()


def _show(args) -> None:
    from app.analysis import investigation as INV
    db = _db()
    try:
        inv = _load_investigation(db, args.investigation_id)
        view = INV.investigation_view(inv)
        _emit(view, args.as_json, lambda v: (
            print(f"{v['name']} [{v['status']}] analysis={v['analysis_id']}"),
            print(f"  nodes={v['counts']['nodes']} findings={v['counts']['findings']} "
                  f"hypotheses={v['counts']['hypotheses']} notes={v['counts']['notes']}")))
    finally:
        db.close()


def _rename(args) -> None:
    from app.analysis import investigation as INV
    db = _db()
    try:
        inv = _load_investigation(db, args.investigation_id)
        INV.rename_investigation(db, inv, args.name)
        db.commit()
        _emit({"investigation_id": str(inv.id), "name": inv.name}, args.as_json,
              lambda x: print(f"renamed -> {x['name']}"))
    finally:
        db.close()


def _add_finding(args) -> None:
    from app.analysis import investigation as INV
    db = _db()
    try:
        inv = _load_investigation(db, args.investigation_id)
        finding = _load_finding(db, args.finding_id)
        if finding.analysis_id != inv.analysis_id:
            raise ValueError("finding belongs to a different analysis than this investigation")
        INV.add_finding(db, inv, finding)
        db.commit()
        _emit({"investigation_id": str(inv.id), "finding_id": str(finding.id), "rule_id": finding.rule_id},
              args.as_json, lambda x: print(f"added finding {x['rule_id']} to investigation"))
    finally:
        db.close()


def _add_node(args) -> None:
    from app.analysis import investigation as INV
    db = _db()
    try:
        inv = _load_investigation(db, args.investigation_id)
        node = INV.add_node(db, inv, args.node_ref, args.node_type, args.label, args.note)
        db.commit()
        _emit({"investigation_id": str(inv.id), "node_ref": node.node_ref}, args.as_json,
              lambda x: print(f"pinned node {x['node_ref']}"))
    finally:
        db.close()


def _note(args) -> None:
    from app.analysis import investigation as INV
    db = _db()
    try:
        inv = _load_investigation(db, args.investigation_id)
        note = INV.add_note(db, inv, args.body, args.author, args.target_ref)
        db.commit()
        _emit({"note_id": str(note.id)}, args.as_json, lambda x: print(f"note added {x['note_id']}"))
    finally:
        db.close()


def _hypothesis(args) -> None:
    from app.analysis import investigation as INV
    db = _db()
    try:
        inv = _load_investigation(db, args.investigation_id)
        hyp = INV.add_hypothesis(db, inv, args.statement, args.rationale, args.status)
        db.commit()
        _emit({"hypothesis_id": str(hyp.id), "status": hyp.status}, args.as_json,
              lambda x: print(f"hypothesis {x['hypothesis_id']} [{x['status']}]"))
    finally:
        db.close()


def _hypothesis_status(args) -> None:
    from app.analysis import investigation as INV
    from app.models.investigation import InvestigationHypothesis
    db = _db()
    try:
        hyp = db.get(InvestigationHypothesis, args.hypothesis_id)
        if hyp is None:
            raise ValueError("Hypothesis not found")
        INV.set_hypothesis_status(db, hyp, args.status, args.rationale)
        db.commit()
        _emit({"hypothesis_id": str(hyp.id), "status": hyp.status,
               "note": "researcher state only — no machine finding changed"},
              args.as_json, lambda x: print(f"hypothesis {x['hypothesis_id']} -> {x['status']}"))
    finally:
        db.close()


def _hypothesis_evidence(args) -> None:
    from app.analysis import investigation as INV
    from app.models.investigation import InvestigationHypothesis
    db = _db()
    try:
        hyp = db.get(InvestigationHypothesis, args.hypothesis_id)
        if hyp is None:
            raise ValueError("Hypothesis not found")
        INV.attach_hypothesis_evidence(db, hyp, args.ref_type, args.ref_id, args.detail)
        db.commit()
        _emit({"hypothesis_id": str(hyp.id), "evidence": len(hyp.evidence)}, args.as_json,
              lambda x: print(f"attached evidence ({x['evidence']} total)"))
    finally:
        db.close()


def _bookmark(args) -> None:
    from app.analysis import investigation as INV
    db = _db()
    try:
        inv = _load_investigation(db, args.investigation_id)
        bm = INV.add_bookmark(db, inv, args.ref_type, args.ref_id, args.label)
        db.commit()
        _emit({"bookmark_id": str(bm.id), "ref": f"{bm.ref_type}:{bm.ref_id}"}, args.as_json,
              lambda x: print(f"bookmarked {x['ref']}"))
    finally:
        db.close()


def _timeline(args) -> None:
    from app.analysis import investigation as INV
    db = _db()
    try:
        inv = _load_investigation(db, args.investigation_id)
        INV.rebuild_timeline(db, inv, inv.analysis)
        db.commit()
        rows = INV.timeline_view(inv)
        _emit(rows, args.as_json, lambda r: (print(f"timeline_events={len(r)}"),
              [print(f"  {x['timestamp'] or '(static)'} {x['event_type']} ({x['source']}) {x['detail']}") for x in r]))
    finally:
        db.close()


def _graph(args) -> None:
    from app.analysis import knowledge_graph as KG
    db = _db()
    try:
        inv = _load_investigation(db, args.investigation_id)
        kg = KG.build_knowledge_graph(inv.analysis)
        counts = KG.snapshot_counts(kg, inv.analysis)
        data = {"analysis_id": str(inv.analysis_id), "digest": KG.graph_digest(kg),
                "truncated": kg.truncated, **counts}
        _emit(data, args.as_json, lambda x: (
            print(f"nodes={x['node_count']} edges={x['edge_count']} digest={x['digest'][:16]}"),
            print(f"  node_types={x['node_type_counts']}"),
            print(f"  edge_types={x['edge_type_counts']}")))
    finally:
        db.close()


def _path(args) -> None:
    from app.analysis import investigation as INV
    db = _db()
    try:
        inv = _load_investigation(db, args.investigation_id)
        result = INV.add_path(db, inv, inv.analysis, args.from_query, args.to_query,
                              max_depth=args.max_depth, min_confidence=args.min_confidence)
        db.commit()
        _emit(result, args.as_json, lambda x: print(json.dumps(x, indent=2, default=str)))
    finally:
        db.close()


def _explain(args) -> None:
    from app.analysis.finding_explorer import explain_finding
    db = _db()
    try:
        finding = _load_finding(db, args.finding_id)
        analysis = _load_analysis(db, finding.analysis_id)
        data = explain_finding(analysis, finding)
        _emit(data, args.as_json, lambda x: (
            print(f"WHY {x['finding']['rule_id']} ({x['finding']['severity']}/{x['finding']['confidence']}):"),
            [print(f"  {i + 1}. {s}") for i, s in enumerate(x["WHY_FOUND"])],
            print("UNCERTAINTIES:"), [print(f"  - {u}") for u in x["UNCERTAINTIES"]],
            print("LIMITATIONS:"), [print(f"  - {lim}") for lim in x["LIMITATIONS"]]))
    finally:
        db.close()


def _evidence_chain(args) -> None:
    from app.analysis.finding_explorer import evidence_chain
    db = _db()
    try:
        finding = _load_finding(db, args.finding_id)
        analysis = _load_analysis(db, finding.analysis_id)
        data = evidence_chain(analysis, finding)
        _emit(data, args.as_json, lambda x: (
            print(f"{x['finding']['rule_id']} [{x['finding']['status']}] fingerprint={x['fingerprint']}"),
            [print(f"  {s['step']}. ({s['provenance']}) {s['detail']}") for s in x["chain"]]))
    finally:
        db.close()


def _export(args) -> None:
    from app.reports.investigation_report import export_investigation
    db = _db()
    try:
        inv = _load_investigation(db, args.investigation_id)
        print(export_investigation(inv.analysis, inv, args.fmt))
    finally:
        db.close()


def _snapshot(args) -> None:
    from app.analysis import knowledge_graph as KG
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        snap = KG.build_snapshot(analysis, datetime.now(timezone.utc))
        db.commit()
        data = {"analysis_id": str(analysis.id), "graph_version": snap.graph_version, "digest": snap.digest,
                "node_count": snap.node_count, "edge_count": snap.edge_count,
                "finding_count": snap.finding_count, "root_cause_count": snap.root_cause_count,
                "runtime_observation_count": snap.runtime_observation_count}
        _emit(data, args.as_json, lambda x: print(
            f"snapshot digest={x['digest'][:16]} nodes={x['node_count']} edges={x['edge_count']}"))
    finally:
        db.close()


# ---------------------------------------------------------------------------
# graph-query handlers (wired into the existing `graph` group by cli.py)
# ---------------------------------------------------------------------------


def graph_query(args) -> None:
    from app.analysis import graph_queries as GQ
    db = _db()
    try:
        analysis = _load_analysis(db, args.analysis_id)
        params = {"min_confidence": getattr(args, "min_confidence", None),
                  "max_depth": getattr(args, "max_depth", None),
                  "component": getattr(args, "component", None)}
        result = GQ.run_query(analysis, args.query_name, params)
        _emit(result, getattr(args, "as_json", False), lambda x: (
            print(f"{x['query']}: {x['count']} result(s) — {x['description']}"),
            [print(f"  {json.dumps(r, default=str)}") for r in x["results"][:50]],
            print(f"  note: {x['note']}") if x.get("note") else None))
    finally:
        db.close()


def graph_queries_list(args) -> None:
    from app.analysis import graph_queries as GQ
    names = GQ.available_queries()
    _emit(names, getattr(args, "as_json", False), lambda n: (print("available graph queries:"),
          [print(f"  {name}") for name in n]))

"""Comparison (APK diff) report + graph-delta export — prompt 15.

`build_comparison_report` renders the persisted comparison into the required
deterministic JSON sections. The graph-delta export marks canonical knowledge-
graph nodes/edges as ADDED/REMOVED/UNCHANGED/CHANGED across the two analyses —
it does NOT build a second graph; it reuses prompt-14 projection identities and
preserves provenance + uncertainty.
"""

from __future__ import annotations

import json
import xml.sax.saxutils as sax
from collections import defaultdict

from app.analysis import knowledge_graph as KG

_CATEGORY_TO_SECTION = {
    "manifest": "manifest_diff",
    "semantics": "semantic_diff",
    "code": "code_diff",
    "native": "native_diff",
    "dependency": "dependency_diff",
    "cve": "cve_diff",
    "finding": "finding_diff",
    "root_cause": "root_cause_diff",
    "attack_surface": "attack_surface_diff",
    "reachability": "reachability_diff",
    "runtime": "runtime_diff",
}


def _change_dict(c) -> dict:
    return {"category": c.category, "entity_type": c.entity_type, "identity": c.entity_identity,
            "change_type": c.change_type, "baseline": c.baseline_value, "candidate": c.candidate_value,
            "confidence": c.confidence, "security_relevant": c.security_relevant,
            "provenance": c.provenance, "evidence": c.evidence}


def build_comparison_report(comparison) -> dict:
    baseline, candidate = comparison.baseline, comparison.candidate
    grouped: dict[str, list] = defaultdict(list)
    for c in comparison.changes:
        grouped[c.category].append(_change_dict(c))

    report = {
        "schema": "androidsecforge.comparison/1",
        "comparison": {
            "id": str(comparison.id), "fingerprint": comparison.fingerprint, "status": comparison.status,
            "snapshot_mode": comparison.snapshot_mode, "security_impact": comparison.security_impact,
            "impact_confidence": comparison.impact_confidence, "error": comparison.error,
            "created_at": _iso(comparison.created_at), "completed_at": _iso(comparison.completed_at),
            "direction": "BASELINE(A) → CANDIDATE(B)",
        },
        "baseline": _analysis_ref(baseline, comparison.snapshot_a_id),
        "candidate": _analysis_ref(candidate, comparison.snapshot_b_id),
        "summary": comparison.summary,
        "category_summaries": [
            {"category": s.category, "added": s.added, "removed": s.removed, "changed": s.changed,
             "unchanged": s.unchanged, "security_relevant": s.security_relevant}
            for s in sorted(comparison.category_summaries, key=lambda s: s.category)
        ],
    }
    for category, section in _CATEGORY_TO_SECTION.items():
        if section == "finding_diff":
            continue
        report[section] = grouped.get(category, [])

    report["finding_diff"] = [
        {"change_type": f.change_type, "rule_id": f.rule_id, "component": f.component,
         "changed_dimensions": f.changed_dimensions, "confidence": f.confidence,
         "security_relevant": f.security_relevant,
         "disposition": "NO_LONGER_DETECTED" if f.change_type == "REMOVED" else None,
         "baseline": f.baseline_value, "candidate": f.candidate_value}
        for f in comparison.finding_changes
    ]

    rd = comparison.risk_delta
    report["risk_delta"] = None if rd is None else {
        "baseline_score": rd.baseline_score, "candidate_score": rd.candidate_score, "delta": rd.delta,
        "baseline_severity": rd.baseline_severity, "candidate_severity": rd.candidate_severity,
        "severity_transition": rd.severity_transition, "baseline_confidence": rd.baseline_confidence,
        "candidate_confidence": rd.candidate_confidence, "confidence_transition": rd.confidence_transition,
        "factor_changes": rd.factor_changes,
        "note": "Risk changed according to the configured scoring model; this is not a claim about exploitability.",
    }

    report["security_impact"] = (comparison.summary or {}).get("security_impact", {
        "verdict": comparison.security_impact, "confidence": comparison.impact_confidence})
    report["uncertainties"] = _uncertainties(comparison)
    report["provenance"] = _provenance(comparison)
    return report


def _analysis_ref(analysis, snapshot_id) -> dict:
    manifest = analysis.manifest
    return {"analysis_id": str(analysis.id), "apk_sha256": analysis.apk_sha256,
            "package": manifest.package if manifest else None, "status": analysis.status,
            "snapshot_id": str(snapshot_id) if snapshot_id else None}


def _uncertainties(comparison) -> list[str]:
    out: list[str] = []
    if comparison.snapshot_mode != "SNAPSHOT":
        out.append(f"snapshot_mode={comparison.snapshot_mode}: one or both sides compared from reconstructed "
                   f"entities rather than a verified prompt-14 snapshot")
    for c in comparison.changes:
        if c.category == "cve" and "POSSIBLY_AFFECTED" in f"{c.baseline_value} {c.candidate_value}":
            out.append(f"CVE {c.entity_identity} remains POSSIBLY_AFFECTED — version match is uncertain, not upgraded")
        if c.category == "semantics" and c.evidence.get("unknown_target"):
            out.append(f"{c.entity_type} {c.entity_identity} targets an UNKNOWN destination (preserved)")
    for f in comparison.finding_changes:
        if f.change_type == "REMOVED":
            out.append(f"finding {f.rule_id}@{f.component or '-'} is NO_LONGER_DETECTED — not proven fixed")
    # de-dupe preserving order
    seen, uniq = set(), []
    for u in out:
        if u not in seen:
            seen.add(u); uniq.append(u)
    return uniq


def _provenance(comparison) -> dict:
    sources = defaultdict(int)
    for c in comparison.changes:
        sources[c.provenance] += 1
    return {"comparison_fingerprint": comparison.fingerprint,
            "baseline_snapshot": str(comparison.snapshot_a_id) if comparison.snapshot_a_id else None,
            "candidate_snapshot": str(comparison.snapshot_b_id) if comparison.snapshot_b_id else None,
            "snapshot_mode": comparison.snapshot_mode,
            "change_sources": dict(sources),
            "note": "Every change carries baseline/candidate values, source provenance, confidence, and evidence; "
                    "the comparison is auditable without re-running analysis."}


# ---------------------------------------------------------------------------
# Graph-delta export (ADDED / REMOVED / UNCHANGED / CHANGED)
# ---------------------------------------------------------------------------


def _delta_graph(baseline, candidate) -> dict:
    kg_a = KG.build_knowledge_graph(baseline)
    kg_b = KG.build_knowledge_graph(candidate)
    nodes: dict[str, dict] = {}
    for nid, n in kg_a.nodes.items():
        nodes[nid] = {"id": nid, "type": n.node_type, "label": n.label, "status": "REMOVED",
                      "baseline": {"confidence": n.confidence, "status": n.status},
                      "provenance": sorted({p.source_type for p in n.provenance})}
    for nid, n in kg_b.nodes.items():
        if nid in nodes:
            a = kg_a.nodes[nid]
            changed = (a.confidence != n.confidence) or (a.status != n.status)
            nodes[nid]["status"] = "CHANGED" if changed else "UNCHANGED"
            nodes[nid]["candidate"] = {"confidence": n.confidence, "status": n.status}
        else:
            nodes[nid] = {"id": nid, "type": n.node_type, "label": n.label, "status": "ADDED",
                          "candidate": {"confidence": n.confidence, "status": n.status},
                          "provenance": sorted({p.source_type for p in n.provenance})}

    edges_a = {e.identity_key(): e for e in kg_a.edges}
    edges_b = {e.identity_key(): e for e in kg_b.edges}
    edges: list[dict] = []
    for key, e in edges_a.items():
        status = "UNCHANGED" if key in edges_b else "REMOVED"
        edges.append(_edge_delta(e, status))
    for key, e in edges_b.items():
        if key not in edges_a:
            edges.append(_edge_delta(e, "ADDED"))
    return {"nodes": list(nodes.values()), "edges": edges}


def _edge_delta(e, status) -> dict:
    return {"source": e.src, "target": e.dst, "type": e.edge_type, "status": status,
            "confidence": e.confidence, "provenance": sorted({p.source_type for p in e.provenance})}


def graph_delta_json(baseline, candidate) -> str:
    delta = _delta_graph(baseline, candidate)
    return json.dumps({"baseline": str(baseline.id), "candidate": str(candidate.id), **delta}, indent=2, default=str)


def graph_delta_dot(baseline, candidate) -> str:
    delta = _delta_graph(baseline, candidate)
    color = {"ADDED": "green", "REMOVED": "red", "CHANGED": "orange", "UNCHANGED": "gray"}
    lines = ["digraph androidsecforge_delta {", "  rankdir=LR;", '  node [shape=box];']
    ids: dict[str, str] = {}
    for i, n in enumerate(delta["nodes"]):
        nid = f"n{i}"; ids[n["id"]] = nid
        label = sax.escape(f'{n["status"]}\\n{n["type"]}\\n{n["label"]}').replace('"', '\\"')
        lines.append(f'  {nid} [label="{label}", color="{color.get(n["status"], "black")}"];')
    for e in delta["edges"]:
        s, d = ids.get(e["source"]), ids.get(e["target"])
        if s and d:
            label = sax.escape(f'{e["status"]}/{e["type"]}').replace('"', '\\"')
            lines.append(f'  {s} -> {d} [label="{label}", color="{color.get(e["status"], "black")}"];')
    lines.append("}")
    return "\n".join(lines)


def graph_delta_graphml(baseline, candidate) -> str:
    delta = _delta_graph(baseline, candidate)
    out = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '  <key id="ntype" for="node" attr.name="type" attr.type="string"/>',
        '  <key id="nlabel" for="node" attr.name="label" attr.type="string"/>',
        '  <key id="nstatus" for="node" attr.name="delta_status" attr.type="string"/>',
        '  <key id="nprov" for="node" attr.name="provenance" attr.type="string"/>',
        '  <key id="etype" for="edge" attr.name="type" attr.type="string"/>',
        '  <key id="estatus" for="edge" attr.name="delta_status" attr.type="string"/>',
        '  <graph edgedefault="directed">',
    ]
    for n in delta["nodes"]:
        out.append(f'    <node id={sax.quoteattr(n["id"])}>')
        out.append(f'      <data key="ntype">{sax.escape(n["type"])}</data>')
        out.append(f'      <data key="nlabel">{sax.escape(n["label"] or "")}</data>')
        out.append(f'      <data key="nstatus">{sax.escape(n["status"])}</data>')
        out.append(f'      <data key="nprov">{sax.escape(",".join(n["provenance"]))}</data>')
        out.append("    </node>")
    present = {n["id"] for n in delta["nodes"]}
    for i, e in enumerate(delta["edges"]):
        if e["source"] not in present or e["target"] not in present:
            continue
        out.append(f'    <edge id="e{i}" source={sax.quoteattr(e["source"])} target={sax.quoteattr(e["target"])}>')
        out.append(f'      <data key="etype">{sax.escape(e["type"])}</data>')
        out.append(f'      <data key="estatus">{sax.escape(e["status"])}</data>')
        out.append("    </edge>")
    out.append("  </graph>")
    out.append("</graphml>")
    return "\n".join(out)


def export_comparison_graph(comparison, fmt: str = "json") -> str:
    fmt = (fmt or "json").lower()
    baseline, candidate = comparison.baseline, comparison.candidate
    if fmt == "json":
        return graph_delta_json(baseline, candidate)
    if fmt == "dot":
        return graph_delta_dot(baseline, candidate)
    if fmt == "graphml":
        return graph_delta_graphml(baseline, candidate)
    if fmt in ("report", "report-json"):
        return json.dumps(build_comparison_report(comparison), indent=2, default=str)
    raise ValueError(f"unsupported comparison export format: {fmt}")


def _iso(value) -> str | None:
    return value.isoformat() if value else None

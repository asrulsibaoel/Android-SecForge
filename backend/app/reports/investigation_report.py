"""Investigation + knowledge-graph export (prompt 14): JSON / GraphML / DOT /
Markdown.

The JSON/GraphML/DOT forms serialize the projected knowledge graph (see
``app.analysis.knowledge_graph``); the Markdown form is a human investigation
report. Every claim links back to a stable evidence identifier (finding
fingerprint, CVE id, dependency ref, graph node id). No exploitability is
asserted; UNKNOWN / POSSIBLY_AFFECTED / NOT_OBSERVED states are preserved.
"""

from __future__ import annotations

import json
import xml.sax.saxutils as sax

from app.analysis import investigation as INV
from app.analysis import knowledge_graph as KG
from app.analysis.finding_explorer import explain_finding


# ---------------------------------------------------------------------------
# Knowledge-graph serialization
# ---------------------------------------------------------------------------


def graph_json(analysis) -> str:
    kg = KG.build_knowledge_graph(analysis)
    return json.dumps({
        "analysis_id": kg.analysis_id, "graph_version": KG.GRAPH_VERSION, "truncated": kg.truncated,
        "digest": KG.graph_digest(kg),
        "nodes": [n.to_dict() for n in kg.nodes.values()],
        "edges": [e.to_dict() for e in kg.edges],
    }, indent=2, default=str)


def graph_dot(analysis) -> str:
    kg = KG.build_knowledge_graph(analysis)
    lines = ["digraph androidsecforge_kg {", "  rankdir=LR;", '  node [shape=box];']
    ids: dict[str, str] = {}
    for i, n in enumerate(kg.nodes.values()):
        nid = f"n{i}"
        ids[n.id] = nid
        label = sax.escape(f"{n.node_type}\\n{n.label}").replace('"', '\\"')
        lines.append(f'  {nid} [label="{label}"];')
    for e in kg.edges:
        s, d = ids.get(e.src), ids.get(e.dst)
        if s and d:
            label = sax.escape(f"{e.edge_type}/{e.confidence}").replace('"', '\\"')
            lines.append(f'  {s} -> {d} [label="{label}"];')
    lines.append("}")
    return "\n".join(lines)


def graph_graphml(analysis) -> str:
    kg = KG.build_knowledge_graph(analysis)
    out = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '  <key id="ntype" for="node" attr.name="type" attr.type="string"/>',
        '  <key id="nlabel" for="node" attr.name="label" attr.type="string"/>',
        '  <key id="nconf" for="node" attr.name="confidence" attr.type="string"/>',
        '  <key id="nstatus" for="node" attr.name="status" attr.type="string"/>',
        '  <key id="nprov" for="node" attr.name="provenance" attr.type="string"/>',
        '  <key id="etype" for="edge" attr.name="type" attr.type="string"/>',
        '  <key id="econf" for="edge" attr.name="confidence" attr.type="string"/>',
        '  <key id="efp" for="edge" attr.name="fingerprint" attr.type="string"/>',
        '  <graph edgedefault="directed">',
    ]
    for n in kg.nodes.values():
        prov = ",".join(sorted({p.source_type for p in n.provenance}))
        out.append(f"    <node id={sax.quoteattr(n.id)}>")
        out.append(f'      <data key="ntype">{sax.escape(n.node_type)}</data>')
        out.append(f'      <data key="nlabel">{sax.escape(n.label or "")}</data>')
        out.append(f'      <data key="nconf">{sax.escape(n.confidence or "")}</data>')
        out.append(f'      <data key="nstatus">{sax.escape(n.status or "")}</data>')
        out.append(f'      <data key="nprov">{sax.escape(prov)}</data>')
        out.append("    </node>")
    for i, e in enumerate(kg.edges):
        out.append(f'    <edge id="e{i}" source={sax.quoteattr(e.src)} target={sax.quoteattr(e.dst)}>')
        out.append(f'      <data key="etype">{sax.escape(e.edge_type)}</data>')
        out.append(f'      <data key="econf">{sax.escape(e.confidence or "")}</data>')
        out.append(f'      <data key="efp">{sax.escape(e.fingerprint)}</data>')
        out.append("    </edge>")
    out.append("  </graph>")
    out.append("</graphml>")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Markdown investigation report
# ---------------------------------------------------------------------------


def investigation_markdown(analysis, inv) -> str:
    manifest = analysis.manifest
    L: list[str] = []
    a = L.append

    a(f"# Investigation — {inv.name}")
    a("")
    a("## Scope")
    a("")
    a(f"- APK sha256: `{analysis.apk_sha256}`")
    if manifest and manifest.package:
        a(f"- Package: `{manifest.package}`")
    a(f"- Analysis: `{analysis.id}` (status {analysis.status})")
    a(f"- Investigation: `{inv.id}` (created by {inv.created_by})")
    a(f"- Pinned nodes: {len(inv.nodes)}, findings: {len(inv.findings)}, hypotheses: {len(inv.hypotheses)}")
    a("")

    findings = sorted(analysis.findings, key=lambda f: (_sev(f.severity), f.rule_id))
    a("## Findings")
    a("")
    if not findings:
        a("_No findings._")
    for f in findings:
        fp = f.fingerprint or f.rule_id
        rt = f" runtime={f.runtime_status}" if f.runtime_status and f.runtime_status != "STATIC_ONLY" else ""
        a(f"- **{f.severity.upper()}** [{f.status}] `{f.rule_id}` — {f.title} "
          f"(component: {f.component or '-'}; confidence: {f.confidence}{rt}) "
          f"[evidence: `FINDING:{fp}`]")
    a("")

    a("## Root Causes")
    a("")
    if not analysis.root_causes:
        a("_No aggregated root causes._")
    for rc in sorted(analysis.root_causes, key=lambda r: _sev(r.severity)):
        a(f"- **{rc.severity.upper()}** {rc.title} — {rc.category} "
          f"({len(rc.findings)} findings) [`ROOT_CAUSE:{rc.identifier}`]")
    a("")

    a("## Attack Surface")
    a("")
    if not analysis.attack_surface_nodes:
        a("_No attack-surface nodes._")
    for n in sorted(analysis.attack_surface_nodes, key=lambda n: -n.risk_score)[:50]:
        a(f"- {n.exposure} · risk {n.risk_score} · {n.name} [`ATTACK_SURFACE_NODE:{n.node_key}`]")
    a("")

    a("## Evidence")
    a("")
    a("Evidence chains are traceable by finding fingerprint; each finding's steps trace to persisted evidence.")
    for f in findings[:30]:
        fp = f.fingerprint or f.rule_id
        a(f"- `FINDING:{fp}`:")
        for i, e in enumerate(f.evidence):
            a(f"  {i + 1}. ({e.source}) {e.detail} [`EVIDENCE:{fp}:{i}`]")
    a("")

    a("## Reachability Paths")
    a("")
    reachable = [p for p in analysis.reachability_paths if p.status == "REACHABLE"]
    if not reachable:
        a("_No proven reachable source→sink paths._")
    for p in sorted(reachable, key=lambda p: p.length)[:40]:
        chain = " → ".join(n.get("label") for n in (p.nodes or []))
        a(f"- [{p.status}/{p.confidence}] {chain}")
    a("")

    a("## Dependencies")
    a("")
    if not analysis.dependencies:
        a("_No dependencies identified._")
    for d in sorted(analysis.dependencies, key=lambda d: (d.kind, d.name))[:80]:
        a(f"- `{d.name}` {d.version or 'UNKNOWN'} ({d.ecosystem}/{d.kind}; identity {d.identity_confidence}, "
          f"version {d.version_confidence}) [`DEP:{d.ecosystem}:{d.name}:{d.version or 'UNKNOWN'}`]")
    a("")

    a("## CVEs")
    a("")
    if not analysis.vulnerability_matches:
        a("_No CVE matches._")
    for m in analysis.vulnerability_matches:
        a(f"- `{m.cve_id}` on `{m.dependency.name}` — version_state **{m.version_state}**, "
          f"correlation **{m.correlation_state}**, reachability {m.reachability_state} "
          f"(severity {m.severity or '-'}) [`CVE:{m.cve_id}`]")
    if analysis.vulnerability_matches:
        a("")
        a("> POSSIBLY_AFFECTED and UNKNOWN states are preserved as-is and are never upgraded to AFFECTED.")
    a("")

    a("## Runtime Observations")
    a("")
    obs = [(s, o) for s in analysis.runtime_sessions for o in s.observations]
    if not obs:
        a("_No runtime observations (runtime lab not run, or UNAVAILABLE)._")
    for s, o in obs[:100]:
        tok = f"{o.class_name}.{o.method_name}" if o.class_name else (o.symbol or "")
        a(f"- [{o.observation_type}] {tok} (source {o.source}) [`RUNTIME_OBSERVATION:{o.id}`]")
    if obs:
        a("")
        a("> Runtime observations corroborate static findings; NOT_OBSERVED does not mean safe.")
    a("")

    a("## Hypotheses")
    a("")
    if not inv.hypotheses:
        a("_No researcher hypotheses._")
    for h in inv.hypotheses:
        a(f"- **[{h.status}]** {h.statement}")
        if h.rationale:
            a(f"  - rationale: {h.rationale}")
        for e in h.evidence:
            a(f"  - evidence: {e.ref_type} `{e.ref_id}` {('— ' + e.detail) if e.detail else ''}")
    a("")
    a("_Hypotheses are researcher annotations and do not modify any finding severity, confidence, or status._")
    a("")

    # Aggregate uncertainties + limitations across findings (deterministic order).
    uncertainties: list[str] = []
    limitations: list[str] = []
    for f in findings:
        ex = explain_finding(analysis, f)
        for u in ex["UNCERTAINTIES"]:
            if u not in uncertainties:
                uncertainties.append(u)
        for lim in ex["LIMITATIONS"]:
            if lim not in limitations:
                limitations.append(lim)

    a("## Uncertainties")
    a("")
    if not uncertainties:
        a("_None recorded._")
    for u in uncertainties:
        a(f"- {u}")
    a("")

    a("## Limitations")
    a("")
    if not limitations:
        a("_None recorded._")
    for lim in limitations:
        a(f"- {lim}")
    a("")

    a("## Timeline")
    a("")
    for ev in INV.timeline_view(inv):
        ts = ev["timestamp"] or "(static)"
        a(f"- {ts} · {ev['event_type']} ({ev['source']}) — {ev['detail']}")
    a("")
    return "\n".join(L)


def export_investigation(analysis, inv, fmt: str = "json") -> str:
    fmt = (fmt or "json").lower()
    if fmt == "json":
        return graph_json(analysis)
    if fmt == "dot":
        return graph_dot(analysis)
    if fmt == "graphml":
        return graph_graphml(analysis)
    if fmt in ("markdown", "md"):
        return investigation_markdown(analysis, inv)
    raise ValueError(f"unsupported investigation export format: {fmt}")


def _sev(severity: str | None) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get((severity or "").lower(), 9)

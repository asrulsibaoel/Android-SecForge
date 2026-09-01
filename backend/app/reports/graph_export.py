"""Export the existing persisted code graph to interoperable formats.

Does not build a second graph — it serializes the already-stored code_nodes /
code_edges (which include semantic and reachability edges). Node IDs are stable;
every edge carries type/confidence/evidence/source/target. No edges are
fabricated.
"""

from __future__ import annotations

import json
import xml.sax.saxutils as sax


def _node_dicts(analysis) -> list[dict]:
    return [
        {"id": n.node_key, "type": n.node_type, "label": n.label, "class": n.class_name,
         "method": n.method_name, "file": n.source_file, "line": n.line, "confidence": n.confidence}
        for n in analysis.code_nodes
    ]


def _edge_dicts(analysis) -> list[dict]:
    return [
        {"source": e.src_key, "target": e.dst_key, "type": e.edge_type,
         "confidence": e.confidence, "evidence": e.evidence, "line": e.line}
        for e in analysis.code_edges
    ]


def export_graph(analysis, fmt: str = "json") -> str:
    fmt = (fmt or "json").lower()
    if fmt == "json":
        return json.dumps({"nodes": _node_dicts(analysis), "edges": _edge_dicts(analysis)}, indent=2)
    if fmt == "dot":
        return _to_dot(analysis)
    if fmt == "graphml":
        return _to_graphml(analysis)
    raise ValueError(f"unsupported graph format: {fmt}")


def _to_dot(analysis) -> str:
    lines = ["digraph androidsecforge {", "  rankdir=LR;", '  node [shape=box];']
    ids: dict[str, str] = {}
    for i, n in enumerate(analysis.code_nodes):
        nid = f"n{i}"
        ids[n.node_key] = nid
        label = sax.escape(f"{n.node_type}\\n{n.label}").replace('"', '\\"')
        lines.append(f'  {nid} [label="{label}"];')
    for e in analysis.code_edges:
        src, dst = ids.get(e.src_key), ids.get(e.dst_key)
        if src and dst:
            label = sax.escape(f"{e.edge_type}/{e.confidence}").replace('"', '\\"')
            lines.append(f'  {src} -> {dst} [label="{label}"];')
    lines.append("}")
    return "\n".join(lines)


def _to_graphml(analysis) -> str:
    out = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '  <key id="ntype" for="node" attr.name="type" attr.type="string"/>',
        '  <key id="nlabel" for="node" attr.name="label" attr.type="string"/>',
        '  <key id="etype" for="edge" attr.name="type" attr.type="string"/>',
        '  <key id="econf" for="edge" attr.name="confidence" attr.type="string"/>',
        '  <key id="eev" for="edge" attr.name="evidence" attr.type="string"/>',
        '  <graph edgedefault="directed">',
    ]
    present = set()
    for n in analysis.code_nodes:
        nid = sax.quoteattr(n.node_key)
        present.add(n.node_key)
        out.append(f"    <node id={nid}>")
        out.append(f"      <data key=\"ntype\">{sax.escape(n.node_type)}</data>")
        out.append(f"      <data key=\"nlabel\">{sax.escape(n.label or '')}</data>")
        out.append("    </node>")
    for i, e in enumerate(analysis.code_edges):
        if e.src_key not in present or e.dst_key not in present:
            continue
        out.append(f'    <edge id="e{i}" source={sax.quoteattr(e.src_key)} target={sax.quoteattr(e.dst_key)}>')
        out.append(f"      <data key=\"etype\">{sax.escape(e.edge_type)}</data>")
        out.append(f"      <data key=\"econf\">{sax.escape(e.confidence)}</data>")
        out.append(f"      <data key=\"eev\">{sax.escape((e.evidence or '')[:200])}</data>")
        out.append("    </edge>")
    out.append("  </graph>")
    out.append("</graphml>")
    return "\n".join(out)

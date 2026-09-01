"""Knowledge-graph projection, queries, snapshot, and export tests (prompt 14).

All offline: the analysis is built directly from models (no JADX/device). These
tests assert node identity, deterministic edge fingerprints, provenance, the
named-query registry, path uncertainty, uncertainty/UNKNOWN preservation, and
graph exports — and prove analytical states are never silently upgraded.
"""

import json
from datetime import datetime, timezone

import pytest

from app.analysis import graph_queries as GQ
from app.analysis import knowledge_graph as KG
from app.analysis.finding_explorer import evidence_chain, explain_finding, explore_finding
from app.reports.investigation_report import graph_dot, graph_graphml, graph_json


# ---- node identity + projection ----

def test_node_identity_stable(make_analysis):
    a = make_analysis()
    kg1 = KG.build_knowledge_graph(a)
    kg2 = KG.build_knowledge_graph(a)
    assert set(kg1.nodes) == set(kg2.nodes)
    assert KG.apk_id(a) in kg1.nodes
    assert kg1.nodes[KG.apk_id(a)].node_type == KG.N_APK


def test_projection_covers_major_entities(make_analysis):
    a = make_analysis()
    kg = KG.build_knowledge_graph(a)
    types = {n.node_type for n in kg.nodes.values()}
    for expected in (KG.N_APK, KG.N_MANIFEST, KG.N_COMPONENT, KG.N_ANDROID_ENTRY_POINT, KG.N_FINDING,
                     KG.N_EVIDENCE, KG.N_DEPENDENCY, KG.N_CVE, KG.N_ROOT_CAUSE, KG.N_ATTACK_SURFACE_NODE,
                     KG.N_SECURITY_BOUNDARY, KG.N_RUNTIME_SESSION, KG.N_RUNTIME_OBSERVATION):
        assert expected in types, f"missing projected node type {expected}"


def test_edges_only_between_present_nodes(make_analysis):
    a = make_analysis()
    kg = KG.build_knowledge_graph(a)
    for e in kg.edges:
        assert e.src in kg.nodes and e.dst in kg.nodes


def test_no_second_graph_uses_canonical_keys(make_analysis):
    a = make_analysis()
    kg = KG.build_knowledge_graph(a)
    # Canonical code node keys are reused verbatim (not re-minted).
    assert any(k.endswith("Web#onCreate") for k in kg.nodes)


# ---- deterministic edge fingerprints ----

def test_edge_fingerprint_deterministic():
    e1 = KG.KGEdge("A", "B", "CALLS", analysis_id="x", evidence_refs=["ev"])
    e2 = KG.KGEdge("A", "B", "CALLS", analysis_id="x", evidence_refs=["ev"])
    e3 = KG.KGEdge("A", "B", "FLOWS_TO", analysis_id="x", evidence_refs=["ev"])
    assert e1.fingerprint == e2.fingerprint
    assert e1.fingerprint != e3.fingerprint


def test_edges_deduplicated_by_fingerprint(make_analysis):
    a = make_analysis()
    kg = KG.build_knowledge_graph(a)
    fps = [e.fingerprint for e in kg.edges]
    assert len(fps) == len(set(fps))


# ---- provenance ----

def test_provenance_present_on_nodes_and_edges(make_analysis):
    a = make_analysis()
    kg = KG.build_knowledge_graph(a)
    finding = a.findings[0]
    fnode = kg.nodes[KG._finding_ref(finding)]
    assert fnode.provenance and fnode.provenance[0].source_type
    ev_nodes = [n for n in kg.nodes.values() if n.node_type == KG.N_EVIDENCE]
    assert ev_nodes and all(n.provenance and n.provenance[0].evidence_id for n in ev_nodes)
    assert all(e.provenance for e in kg.edges)


def test_manifest_provenance_is_manifest(make_analysis):
    a = make_analysis()
    kg = KG.build_knowledge_graph(a)
    perm_or_component = next(n for n in kg.nodes.values() if n.node_type == KG.N_COMPONENT)
    assert perm_or_component.provenance[0].source_type == KG.P_MANIFEST


# ---- snapshot determinism ----

def test_snapshot_hash_deterministic(make_analysis):
    a = make_analysis()
    d1 = KG.graph_digest(KG.build_knowledge_graph(a))
    d2 = KG.graph_digest(KG.build_knowledge_graph(a))
    assert d1 == d2 and len(d1) == 64


def test_snapshot_differs_across_analyses(make_analysis):
    a = make_analysis(package="com.a")
    b = make_analysis(package="com.b")
    assert KG.graph_digest(KG.build_knowledge_graph(a)) != KG.graph_digest(KG.build_knowledge_graph(b))


def test_build_snapshot_persists(make_analysis, db_session):
    a = make_analysis()
    snap = KG.build_snapshot(a, datetime.now(timezone.utc))
    db_session.flush()
    assert snap.node_count > 0 and snap.edge_count > 0 and snap.finding_count == 3
    assert snap in a.graph_snapshots


# ---- named queries ----

def test_query_registry_runs(make_analysis):
    a = make_analysis()
    for name in GQ.available_queries():
        result = GQ.run_query(a, name, {"component": "com.x.Web"})
        assert "results" in result and "count" in result


def test_unknown_query_raises(make_analysis):
    a = make_analysis()
    with pytest.raises(ValueError):
        GQ.run_query(a, "does-not-exist", {})


def test_exported_components_query(make_analysis):
    a = make_analysis()
    r = GQ.run_query(a, "exported-components", {})
    assert r["count"] == 1 and r["results"][0]["name"].endswith(".Web")


def test_external_to_webview_query(make_analysis):
    a = make_analysis()
    r = GQ.run_query(a, "external-to-webview", {})
    assert r["count"] >= 1
    assert any("WebView.loadUrl" in step for row in r["results"] for step in row["chain"])


def test_cve_reachable_and_possibly_affected_preserved(make_analysis):
    a = make_analysis()
    reachable = GQ.run_query(a, "cve-reachable", {})
    possibly = GQ.run_query(a, "possibly-affected", {})
    assert any(m["cve_id"] == "CVE-2020-0002" for m in reachable["results"])
    # POSSIBLY_AFFECTED must remain POSSIBLY_AFFECTED (never upgraded to AFFECTED).
    assert possibly["count"] == 1
    assert possibly["results"][0]["version_state"] == "POSSIBLY_AFFECTED"


def test_runtime_not_observed_is_not_safe(make_analysis):
    a = make_analysis()
    r = GQ.run_query(a, "runtime-not-observed", {})
    assert r["count"] == 1
    assert "not" in r["note"].lower() and "safe" in r["note"].lower()
    # No result is ever relabeled SAFE.
    assert all(row["validation_state"] == "NOT_OBSERVED" for row in r["results"])


def test_unknown_boundaries_query(make_analysis):
    a = make_analysis()
    r = GQ.run_query(a, "unknown-boundaries", {})
    assert any(row["boundary_type"] == "BINDER_IPC" or row["confidence"].upper() in ("LOW", "UNKNOWN")
               for row in r["results"])


# ---- path investigation + uncertainty ----

def test_path_investigation_finds_path_and_surfaces_uncertainty(make_analysis):
    a = make_analysis()
    r = GQ.investigate_paths(a, "Web", "loadUrl")
    assert r["status"] == "REACHABLE" and r["count"] >= 1
    # The unresolved reflection target must be surfaced, never silently dropped.
    assert any(u["target"].endswith("UNKNOWN") for u in r["uncertainty"])


def test_unreachable_with_unknown_boundary_is_unknown_not_not_reachable(make_analysis):
    a = make_analysis()
    # sink:exec exists but has no incoming edge; the start has an UNKNOWN reflection target.
    r = GQ.investigate_paths(a, "Web", "Runtime.exec")
    assert r["count"] == 0
    assert r["status"] == "UNKNOWN"  # not silently NOT_REACHABLE


def test_unrelated_nodes_have_no_path(make_analysis):
    a = make_analysis()
    r = GQ.investigate_paths(a, "A.foo", "B.bar")
    assert r["count"] == 0 and r["status"] == "NOT_REACHABLE"


def test_max_depth_enforced(make_analysis):
    a = make_analysis()
    shallow = GQ.investigate_paths(a, "Web", "loadUrl", max_depth=1)
    deep = GQ.investigate_paths(a, "Web", "loadUrl", max_depth=10)
    assert shallow["count"] == 0  # a path needs >= 2 nodes; depth 1 admits none
    assert deep["count"] >= 1
    assert shallow["bounds"]["max_depth"] == 1


def test_low_confidence_not_upgraded(make_analysis):
    a = make_analysis()
    r = GQ.investigate_paths(a, "Web", "loadData")  # traverses a LOW edge
    assert r["count"] >= 1
    assert any(p["confidence"] == "LOW" for p in r["paths"])  # min-confidence preserved, never HIGH


def test_min_confidence_filters_low_edges(make_analysis):
    a = make_analysis()
    r = GQ.investigate_paths(a, "Web", "loadData", min_confidence="MEDIUM")
    assert r["count"] == 0  # the only route uses a LOW edge, filtered out


# ---- explanation engine ----

def test_explain_finding_no_exploitable_claim(make_analysis):
    a = make_analysis()
    reach = next(f for f in a.findings if f.rule_id == "ANDROID-REACH-001")
    ex = explain_finding(a, reach)
    assert ex["WHY_FOUND"] and ex["EVIDENCE_CHAIN"]
    blob = json.dumps(ex).lower()
    assert "exploitable" not in blob and "validated" not in blob
    assert any("runtime" in u.lower() for u in ex["UNCERTAINTIES"])


def test_evidence_chain_traces_provenance(make_analysis):
    a = make_analysis()
    reach = next(f for f in a.findings if f.rule_id == "ANDROID-REACH-001")
    chain = evidence_chain(a, reach)
    assert chain["fingerprint"] and chain["chain"]
    assert chain["chain"][0]["provenance"]


def test_explore_finding_preserves_cve_state(make_analysis):
    a = make_analysis()
    cve = next(f for f in a.findings if f.category == "cve")
    bundle = explore_finding(a, cve)
    assert bundle["cve_matches"]
    assert any(m["version_state"] == "POSSIBLY_AFFECTED" for m in bundle["cve_matches"])
    # graph neighbours available for exploration
    assert isinstance(bundle["graph_neighbors"], list)


# ---- exports ----

def test_graph_json_export(make_analysis):
    a = make_analysis()
    data = json.loads(graph_json(a))
    assert data["nodes"] and data["edges"] and len(data["digest"]) == 64
    assert all("provenance" in n for n in data["nodes"])


def test_graph_graphml_export(make_analysis):
    a = make_analysis()
    out = graph_graphml(a)
    assert out.startswith("<?xml") and "<graphml" in out and "provenance" in out


def test_graph_dot_export(make_analysis):
    a = make_analysis()
    out = graph_dot(a)
    assert out.startswith("digraph") and "->" in out


# ---- cross-analysis isolation ----

def test_no_cross_analysis_contamination(make_analysis):
    a = make_analysis(package="com.a")
    b = make_analysis(package="com.b")
    kg_a = KG.build_knowledge_graph(a)
    # Every node in A's graph is stamped with A's analysis id — the projection is
    # per-analysis and never merges two analyses (content-derived finding IDs may
    # coincide for identical findings, but the graphs stay isolated).
    assert all(n.analysis_id == str(a.id) for n in kg_a.nodes.values())
    assert all(e.analysis_id == str(a.id) for e in kg_a.edges)
    # B's APK node (sha-derived, unique) is never present in A's graph.
    assert KG.apk_id(b) not in kg_a.nodes
    # Edges never dangle to a node outside A's graph.
    for e in kg_a.edges:
        assert e.src in kg_a.nodes and e.dst in kg_a.nodes

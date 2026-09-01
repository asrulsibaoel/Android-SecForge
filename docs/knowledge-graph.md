# Knowledge graph

AndroidSecForge exposes an **evidence-centric knowledge graph** on top of the
existing analysis model. It is a *projection*, not a second graph: the canonical
graph remains `code_nodes` / `code_edges` (plus the semantic and reachability
edges folded into them at analysis time). The projection
(`app/analysis/knowledge_graph.py`) reads the already-persisted entities and
unifies them into one node/edge view with provenance on every relationship.

## Why a projection (and not a new graph)

- The canonical code/reachability graph stays authoritative. Nothing is copied
  into a competing representation.
- Code-graph node keys (`com.pkg.Class#method`, `sink:…`, `entry:…`) are reused
  **verbatim** as knowledge-graph node IDs, so canonical edges connect natively.
- Higher-level entities (APK, manifest, components, dependencies, CVEs,
  findings, root causes, attack surface, runtime) are projected as additional
  nodes and joined with relationship edges that already exist in the database.

## Node categories

`APK`, `MANIFEST`, `PERMISSION`, `COMPONENT`, `ANDROID_ENTRY_POINT`,
`CODE_CLASS`, `CODE_METHOD`, `CODE_FIELD`, `NATIVE_LIBRARY`, `NATIVE_FUNCTION`,
`JNI_BINDING`, `DEPENDENCY`, `CVE`, `FINDING`, `EVIDENCE`, `ROOT_CAUSE`,
`ATTACK_SURFACE_NODE`, `SECURITY_BOUNDARY`, `RUNTIME_DEVICE`, `RUNTIME_SESSION`,
`RUNTIME_PROCESS`, `RUNTIME_OBSERVATION` (plus `SOURCE`, `SECURITY_SINK`,
`ANDROID_FRAMEWORK` carried through from the code graph).

Each node carries: stable **id**, **node_type**, human **label**, **analysis_id**,
**source_entity_id** (the DB row it projects), **confidence**, **status**,
**provenance** (list), and **metadata**.

### Node identity

IDs are stable and content-derived so the same persisted analysis always
projects to the same identities:

| Category | ID form |
| --- | --- |
| APK | `APK:{sha256}` |
| Manifest | `MANIFEST:{package}` |
| Permission | `PERMISSION:{name}` |
| Component | `COMPONENT:{name}` |
| Entry point | `ANDROID_ENTRY_POINT:{component}.{method}` |
| Code method | canonical `{fqcn}#{method}` (reused) |
| Native library | `NATIVE_LIBRARY:{archive_path}` |
| Dependency | `DEP:{ecosystem}:{name}:{version|UNKNOWN}` |
| CVE | `CVE:{cve_id}` |
| Finding | `FINDING:{fingerprint}` |
| Evidence | `EVIDENCE:{finding_fp}:{index}` |
| Root cause | `ROOT_CAUSE:{identifier}` |
| Runtime observation | `RUNTIME_OBSERVATION:{uuid}` |

Content-derived finding IDs mean an *identical* finding in two APKs shares an ID
— useful for future APK-diff — while each projected graph stays per-analysis
(`analysis_id` stamped on every node/edge; the projection never merges two
analyses).

## Edge types

`CONTAINS`, `DECLARES`, `REQUESTS`, `EXPORTS`, `DISPATCHES_TO`, `CALLS`,
`FLOWS_TO`, `BINDS_TO`, `DEPENDS_ON`, `MATCHES_CVE`, `SUPPORTS`, `CAUSED_BY`,
`EVIDENCE_FOR`, `EXPOSES`, `REACHES`, `LEADS_TO`, `CROSSES`, `OBSERVED_AT`,
`OBSERVED_ON`, `CORROBORATES`, `CORRELATES_WITH`, `ROOT_CAUSE_OF`, `AFFECTS`,
`RELATED_TO`, plus the canonical code/semantic edge types
(`INVOKES`, `FRAMEWORK_DISPATCH`, `WEBVIEW_BRIDGE`, `REFLECTION_TARGET`, …).

Every edge carries: **source**, **target**, **edge_type**, **confidence**,
**provenance**, **evidence_refs**, **analysis_id**, **created_at**, and a
deterministic **fingerprint** (see [graph-integrity](graph-integrity.md)). An
edge is added only when both endpoints exist in the projection — a relationship
is never invented from name similarity.

## Snapshots

`build_snapshot(analysis, now)` records node/edge/finding/root-cause/observation
counts plus a deterministic content **digest** into `graph_snapshots`. The
analysis pipeline builds one automatically in the `graph_snapshot` stage. See
[graph-integrity](graph-integrity.md#snapshot-hashing).

## Usage

```bash
androidsecforge graph kg <analysis-id> --format json      # or graphml / dot
androidsecforge graph snapshot <analysis-id> --json       # deterministic digest
```

REST: `GET /api/v1/analysis/{id}/graph/knowledge?format=json|graphml|dot`,
`GET /api/v1/analysis/{id}/graph/snapshot`.

See also: [investigation](investigation.md), [provenance](provenance.md),
[graph-queries](graph-queries.md), [investigation-export](investigation-export.md),
[graph-integrity](graph-integrity.md).

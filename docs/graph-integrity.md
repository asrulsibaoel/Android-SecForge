# Graph integrity, snapshots & performance

## Integrity — researcher state never overwrites truth

The investigation workspace is strictly separate from analytical evidence:

- Researcher **notes** and **hypotheses** live in their own tables and are never
  merged into finding descriptions or evidence.
- A **hypothesis** status (`OPEN`/`SUPPORTED`/`REFUTED`/`UNKNOWN`) is researcher
  state only. Setting it — or attaching evidence — changes **no** finding
  severity, confidence, or status, and never touches risk or the graph. It is
  never auto-promoted.
- **Runtime** observations corroborate but never overwrite static findings, and
  `NOT_OBSERVED` never becomes `SAFE` (see [runtime-correlation](runtime-correlation.md)).
- **CVE** matches never modify dependency identity, and `POSSIBLY_AFFECTED` /
  `UNKNOWN` are never inferred to `AFFECTED`.
- **Risk** scores cannot be changed by a note or hypothesis.
- Projected edges connect only nodes that both exist; a relationship is never
  invented from name similarity, and the projection is per-analysis
  (`analysis_id` stamped on every node/edge — two analyses never connect).

These invariants are covered by negative tests in `tests/test_investigation.py`
and `tests/test_knowledge_graph.py` (POSSIBLY_AFFECTED stays POSSIBLY_AFFECTED;
UNKNOWN stays UNKNOWN not NOT_REACHABLE; NOT_OBSERVED ≠ safe; LOW confidence is
never upgraded; hypotheses/notes never alter findings; unrelated nodes yield no
path; cross-analysis nodes never connect).

## Edge identity (fingerprint)

Each edge has a deterministic fingerprint:

```
sha256( analysis_id | src | edge_type | dst | sorted(evidence_refs) )[:24]
```

Same inputs → same fingerprint; a different edge type or endpoint → different
fingerprint. Fingerprints deduplicate edges within a projection and give edges a
stable identity across re-projections of the same analysis.

## Snapshot hashing

`graph_digest(kg)` is a deterministic content hash:

```
sha256( sorted("{type}\x1f{id}" for nodes) + "--edges--" + sorted(edge fingerprints) )
```

The same persisted analysis therefore always produces the same 64-hex digest
(verified live: two snapshots of the same APK produced identical digests), while
different analyses differ (the `APK:{sha}` node alone guarantees it). A
`GraphSnapshot` row records the digest plus node/edge/finding/root-cause/
observation counts and per-type histograms, enabling regression comparison and
future APK diff. The analysis pipeline writes one in the `graph_snapshot` stage;
`graph snapshot <id>` writes another on demand.

> Note: timestamps are passed in explicitly (`build_snapshot(analysis, now)`);
> the digest itself is computed only from node/edge identity, so it does not
> depend on wall-clock time.

## Performance

The projection and all traversals are bounded so large real APKs degrade
gracefully (Magisk, ~18k nodes / ~16k edges, projects and snapshots in-process):

- projection caps: `graph_max_projected_nodes` (default 40000),
  `graph_max_projected_edges` (120000). Code-graph nodes referenced by
  findings/paths/entry points/boundaries are **always** kept so evidence chains
  stay traversable even under truncation (`truncated` flag is surfaced).
- path/query bounds: `graph_query_max_depth` (25), `graph_query_max_paths` (100),
  `graph_query_max_nodes` (200000), `graph_query_timeout_seconds` (15), plus
  `--min-confidence` filtering.
- adjacency + reverse indexes; no N×M scans; the full graph is not materialized
  into a second store.

All bounds are configurable via `ASF_GRAPH_*` environment variables.

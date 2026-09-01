# Graph export

`graph export` serializes the **existing** persisted code graph — it does not
build a second graph. Nodes come from `code_nodes`; edges from `code_edges`,
which already include Java call edges, JNI/native edges, semantic edges
(`FRAMEWORK_DISPATCH`, `SECURITY_BOUNDARY`, `DEEP_LINK`, `WEBVIEW_BRIDGE`,
`REFLECTION_TARGET`, `DYNAMIC_LOAD`, …), and reachability edges. No edge is
fabricated.

## Formats

```bash
androidsecforge graph export <analysis-id> --format json     # {nodes:[...], edges:[...]}
androidsecforge graph export <analysis-id> --format dot      # Graphviz digraph
androidsecforge graph export <analysis-id> --format graphml  # GraphML for Gephi/yEd/Cytoscape
```

REST: `GET /api/v1/analysis/{id}/graph/export?format=json|dot|graphml`.

## Guarantees

- **Stable node IDs**: the graph node key (`node_key`) is the exported id.
- **Edge provenance**: every edge retains `type`, `confidence`, `evidence`,
  `source`, and `target`.
- The output is self-contained and loadable by external visualization tools.

## Note

Edge count reflects what analysis produced: with JADX unavailable there is no
Java call graph, so a manifest/native-only analysis exports few edges (entry
points, boundaries, native symbols) — honestly, not a fabricated dense graph.

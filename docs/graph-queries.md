# Graph queries

The query layer (`app/analysis/graph_queries.py`) is a small **safe** query
abstraction: a fixed registry of named, deterministic queries plus a bounded
path-investigation primitive. It is **not** an arbitrary-code execution
mechanism — there is no query string interpreter, only vetted queries over the
persisted entities and the canonical graph.

Every query returns a structured result (`{query, description, count, results,
…}`) and preserves analytical states verbatim: `UNKNOWN`, `POSSIBLY_AFFECTED`,
`NOT_REACHABLE`, and `NOT_OBSERVED` are never upgraded.

## CLI

```bash
androidsecforge graph queries                                   # list queries
androidsecforge graph query <name> --analysis <id> [--json] \
    [--min-confidence LOW|MEDIUM|HIGH] [--max-depth N] [--component NAME]
```

REST: `GET /api/v1/analysis/{id}/graph/query?name=<name>&min_confidence=&max_depth=&component=`

## Named queries

| Name | Returns |
| --- | --- |
| `exported-components` | components externally reachable (Android exposure semantics) |
| `public-attack-surface` | attack-surface nodes classified `PUBLIC` |
| `findings-reachable-from-exported` | findings sited on exported components |
| `external-to-webview` | paths from an external entry point to a WebView sink |
| `external-to-exec` | paths from an external entry point to a command/loader sink |
| `exported-to-jni` | paths from exported entry points crossing the JNI boundary |
| `cve-reachable` | CVE matches with `AFFECTED_REACHABLE` |
| `possibly-affected` | dependencies `POSSIBLY_AFFECTED` (never upgraded) |
| `dependencies-with-cve` | dependencies with ≥1 CVE match |
| `runtime-confirmed` | findings observed/supported at runtime |
| `runtime-not-observed` | findings `NOT_OBSERVED` (≠ safe) |
| `unknown-boundaries` | security/Binder boundaries with `LOW`/`UNKNOWN` confidence |
| `webview-bridges` | WebView JS-bridge boundaries |
| `reflection-paths` | reflection targets (unresolved stay `UNKNOWN`) |
| `dynamic-load-paths` | dynamic code-load sites (unresolved stay `UNKNOWN`) |
| `high-risk-entrypoints` | attack-surface nodes with `risk_score ≥ threshold` |
| `findings-crossing-jni` | findings whose evidence crosses the JNI boundary |
| `findings-involving-native` | findings involving a native library |
| `root-causes-for-component` | root causes affecting `--component` |

When a query cannot be proven (e.g. no WebView sink exists), it returns an empty
result with `status: NOT_APPLICABLE` and a `reason` — it never invents a result.

## Path investigation

`investigate_paths` (also `investigate path`, and
`GET /api/v1/investigations/{id}/paths`) runs a bounded BFS between node sets
matched by `--from` / `--to`:

```
--from NODE   --to NODE   --max-depth N   --min-confidence LOW|MEDIUM|HIGH
```

It returns each path's node metadata, edge types, evidence, and a path
confidence equal to the **minimum** edge confidence (never rounded up). Crucially,
it surfaces **uncertainty boundaries**: unresolved reflection / dynamic-load
targets reachable from path nodes are reported in an `uncertainty` list, and if
no concrete path exists but the start set has unresolved targets, the status is
`UNKNOWN` rather than `NOT_REACHABLE`. Uncertainty is never silently truncated.

## Bounds

All traversals are bounded (see [graph-integrity](graph-integrity.md#performance)):
`--max-depth`, max paths, max nodes, a wall-clock timeout, and confidence
filtering. Large real APKs degrade gracefully rather than hanging.

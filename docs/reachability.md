# Dataflow & reachability engine

The reachability engine (`backend/app/analysis/reachability.py`) connects the
existing analysis layers to answer: *can an attack-surface entry point or external
input be statically connected to a security-relevant operation?* Results are
`REACHABLE`, `NOT_REACHABLE`, or `UNKNOWN` — and `UNKNOWN` is never silently turned
into `NOT_REACHABLE`.

## Code graph

Nodes: `COMPONENT`/`ENTRY_POINT`, `JAVA_METHOD`, `SOURCE`, `SECURITY_SINK`,
`NATIVE_LIBRARY`, `NATIVE_FUNCTION`, `JNI_BINDING`. Edges: `DECLARES`, `CALLS`,
`INVOKES`, `ACQUIRES`, `FLOWS_TO`, `BINDS_TO`, `DEPENDS_ON`, `LOADS_LIBRARY`. An
edge is created only when supported by evidence.

Persisted relationally in `code_nodes`, `code_edges`, `dataflow_sources`,
`security_sinks`, `entry_points`, `reachability_paths` (persistence is bounded by
`ASF_REACH_MAX_PERSISTED_NODES` / `_EDGES`).

## Java call graph (conservative)

Built from JADX-decompiled Java with a string/comment-masked, brace-matched
parser. Resolution:

- unqualified same-class call `foo(...)` → `ThisClass#foo` (MEDIUM)
- `Type.method(...)` where `Type` is a known class → `Type#method` (MEDIUM)
- `local.method(...)` where `local`'s declared type is known → that class (LOW)

Unresolved dynamic dispatch is left out rather than guessed. Nothing is
fabricated; ambiguous edges are LOW confidence.

## Sources & sinks

Declarative signatures live in `backend/app/analysis/signatures.py`. Sources
include `Intent.getStringExtra/getData/getParcelableExtra`, `Bundle.get*`,
`Uri.getQueryParameter/getPath`, and network/webview input. Java sinks include
`Runtime.exec`, `ProcessBuilder`, `WebView.loadUrl/evaluateJavascript/
addJavascriptInterface`, reflection, dynamic class loading, file write, and raw
SQL. Native sinks are dangerous imported symbols (`strcpy`, `system`, …). All are
`SECURITY_RELEVANT_SINK`, never automatically a vulnerability.

## Dataflow

- **Intra-method taint**: `x = source(); … sink(… x …)` creates a `FLOWS_TO`
  edge from the source to the sink (MEDIUM).
- **Inter-procedural**: reachability follows resolved `CALLS` edges from an entry
  method to a sink-containing method (bounded BFS).

## JNI boundary

A Java `native` method links `BINDS_TO` a `JNI_BINDING` and then to the
`NATIVE_FUNCTION`, carrying the binding's confidence (HIGH/MEDIUM/LOW) — never
upgraded. Without Ghidra there is no native call graph, so the chain honestly
stops at the native boundary (that is `ANDROID-REACH-003`); a JNI export is never
fabricated to reach `strcpy`.

## Path search & findings

Bounded BFS (default depth `ASF_REACH_MAX_DEPTH=50`, cycle-free) finds shortest
paths from entry points / sources to sinks and JNI boundaries. A reachability
finding is produced **only** when a path is established:

- `ANDROID-REACH-001` external input → WebView / reflection / dynamic-load / file / SQL sink
- `ANDROID-REACH-002` external input → command execution sink
- `ANDROID-REACH-003` exported component → JNI/native boundary
- `ANDROID-REACH-004` external input → native security-relevant API (needs native call evidence)

Severity is INFO/LOW/MEDIUM only; path confidence is the weakest edge on the
chain. A source and a sink merely coexisting in the app is never a finding.

## CLI

```bash
androidsecforge graph build <analysis-id> [--json]
androidsecforge graph entrypoints <analysis-id> [--json]
androidsecforge graph sources <analysis-id> [--json]
androidsecforge graph sinks <analysis-id> [--json]
androidsecforge graph paths <analysis-id> [--from X --to Y --max-depth N] [--json]
```

`graph paths --from --to` runs a bounded relational BFS over the persisted
edges; with no `--from/--to` it lists the reachability paths found during
analysis. The JSON report adds `entry_points`, `sources`, `sinks`, `code_edges`,
and `reachability_paths`.

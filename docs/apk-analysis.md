# APK analysis pipeline

The orchestrator (`backend/app/analysis/orchestrator.py`) runs an ordered set of
stages. Each stage is isolated: a failure in one stage is recorded and the others
continue. Every stage records `name`, `status`, `duration_seconds`, `detail`, and
`errors`.

## Stages

1. `ingest` — validate the archive, hash it, store the original by SHA-256, prepare the workspace.
2. `manifest` — locate and decode `AndroidManifest.xml` ([axml.md](axml.md)); normalize into a typed model.
3. `permissions` — classify requested permissions by protection level.
4. `components` — enumerate components and compute exposure.
5. `dex` — extract every `classes*.dex` and record header counts.
6. `jadx` — decompile with JADX if available ([jadx.md](jadx.md)).
7. `code_index` — index decompiled sources into a searchable code model.
8. `rules` — run the data-driven rule engine over manifest facts and code ([rules.md](rules.md)).
9. `native` / `jni` / `ghidra` / `native_rules` — native ELF + JNI analysis ([native.md](native.md), [jni.md](jni.md), [ghidra.md](ghidra.md)).
10. `graph` / `reachability` — build the code graph and search for evidence-backed source→sink paths ([reachability.md](reachability.md)).
11. `semantics` — Android semantic layer: framework dispatch, intents, deep links, IPC, provider inputs, WebView bridges, reflection, dynamic loading, security boundaries ([semantics.md](semantics.md)).
12. `dependency_fingerprint` / `vulnerability_match` / `vulnerability_reachability` — dependency inventory + offline CVE correlation with reachability states ([cve.md](cve.md)).
13. `correlation` / `attack_surface` / `risk` — finding correlation + root causes ([correlation.md](correlation.md), [root-causes.md](root-causes.md)), attack-surface model ([attack-surface.md](attack-surface.md)), and explainable risk ([risk-engine.md](risk-engine.md)).

## Stage statuses

`COMPLETE`, `FAILED`, `UNAVAILABLE` (optional tool absent), `SKIPPED` (nothing to do / prerequisite missing), `DEGRADED` (partial input).

## Overall analysis status

- `COMPLETE` — every stage completed.
- `PARTIAL` — some stage was unavailable/skipped/failed (e.g. JADX not installed → no code analysis).
- `FAILED` — a fundamental failure (the manifest stage itself raised).

The reason for a `PARTIAL` result is always visible in the per-stage list and in `capabilities`.

## Reproducibility

Each `Analysis` records `apk_sha256`, `ruleset_version` (a content hash of the rule
catalogue), `tool_versions`, `profile`, and timestamps. Re-running on the same APK
with the same ruleset yields a comparable report.

## Outputs

- Relational rows: `analyses`, `manifests`, `permissions`, `components`, `dex_artifacts`, `code_entities`, `findings`, `evidence`, `artifacts`.
- JSON report via `androidsecforge analyze <apk> --json` or `GET /api/v1/analysis/{id}`.

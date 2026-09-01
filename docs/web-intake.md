# Web-based APK intake & analysis execution

The web intake layer (prompt 26) lets a researcher drive the **existing**
authoritative pipeline from the browser: upload an Android artifact, create an
analysis, watch real execution progress, and open the resulting workspace. It
adds **no second analysis pipeline, no second graph, and no new database table** —
durable truth remains the `APKArtifact` + `Analysis` rows produced by
`app/analysis/orchestrator.py::analyze_apk`. Live progress is ephemeral,
in-process state only.

It introduces **no `exploitable` field or conclusion** and never collapses a
result to SAFE/UNSAFE. Distinct states are preserved: an *unavailable capability*
is never reported as a successful stage, and an *analysis failure* is never
reported as "no findings".

## Supported artifact types

| Extension | Intake type | Actual support state |
|-----------|-------------|----------------------|
| `.apk`  | `APK`         | Fully analyzed by the existing pipeline |
| `.apks` | `APK_SET`     | Accepted and stored (split-APK container) |
| `.apkm` | `APKM`        | Accepted and stored (APKMirror bundle) |
| `.aab`  | `APP_BUNDLE`  | Accepted and stored (Android App Bundle) |

Classification is by extension **and** content: every upload must also be a valid
ZIP container (`app/services/apk_ingestion.py`). The backend is authoritative —
the browser's extension check is only an early hint.

## Intake workflow

```
Browser (New Analysis)                Backend
  select / drag artifacts
  client-side classify + bound  ─┐
                                 └─▶ POST /api/v1/apk/import  (multipart)
                                      ingest_apk → validate ext + ZIP,
                                      SHA-256, dedup, store {sha256}.{type}
  create analysis  ──────────────▶ POST /api/v1/analyses?artifact_id=…
                                      start_execution → daemon thread → analyze_apk
  poll progress  ────────────────▶ GET /api/v1/analysis/execution/{execution_id}
  open workspace  ───────────────▶ /analysis/{analysis_id}
```

## Upload bounds

Enforced server-side (`app/core/config.py`, `app/main.py::import_apk`):

- **per-file** ≤ `upload_max_file_size` (default 512 MiB) → oversize returns **413**.
- **empty** file → **400**.
- **unsupported extension** / non-ZIP → **400** (with a machine-readable `detail`).

The browser mirrors the per-file limit as a hint (`CLIENT_MAX`), but the backend
decision always wins.

## Duplicate handling

Intake dedups by **content SHA-256**. Re-uploading the same bytes returns the
**existing** `APKArtifact` (same `id`, same `storage_path`) instead of creating a
duplicate — provenance stays single-sourced. A new analysis can still be created
over the existing artifact.

## Storage & provenance

Artifacts are stored under the configured workspace as `{sha256}.{artifact_type}`
— a content-addressed, path-traversal-safe name derived only from the bytes, never
from the uploaded filename. The original filename is retained as metadata
(`original_filename`) and surfaced in the dashboard history, but is never used for
storage or identity.

## Analysis execution architecture

`POST /api/v1/analyses` calls `app/services/execution.py::start_execution`, which:

1. records an in-memory execution entry (state `QUEUED`),
2. spawns a **daemon thread** that opens its **own** `SessionLocal`,
3. installs a **thread-local progress sink** into the orchestrator,
4. calls the unchanged `analyze_apk(...)`,
5. maps the pipeline's terminal artifact status to an execution state,
6. releases a `BoundedSemaphore(analysis_max_concurrent_executions)` slot.

The orchestrator emits progress through the thread-local sink after each stage
(`app/analysis/orchestrator.py::_emit_progress`). Because the sink writes to the
in-memory registry — not the database — it never contends with the long-running
`analyze_apk` write transaction (SQLite is single-writer).

## Lifecycle states

`app/services/execution.py`:

| State | Meaning |
|-------|---------|
| `INTAKE_VALIDATED` | artifact accepted by intake |
| `QUEUED` | execution registered, awaiting a concurrency slot |
| `RUNNING` | pipeline in progress |
| `COMPLETED` | pipeline finished, artifact status `COMPLETE` |
| `COMPLETED_WITH_LIMITATIONS` | pipeline finished, but ≥1 capability was unavailable/degraded (artifact `PARTIAL`) |
| `FAILED` | pipeline raised; `error` carries `{code, message, stage, retryable}` |
| `CANCELLED` | reserved (see cancellation) |

`COMPLETED_WITH_LIMITATIONS` is a **first-class success-with-caveats** state, not
a failure and not a clean success. It is emitted whenever a capability such as
`jadx`, `ghidra`, `code_analysis`, `native_deep`, `reachability`, or `semantics`
was unavailable or degraded, so the absence stays visible in the UI.

## Progress model (not fabricated)

The frontend renders the full 25-stage pipeline
(`frontend/src/pages/Progress.tsx::PIPELINE_STAGES`) but colours each stage **only**
from backend-reported status. Stages the backend has not yet reported are shown
`PENDING` — never pre-marked complete. Reported statuses are passed through
verbatim: `COMPLETE`, `SKIPPED`, `UNAVAILABLE`, `PARTIAL`, `FAILED`.

Two progress endpoints:

- `GET /api/v1/analysis/execution/{execution_id}` — live, in-memory execution.
- `GET /api/v1/analysis/{analysis_id}/progress` — falls back to the persisted
  `Analysis` for analyses created by the **CLI** (which have no in-memory
  execution), so the same UI works for either origin.

## Completed-with-limitations semantics

> **unavailable capability ≠ successful analysis stage**

A stage backed by a missing tool is reported `UNAVAILABLE`/`SKIPPED`, and the
execution ends `COMPLETED_WITH_LIMITATIONS`. The `capability_limitations` list
(e.g. `jadx UNAVAILABLE`, `ghidra_deep PARTIAL`, `native_deep DEGRADED`) stays
visible on the progress screen. The workspace still opens and still shows every
finding that *was* derived — limitations narrow scope, they do not void results.

## Failure semantics

> **analysis failure ≠ no findings**

If `analyze_apk` raises, the execution is `FAILED` with a bounded, path-stripped
error (`app/services/execution.py::_bounded_message`) and the progress screen
says *failed* — it never renders an empty/zero-finding "success". A failed
execution has no `analysis_id` workspace link.

## Cancellation

The existing pipeline is a single synchronous call, so mid-run cancellation
cannot be done honestly. `POST /api/v1/analysis/execution/{id}/cancel` returns
`CANCELLATION_UNAVAILABLE` rather than pretending to stop work. This is an honest
capability limitation, not a silent no-op.

## Capability availability semantics

Intake itself requires **no new tool capability** — it is ZIP validation +
hashing, always available — so `doctor` gains **no invented intake capability**
(§34). The capabilities that shape a result (`jadx`, `ghidra`, `native_deep`, …)
are the existing, authoritative ones; the web layer only surfaces them, it does
not redefine them.

## CLI / API relationship

The web layer is a **peer entry point**, not a replacement. `analyze_apk` and the
CLI are unchanged; a CLI-created analysis is a first-class citizen in the web UI
(history, workspace, and the analysis-level progress fallback). Both paths write
the same `Analysis` rows into the same canonical graph.

## New endpoints

- `POST /api/v1/analyses?artifact_id=…` → **202**, `{execution_id, state, artifact}`
- `GET  /api/v1/analysis/execution/{execution_id}` → live execution snapshot
- `POST /api/v1/analysis/execution/{execution_id}/cancel` → `CANCELLATION_UNAVAILABLE`
- `GET  /api/v1/analysis/{analysis_id}/progress` → execution snapshot or persisted fallback

## Frontend

- Routes: `analyses/new`, `progress/execution/:executionId`, `progress/analysis/:analysisId`.
- Pages: `NewAnalysis.tsx` (drag-drop + picker, multi-file, per-file classify/bounds),
  `Progress.tsx` (stage checklist, bounded polling, limitations, workspace link).
- Dashboard history gains Artifact/Type columns and Open / View-Progress actions.

# UI architecture

## Routes

| Route | Page |
|-------|------|
| `/` | Dashboard — recent analyses, capabilities, latest investigations |
| `/analysis/:analysisId` | Analysis workspace (nested tabs, see below) |
| `/investigations` | Investigation list |
| `/investigations/:investigationId` | Investigation workspace |
| `/diff/:comparisonId` | Comparison workspace |

Analysis tabs (nested under `/analysis/:analysisId`): **Overview, Findings,
Attack Surface, Knowledge Graph, CVE Intelligence, Remediation, Validation,
Runtime, Native, Obfuscation, Assessment, Diff, Investigation, Evidence, Search.**
Each tab is backed only by existing APIs; nothing is fabricated for a section
without data.

Prompt 25 (final UI/UX polish) added the **Assessment** tab (prompt-24 decision
intelligence: overall state + conclusion explorer + per-conclusion decision chain
via `/assessment/explain/{ref}`), a bounded analysis-scoped **Search** tab, a
read-only **device-capability panel** on the Runtime tab (`/runtime/device` —
CONNECTED/UNAUTHORIZED/OFFLINE/NOT_CONNECTED, frida host vs frida-server), and
domain **MetricCards** on the Overview linking to each tab (an unavailable
capability renders `UNAVAILABLE`, never "0"). Reusable primitives live in
`src/components/primitives.tsx`: `MetricCard`, `SectionHeader`, `TruncatedBanner`,
`ProvenanceBadge`, `ConfidenceIndicator`, `DetailPanel`.

## API client (`src/api`)

`client.ts` exposes `apiGet` / `apiPost` returning a discriminated
`ApiResult<T>` with `status ∈ { loading, success, empty, not_found, bad_request,
server_error, unavailable, network_error }`. `index.ts` provides one typed
function per backend endpoint; `types.ts` mirrors the JSON contracts. The client
treats an empty array / empty object under HTTP 200 as `empty`, never `success`.

`useApi(loader, deps)` runs a loader and exposes `{ result, reload }`.
`<ResultGate result>` renders the correct honest state (loading / empty / error /
unavailable / not-found) and only calls its child on real `success`.

## Backend additions (prompt 22, §26)

Two additive, read-only changes expose already-existing data to the UI without
altering contracts:

- `GET /api/v1/analyses?limit=` — a bounded list of recent analyses for the
  dashboard (there was previously only a per-APK list).
- The findings serializer (`_finding_section`) additively includes `id`,
  `fingerprint`, `severity_score`, `confidence_score`, `runtime_status`,
  `runtime_validation_state`, `root_cause_id`, and `evidence_count` — the `id` is
  what lets the UI open `/findings/{id}/explain` and the evidence chain. Existing
  keys are unchanged. Backend tests: `tests/test_api_ui_endpoints.py`.

No other backend semantics were modified.

## State management (§20)

Client state is UI-only: selected node, filters, graph viewport, current theme.
`localStorage` holds a single UI preference (theme). No analytical truth is stored
client-side; the backend remains authoritative and every view re-reads from the API.

## Components

- **StatusBadge / ModeBadge** — render a semantic state with an accessible label
  (never color alone). `ModeBadge` gives LIVE/MOCKED a permanent, distinct marker.
- **CapabilityBadge** — capability chip (AVAILABLE/PARTIAL/UNAVAILABLE/…).
- **DataTable** — reusable table with deterministic sort + pagination.
- **EvidenceDrawer / EvidenceItem** — the global evidence panel reused across
  findings, CVE, remediation, validation, runtime, native, graph, investigation.
- **ExplanationView** — renders any backend `explain` / evidence-chain payload.
- **GraphView** — bounded SVG graph renderer (see [ui-graph](ui-graph.md)).
- **AxisLegend** — makes the “distinct axes” rule explicit.

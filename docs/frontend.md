# Frontend — investigation workspace (prompt 22)

`frontend/` is a React + TypeScript + Vite single-page app that acts as a
**presentation and investigation layer** over the canonical AndroidSecForge
backend. It is **not** a source of truth: it consumes the existing REST API under
`/api/v1`, duplicates no backend business logic, persists no analytical truth in
the browser, and introduces no “exploitable” conclusion.

## Stack

- React 18 + TypeScript (strict) + Vite 5
- react-router-dom 6 (route-based pages)
- Vitest + Testing Library + jsdom (tests)
- ESLint (typescript-eslint, react-hooks) — `--max-warnings 0`
- No graph library — the graph is a self-authored **bounded SVG renderer** (no
  second canonical graph)

## Development workflow

```bash
cd frontend
npm install
# run the backend first (serves /api/v1), e.g.:
#   cd ../backend && ASF_DATABASE_URL=sqlite:///…/analysis.db python -m uvicorn app.main:app --port 8000
npm run dev        # http://localhost:5173 — proxies /api → http://localhost:8000
npm run build      # tsc --noEmit + vite build → dist/
npm run lint       # eslint, zero warnings
npm run test       # vitest (offline; no backend needed — API is mocked)
```

The Vite dev server proxies `/api` to `http://localhost:8000`. In production the
`dist/` bundle can be served by any static host behind the same origin as the API.

## Layout

```
frontend/src/
  api/            typed client (client.ts, index.ts, types.ts)
  hooks/useApi.ts loading/result state
  lib/semantics.ts   security state → accessible label + tone (the strict rules)
  components/     StatusBadge, CapabilityBadge, DataTable, EvidenceDrawer,
                  ExplanationView, GraphView, AxisLegend, States, Layout
  pages/          Dashboard, AnalysisLayout + 15 analysis tabs (incl. Assessment + Search), Investigation*,
                  Diff*, NotFound
  test/           vitest suites
```

## Principles

- **Backend is authoritative.** Every value originates from an API response; the
  UI never invents values (§1). HTTP 200 is not proof data exists — an empty
  payload renders an explicit empty state, never “0 vulnerabilities” (§19/§22).
- **Capabilities are honest.** `AVAILABLE / PARTIAL / UNAVAILABLE / NOT_CONNECTED
  / UNKNOWN / READY / FAILED` are shown verbatim; `UNAVAILABLE` never looks like a
  clean/zero result.
- **No orchestration from the UI** (§28). Opening a page performs only reads.
  Runtime install/launch/attach/instrument remain explicit backend operations.
- **Determinism.** Table ordering uses explicit stable sorts; graph layout is
  deterministic (type-clustered radial keyed by node id). No client-generated
  analytical IDs (§29).

See also: [ui-architecture](ui-architecture.md), [ui-security-semantics](ui-security-semantics.md),
[ui-graph](ui-graph.md), [ui-investigation](ui-investigation.md), [ui-testing](ui-testing.md).

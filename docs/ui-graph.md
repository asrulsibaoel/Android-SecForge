# UI knowledge graph

The graph explorer (`src/components/GraphView.tsx` + `src/pages/GraphPage.tsx`)
is **only a rendering of backend graph data**. It constructs no second canonical
graph, computes no analytical truth, and fabricates no edges. The backend
knowledge graph (a projection over the canonical code graph) remains authoritative.

## Data source

`GET /api/v1/analysis/{id}/graph/knowledge` returns the bounded node/edge
projection plus its deterministic `digest` and a `truncated` flag.
`GET …/graph/snapshot` provides the deterministic snapshot digest and counts.
`GET …/graph/query?name=` runs a named, backend-computed bounded query. Exports use
`GET …/graph/export?format=graphml|dot|json` (the browser generates no export).

## Interaction (§6/§7)

- Pan (pointer drag) and zoom (wheel / buttons) via an SVG transform.
- Node and edge selection open a side panel with type, status, confidence,
  provenance, and relationships.
- Filters: node type, edge type, minimum confidence, and text search.
- **Bounded neighborhood expansion**: “Focus” restricts the view to a selected
  node and its direct backend neighbors — never an unbounded expansion.
- **Named query investigation** runs the backend bounded query and shows its
  `count` and `truncated` status.

## Uncertainty & truncation (§7/§23)

- An `UNKNOWN`-confidence or UNKNOWN-typed edge is drawn **dashed** and labelled
  “UNKNOWN — not a confirmed relationship”; it is never rendered as a confirmed edge.
- Rendering is bounded by `maxNodes` (default 400). When the backend graph has
  more nodes, a **TRUNCATED** banner states “showing N of M nodes” — evidence is
  never silently dropped.
- The 18k-node Magisk graph does not freeze the browser: the backend returns a
  bounded projection (≈140 nodes for Magisk), and the client caps rendering and
  expands interactively.

## Node types

Distinct visual classes (color via CSS + always a text label) exist for APK,
MANIFEST, PERMISSION, COMPONENT, ENTRY_POINT, CLASS/METHOD/FIELD, NATIVE_LIBRARY,
NATIVE_FUNCTION, JNI_BINDING, DEPENDENCY, CVE, FINDING, EVIDENCE, ROOT_CAUSE,
ATTACK_SURFACE, SECURITY_BOUNDARY, RUNTIME_DEVICE/SESSION/PROCESS/OBSERVATION,
RUNTIME_CORRELATION, REMEDIATION_ITEM, VALIDATION_CLAIM/BLOCKER,
OBFUSCATION_OBSERVATION, ANTI_ANALYSIS_INDICATOR, ANALYSIS_IMPACT.

## Layout determinism

Layout is a deterministic type-clustered radial keyed by node id order (§29).
Visual position may vary with pan/zoom, but backend graph identity, digest, and
evidence are deterministic and untouched by the UI.

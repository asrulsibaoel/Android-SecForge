# UI investigation workspace

`/investigations/:id` (`src/pages/InvestigationWorkspace.tsx`) is the researcher
workspace over the backend investigation API (prompt 14). It stores no analytical
truth in the browser — every pin, note, and hypothesis is persisted through the
backend and re-read from it.

## Sections

Overview · Findings · Notes · Hypotheses · Timeline · Graph · Export.

## Actions

- **Create** an investigation from an analysis (`POST /investigations`).
- **Pin a node** (`POST /investigations/{id}/nodes`) — works for any backend node
  ref, including runtime correlations, findings, and graph nodes.
- **Add note** (`POST …/notes`) and **add hypothesis** (`POST …/hypotheses`).
- **Export** via backend endpoints (`GET …/export?format=json|markdown|graphml|dot`).

## Researcher vs machine truth (§15/§16)

Notes and hypotheses are labelled **researcher** state and are visually separated
from machine-derived evidence. The timeline marks every event as **⚙ machine** or
**👤 researcher**, and event types include `STATIC_FINDING`, `LIVE_OBSERVATION`,
`CORRELATION`, `VALIDATION_TRANSITION`, and `INVESTIGATION_NOTE`.

A hypothesis is researcher state only: it **never** alters finding severity,
finding confidence, risk, validation state, CVE state, remediation priority, or
graph truth. The UI enforces this by construction — researcher-input helpers
(`addNote`, `addHypothesis`, `pinNode`) POST only to `/investigations/*` routes and
never to any finding/risk/validation/remediation mutation route. This is asserted
by `src/test/components.test.tsx` (“researcher input never targets analytical-truth
routes”).

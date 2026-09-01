# UI testing

Frontend tests use Vitest + Testing Library + jsdom and are fully offline (the
API is mocked). Run from `frontend/`:

```bash
npm run test        # vitest run
npm run lint        # eslint --max-warnings 0
npm run build       # tsc --noEmit + vite build
```

## Suites (52 tests)

| File | Covers |
|------|--------|
| `src/test/semantics.test.ts` | state → label/tone mapping; the strict non-collapse rules |
| `src/test/client.test.ts` | API client: loading/success/**empty**/404/400/500/network — HTTP 200 ≠ “data exists” |
| `src/test/components.test.tsx` | StatusBadge/ModeBadge, EvidenceItem UNKNOWN preservation, DataTable deterministic sort + empty, ResultGate honest states, researcher-routes guard |
| `src/test/graph.test.tsx` | bounded rendering + TRUNCATED, node selection, UNKNOWN edge dashed/labelled |
| `src/test/findings.test.tsx` | findings table render, runtime-state filter, MOCKED-vs-LIVE per row, evidence drawer + no-exploitable note |
| `src/test/security-semantics.test.tsx` (prompt 25) | assessment decision states never SAFE/UNSAFE/EXPLOITABLE; INCONCLUSIVE ≠ UNSAFE; SUPPORTED ≠ EXPLOITABLE; native API presence ≠ reachability; JNI presence ≠ invocation; native/frida-server UNAVAILABLE ≠ zero; BLOCKED ≠ SAFE; MetricCard UNAVAILABLE ≠ "0" |
| `src/test/assessment.test.tsx` (prompt 25) | Assessment page: overall INCONCLUSIVE (never SAFE/UNSAFE), conclusions + decision states + rule ids, conclusion drawer LIVE evidence + no-exploitability note |

## Explicit regression tests (§25)

- **MOCKED never renders as LIVE** — `semantics.test.ts`, `components.test.tsx`,
  `findings.test.tsx`.
- **UNKNOWN never renders as SAFE** — `semantics.test.ts`, `components.test.tsx`.
- **POSSIBLY_AFFECTED never renders as AFFECTED** — `semantics.test.ts`,
  `components.test.tsx`.
- **NO_LONGER_DETECTED never renders as FIXED** — `semantics.test.ts`,
  `components.test.tsx`.
- **Hypothesis does not alter machine truth** — `components.test.tsx` asserts
  researcher-input helpers POST only to `/investigations/*`.

## Backend regression

The backend suite (`backend/`, `python -m pytest`) remains green after the two
additive UI endpoints; `tests/test_api_ui_endpoints.py` covers the bounded
`/analyses` list and the additive, read-only findings fields.

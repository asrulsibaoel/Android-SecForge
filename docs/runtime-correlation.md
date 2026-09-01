# Static ↔ runtime correlation

`backend/app/analysis/runtime_correlation.py` connects persisted runtime
observations to the **existing** static findings/graph. Runtime is a separate
evidence source; it never overwrites static evidence.

## Statuses

Per finding (`findings.runtime_status`):

- `STATIC_ONLY` — no confirming runtime observation.
- `STATIC_RUNTIME_CONFIRMED` — a runtime observation of the same Java api the
  static finding concerns (e.g. static `WebView.loadUrl` sink + observed
  `WebView.loadUrl`).
- `RUNTIME_SUPPORTS_STATIC_PATH` — a native symbol observation supports a native
  static finding (e.g. observed `strcpy`).
- (`RUNTIME_OBSERVED`, `RUNTIME_CONTRADICTS_HYPOTHESIS`, `INCONCLUSIVE` are also
  modeled.)

Validation state (`findings.validation_state`): `NOT_RUN`, `RUNNING`,
`OBSERVED`, `NOT_OBSERVED`, `INCONCLUSIVE`.

## Matching

An observation `android.webkit.WebView.loadUrl` yields the api token
`WebView.loadUrl`; a finding is confirmed when that concrete api token appears in
the finding's title/evidence — i.e. the **same api** was observed, not a fuzzy
name guess. Native findings match on the observed symbol. Confirmation increments
`runtime_evidence_count`.

## Confidence (bounded, documented)

On confirmation, a finding's `confidence_score` increases by a fixed **+15**,
capped at **95**. **Severity is never changed** by runtime evidence.

## Critical semantics

- `NOT_OBSERVED` **does not mean SAFE** — a hook not firing does not prove the
  code is unreachable, and absence of an observation is not proof of absence.
- A static finding is **never downgraded** merely because runtime did not observe
  it (it stays `STATIC_ONLY`, validation `NOT_OBSERVED`).
- `UNKNOWN` remains `UNKNOWN`.

## Graph integration

`RUNTIME_OBSERVED` edges are added to the **existing** graph (a runtime marker
node + edge) only from a static Java-method node that actually matches the
observed class+method — never on name similarity between arbitrary nodes.

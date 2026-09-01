# Finding correlation & deduplication

`backend/app/analysis/correlation.py` unifies the independent analysis outputs
(rule findings, reachability paths, boundaries, dependencies, CVE matches) into a
single security model, operating entirely on **persisted** evidence.

## Deduplication (deterministic)

Each finding gets a stable `fingerprint = sha256(rule_id | category | primary_target | evidence_identity)[:32]`,
where `primary_target` is the most specific evidence location (else the component)
and `evidence_identity` is the sorted set of `source:location` pairs. Two findings
in the same analysis with an identical fingerprint are exact duplicates; the later
one is flagged `is_duplicate=True`. Findings that merely share a component are
**not** deduplicated. `severity_score` and `confidence_score` are also filled in
here (bands: info=10/low=30/medium=55/high=80/critical=95; confidence
low=30/medium=60/high=85/confirmed=95).

## Correlation index (O(N), no pairwise scan)

For each finding, `finding_dimensions()` derives shared-evidence keys —
`component`, `cve`, `dependency`, `native_library`, `sink` — and one
`finding_correlations` row per (finding, dimension, key). Findings sharing a
`(dimension, key)` are correlated. This is O(findings × dimensions), never
O(N²). `correlation_groups()` returns groups with more than one member.

## Path summarization

`summarize_path()` renders a persisted reachability path as a concise
`" -> "` chain and **preserves UNKNOWN markers**: a path terminating at a
`NATIVE_FUNCTION` (JNI boundary) is annotated `UNKNOWN_NATIVE_TARGET` — gaps are
never filled in.

## False-positive controls

- Text similarity never merges findings — only shared evidence identity.
- A single-member correlation group is not a group.
- Disconnected source/sink findings (different components, no shared sink) are
  never correlated (see `test_correlation.py::test_disconnected_source_and_sink_not_correlated`).

## Limitations

- Correlation keys are derived from persisted fields/evidence text; a sink label
  is parsed from evidence detail, so a finding without evidence contributes only
  its component/CVE dimensions.
- Deduplication is per-analysis; cross-analysis dedup is out of scope.

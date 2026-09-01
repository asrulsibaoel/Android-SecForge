# APK diff & comparative security analysis

The comparison layer (`app/analysis/diff.py`) compares two existing analyses —
**baseline A → candidate B** — entity-by-entity, reusing prompt-14 graph
snapshots for integrity. It is read-only against both analyses: it writes only
`comparison_*` rows and never mutates the canonical graph or either analysis.

Direction matters: A→B is a distinct comparison from B→A, and the fingerprint
encodes the ordered pair.

## Comparison identity

```
fingerprint = sha256(baseline.id | candidate.id | snapshot_a.digest | snapshot_b.digest)[:32]
```

The same ordered pair always yields the same fingerprint. The report labels
`BASELINE(A)` and `CANDIDATE(B)` explicitly.

## Snapshot integrity

Where a prompt-14 `GraphSnapshot` exists, the engine recomputes the
knowledge-graph digest and compares it to the stored one:

- both sides have a verified snapshot → `snapshot_mode = SNAPSHOT`
- exactly one side → `MIXED`
- neither → `RECONSTRUCTED` (compared from persisted entities, reported honestly)
- **a stored snapshot whose digest no longer matches → `status = FAILED`** (a
  stale/corrupted snapshot is never silently compared)

## Diff categories

Every category is diffed by **stable identity** (never decompiler line numbers):

| Category | Identity |
| --- | --- |
| manifest | permission name; component name; deep-link (component,scheme,host,path); intent-filter (component,actions) |
| semantics | entry point (component,method); intent tuple; IPC tuple; boundary (type,component); WebView/reflection/dynamic-load edge (src,dst) |
| code | class = package/class; method = class+name+signature; field = class+name; call = (src_key,dst_key); source/sink relationship |
| native | library = archive path; function = (lib,name,kind); JNI binding = (class,method,native_fn,lib); SONAME/DT_NEEDED/arch changes; JNI confidence change |
| dependency | (ecosystem,name); classified ADDED/REMOVED/VERSION_CHANGED/VERSION_UNKNOWN/CLASSIFICATION_CHANGED |
| cve | (cve_id,dependency); transitions preserve version/affected-range evidence, confidence, reachability |
| finding | stable fingerprint + semantic relink; CHANGED reports which dimensions moved |
| root_cause | deterministic identifier |
| attack_surface | node_key; edge (src,dst,type); exposure/risk transitions |
| reachability | (rule_id,from_key,to_key,status) |
| runtime | (observation_type,class,method,symbol) when runtime data exists |

Analytical states are preserved verbatim: `UNKNOWN`, `NOT_REACHABLE`,
`NOT_OBSERVED`, `POSSIBLY_AFFECTED`, and `UNKNOWN_NATIVE_TARGET` are never
re-interpreted. A version change is never itself treated as vulnerable/safe — the
CVE engine's persisted match rows are the authority.

## Findings

A disappeared finding is **`NO_LONGER_DETECTED`**, never "fixed" (unless there is
direct evidence of remediation such as the supporting component being removed).
An appeared finding is never automatically "exploitable".

## Risk delta

Reports `baseline → candidate` score, `delta`, severity-band transition,
confidence transition, and factor changes, always framed as *"Risk changed
according to the configured scoring model"* — never as a change in
exploitability.

## Security-impact classification (conservative)

`SECURITY_REGRESSION`, `SECURITY_IMPROVEMENT`, `MIXED`,
`NO_MATERIAL_SECURITY_CHANGE`, or `INCONCLUSIVE`, each with a confidence.

- A **regression** requires positive security evidence: a new PUBLIC entry point,
  a new confirmed reachable path to a sink, a newly reachable+AFFECTED CVE, a new
  `CONFIRMED_BY_STATIC_ANALYSIS` finding, a component becoming exported, or a
  risk increase with meaningful factors.
- An **improvement** requires evidence of a security-relevant reduction (e.g. a
  component becoming internal, a dangerous permission removed, a CVE no longer
  reachable-and-affected).
- Ambiguous signals (a `POSSIBLY_AFFECTED` transition, a new *potential* finding,
  a confirmed finding `NO_LONGER_DETECTED` without proof of remediation) →
  `INCONCLUSIVE`.
- No security-relevant signals → `NO_MATERIAL_SECURITY_CHANGE`.

## CLI

```bash
androidsecforge diff create <baseline> <candidate> [--json]
androidsecforge diff show <comparison> [--json]
androidsecforge diff summary <comparison> [--json]
androidsecforge diff changes <comparison> [--category C] [--change-type ADDED|REMOVED|CHANGED] \
    [--min-confidence LOW|MEDIUM|HIGH] [--security-impact] [--json]
androidsecforge diff findings <comparison> [--json]
androidsecforge diff attack-surface <comparison> [--json]
androidsecforge diff risk <comparison> [--json]
androidsecforge diff paths <comparison> [--json]
androidsecforge diff export <comparison> --format report|json|graphml|dot
androidsecforge diff list [--json]
```

## REST

`POST /api/v1/diff?baseline=&candidate=`, and
`GET /api/v1/diff/{id}[/summary|/changes|/findings|/attack-surface|/risk|/paths|/export]`.

## Graph-delta export

`diff export --format json|graphml|dot` projects the two knowledge graphs and
marks each node and edge `ADDED` / `REMOVED` / `UNCHANGED` / `CHANGED` using
analysis-agnostic edge identities (fingerprint without `analysis_id`). It reuses
the canonical projection — it does not build a second graph — and preserves
provenance and uncertainty. `--format report` emits the full deterministic JSON
comparison report.

## Performance

The engine indexes every entity set once per analysis (dictionaries/sets) and
diffs by stable identity — no O(N×M) scans. An ~18k-node graph comparison
(Magisk v29.0) completes in a few seconds. Per-category change persistence is
bounded (`ASF_DIFF_MAX_CHANGES_PER_CATEGORY`, default 5000); truncation is
recorded in the summary and flips the status to `PARTIAL` — referenced entities
are never dropped to satisfy a limit.

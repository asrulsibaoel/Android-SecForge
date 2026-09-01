# Investigation workspace

An **investigation** is a persistent researcher workspace scoped to one analysis.
It lets a security researcher start from any entity — APK, component, finding,
root cause, CVE, dependency, source, sink, JNI binding, native library, or
runtime observation — and navigate the complete evidence chain, pinning what
matters, recording notes and hypotheses, and exporting a report.

Investigation state is **strictly separate from analytical truth**. Nothing in
the workspace changes findings, severity, confidence, risk, CVE state, or the
code graph. See [graph-integrity](graph-integrity.md).

## Model

| Table | Purpose |
| --- | --- |
| `investigations` | one workspace per (analysis, researcher) |
| `investigation_nodes` | canonical graph nodes the researcher pinned (by ID) |
| `investigation_edges` | pinned relationships / path segments |
| `investigation_findings` | findings attached to the investigation |
| `investigation_notes` | free-text researcher annotations |
| `investigation_hypotheses` | researcher hypotheses + status |
| `investigation_hypothesis_evidence` | evidence attached to a hypothesis |
| `investigation_bookmarks` | quick references |
| `investigation_timeline_events` | deterministic timeline (see below) |

## Lifecycle

```bash
androidsecforge investigate create <analysis-id> --name "My case"
androidsecforge investigate list <analysis-id>
androidsecforge investigate show <investigation-id> --json
androidsecforge investigate rename <investigation-id> "New name"

androidsecforge investigate add-finding <investigation-id> <finding-id>
androidsecforge investigate add-node <investigation-id> "com.x.Foo#bar" --type CODE_METHOD
androidsecforge investigate path <investigation-id> --from COMPONENT --to loadUrl   # pins a path
androidsecforge investigate note <investigation-id> "check the deep link handler"
androidsecforge investigate bookmark <investigation-id> finding <finding-id> --label primary

androidsecforge investigate hypothesis <investigation-id> "External input may control reflective class loading."
androidsecforge investigate hypothesis-status <hypothesis-id> SUPPORTED
androidsecforge investigate hypothesis-evidence <hypothesis-id> FINDING <finding-id> --detail "reachable path"

androidsecforge investigate timeline <investigation-id> --json
androidsecforge investigate graph <investigation-id>            # KG summary + digest
androidsecforge investigate explain <finding-id> --json
androidsecforge investigate evidence-chain <finding-id> --json
androidsecforge investigate export <investigation-id> --format markdown
androidsecforge investigate snapshot <analysis-id> --json
```

REST mirrors these under `/api/v1/investigations` and
`/api/v1/findings/{id}/explain|evidence-chain|explore`.

## Hypotheses

A hypothesis is *researcher state*. Its status is one of `OPEN`, `SUPPORTED`,
`REFUTED`, `UNKNOWN`, and it is **never** auto-promoted — attaching evidence does
not change the status; only an explicit `hypothesis-status` action does. Setting
a hypothesis `SUPPORTED` changes **no** finding.

Example:

> **Hypothesis:** "External input may control reflective class loading."
> **Evidence:** exported component; external-input source; `Class.forName` sink;
> reachable path.
> **Status:** `SUPPORTED` — *if the evidence is incomplete, keep it `UNKNOWN`.*

## Finding explorer

`investigate explain <finding-id>` runs the deterministic explanation engine and
returns `WHY_FOUND`, `EVIDENCE_CHAIN`, `ASSUMPTIONS`, `UNCERTAINTIES`,
`LIMITATIONS`, and `RELATED_ENTITIES`. It never asserts exploitability. The
finding-centric `explore` bundle additionally returns the root cause, correlated
findings, attack surface, component, entry points, sources/sinks, reachability
paths, dependencies, CVE matches (state preserved verbatim), JNI/native context,
runtime observations, and graph neighbours.

## Timeline

`rebuild_timeline` produces a deterministic ordering:

- **static** events use the analysis timestamp (ingestion, manifest, JADX, ELF,
  JNI, semantics, reachability, CVE, finding generation);
- **runtime** events use their actual timestamps (session, observation);
- **researcher notes** use their creation time.

No historical timestamp is fabricated. Ordering ties break on a stable
`sequence` field.

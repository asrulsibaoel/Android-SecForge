# Investigation export

Investigations and the projected knowledge graph export to four formats
(`app/reports/investigation_report.py`):

| Format | Content |
| --- | --- |
| `json` | full knowledge graph (nodes + edges + provenance + digest) |
| `graphml` | knowledge graph for visualization tools (yEd, Gephi, …) |
| `dot` | Graphviz rendering of the knowledge graph |
| `markdown` | human investigation report |

```bash
androidsecforge investigate export <investigation-id> --format markdown
androidsecforge graph kg <analysis-id> --format json|graphml|dot
```

REST: `GET /api/v1/investigations/{id}/export?format=…`,
`GET /api/v1/analysis/{id}/graph/knowledge?format=…`.

## GraphML / DOT

Nodes carry `type`, `label`, `confidence`, `status`, and a comma-joined
`provenance` source list. Edges carry `type`, `confidence`, and the deterministic
`fingerprint`. Only edges between present nodes are emitted.

## JSON

The JSON export is the complete projection: every node's provenance list and
every edge's fingerprint + evidence refs, plus the graph `digest`. It is the
machine-readable form for downstream tooling and regression comparison.

## Markdown report

The Markdown report has a fixed section order:

```
# Investigation
## Scope
## Findings
## Root Causes
## Attack Surface
## Evidence
## Reachability Paths
## Dependencies
## CVEs
## Runtime Observations
## Hypotheses
## Uncertainties
## Limitations
## Timeline
```

Every claim links back to a stable evidence identifier — `FINDING:{fingerprint}`,
`EVIDENCE:{fp}:{i}`, `ROOT_CAUSE:{identifier}`, `CVE:{id}`,
`DEP:{ecosystem}:{name}:{version}`, `ATTACK_SURFACE_NODE:{key}`,
`RUNTIME_OBSERVATION:{id}`. The report:

- preserves `POSSIBLY_AFFECTED` / `UNKNOWN` CVE states and states so explicitly;
- notes that `NOT_OBSERVED` does not mean safe;
- marks hypotheses as researcher annotations that do not modify findings;
- never uses the word "exploitable".

The Uncertainties and Limitations sections are aggregated deterministically from
each finding's explanation (runtime not observed, unresolved reflection targets,
JADX/Ghidra availability, …).

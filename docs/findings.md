# Findings & evidence

Findings are persisted relationally (`findings` and `evidence` tables) and linked to the
analysis that produced them.

## Finding fields

- `rule_id`, `title`, `category`
- `severity` — `info | low | medium | high | critical`
- `confidence` — `low | medium | high | confirmed`
- `status` — `POTENTIAL` or `CONFIRMED_BY_STATIC_ANALYSIS` (never `EXPLOITABLE` without runtime validation, which is out of scope for this slice)
- `description`, `remediation`, `references`
- `component` — the associated component name, when applicable

Severity, confidence, and status are **independent axes**. A high-severity code pattern can
still be `POTENTIAL` with `low` confidence.

## Evidence

Every finding references evidence:

- `source` — `manifest` or `source_code`
- `location` — e.g. `activity .MainActivity` or `com/x/A.java:42`
- `detail` — the concrete reason (secrets masked)
- `artifact`, `class_name`, `method_name`, `line` — where available

## Provenance

From a finding you can trace back to the rule (`rule_id`), the analysis (`analysis_id`), the
ruleset version, and the APK SHA-256 — every result is reproducible.

## Access

- CLI: `androidsecforge findings <analysis-id> [--json]`
- JSON report: the `findings` array (sorted by severity, then rule id)
- REST: `GET /api/v1/analysis/{id}/findings`

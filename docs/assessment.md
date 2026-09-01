# Security assessment & decision intelligence

The assessment layer (`app/assessment/`) is a **deterministic projection** that
synthesizes every prior AndroidSecForge layer into a single auditable assessment
state. It answers *"what is supported, what is uncertain, what requires review,
and what evidence is missing?"* — it **never** answers whether something is
"exploitable" and **never** collapses results into SAFE/UNSAFE. It is not a second
source of truth: every conclusion references an existing ID / fingerprint and
duplicates or mutates no canonical record.

## Decision states (evidentiary strength — not verdicts)

`CONFIRMED` · `STRONGLY_SUPPORTED` · `SUPPORTED` · `CONDITIONALLY_SUPPORTED` ·
`REQUIRES_REVIEW` · `UNVERIFIED` · `BLOCKED` · `INCONCLUSIVE` · `NOT_APPLICABLE` ·
`SUPERSEDED`. These express how much evidence backs a conclusion, never
exploitability and never a safety judgement.

## Conclusion types (`app/assessment/taxonomy.py`)

- **Finding** — `FINDING_CONFIRMED` / `FINDING_SUPPORTED` / `FINDING_UNVERIFIED` /
  `FINDING_BLOCKED` / `FINDING_INCONCLUSIVE`.
- **CVE** — `CVE_CONFIRMED` / `CVE_POSSIBLY_RELEVANT` / `CVE_VERSION_UNVERIFIED` /
  `CVE_NOT_AFFECTED` / `CVE_NOT_REACHABLE` / `CVE_EVIDENCE_INSUFFICIENT`
  (`POSSIBLY_AFFECTED` is never promoted to `AFFECTED`).
- **Runtime** — `RUNTIME_CORROBORATED` / `RUNTIME_NOT_OBSERVED` /
  `RUNTIME_UNAVAILABLE` / `RUNTIME_MOCKED_ONLY` (MOCKED never satisfies LIVE;
  UNAVAILABLE is distinct from NOT_OBSERVED).
- **Native** — `NATIVE_API_CONFIRMED` (LIVE-invoked) / `NATIVE_PATH_CORROBORATED`
  (Ghidra reach) / `NATIVE_REACHABILITY_UNVERIFIED` / `NATIVE_ANALYSIS_UNAVAILABLE`
  (ELF-only). `UNKNOWN_NATIVE_TARGET` is preserved as a blocker.
- **Remediation** — `REMEDIATION_RECOMMENDED` / `REMEDIATION_CONDITIONAL` /
  `REMEDIATION_REQUIRES_REVIEW` / `REMEDIATION_REMEDIATED` /
  `REMEDIATION_STATUS_UNVERIFIED` (runtime alone never yields `REMEDIATED`).
- **Assessment-level** — `SECURITY_RELEVANT_EVIDENCE_PRESENT` /
  `SECURITY_REVIEW_REQUIRED` / `EVIDENCE_INCOMPLETE` / `VALIDATION_INCOMPLETE` /
  `ASSESSMENT_CONCLUSIVE` / `ASSESSMENT_INCONCLUSIVE`.

## Decision engine (`app/assessment/engine.py`)

`build_assessment(db, analysis)` consumes persisted projections — findings, CVE
matches, validation state, remediation items, runtime validation runs, deep-native
view, native runtime correlations, attack surface / reachability / root causes —
and applies **explicit, inspectable rules**. Every conclusion records the
`rule_id` that fired (e.g. `R-CVE-VERSION-UNVERIFIED`, `R-RT-MOCKED`,
`R-NAT-ELF-ONLY`, `R-FIND-RUNTIME`), a rationale, `DecisionEvidence` referencing
the source records (with `STATIC` / `LIVE` / `MOCKED` / `UNAVAILABLE` mode +
provenance), `DecisionBlocker`s, `DecisionRequirement`s, and `DecisionDependency`s.
There is no ML, no hidden weight, no probability, and no "risk of exploit".

Assessment-level conclusions aggregate the rest: any open state (`REQUIRES_REVIEW`
/ `UNVERIFIED` / `BLOCKED` / `INCONCLUSIVE` / `CONDITIONALLY_SUPPORTED`) →
`SECURITY_REVIEW_REQUIRED` + `ASSESSMENT_INCONCLUSIVE`; only a fully-settled set →
`ASSESSMENT_CONCLUSIVE`.

## Determinism & persistence

Conclusion fingerprint = `sha256(subject_type|subject_ref|conclusion_type|
decision_state|sorted(evidence refs))`; assessment fingerprint = `sha256` over
sorted conclusion fingerprints. No DB ids or timestamps participate. Rebuild is
idempotent (prior assessments cleared, no duplicates). Models
(`models/assessment.py`, migration `0021_assessment`): `assessments`,
`assessment_subjects`, `security_conclusions`, `decision_evidence`,
`decision_blockers`, `decision_requirements`, `decision_dependencies`,
`assessment_transitions`, `assessment_summaries`.

## Integrations

- **Report** — a `assessment` section in the JSON report + Markdown export
  (`assess export --format markdown`). Runtime invocation is never labelled a
  vulnerability confirmation.
- **APK diff** — `assessment_from_diff` (`GET /api/v1/diff/{id}/assessment`)
  compares conclusions by (subject_type, subject_ref): `NEW_CONCLUSION` /
  `STATE_CHANGED` / `NO_LONGER_PRESENT`. A removed conclusion is
  `NO_LONGER_PRESENT` — never `FIXED` / `REMEDIATED` / `NOT_AFFECTED`.
- **Doctor** — `assessment: READY` (deterministic, offline).
- Not added to the orchestrator or the default KG projection, so graph snapshots /
  APK-diff integrity are unaffected (on-demand, like remediation).

## CLI / REST

```
androidsecforge assess build <analysis-id>
androidsecforge assess summary|conclusions <analysis-id> [--state --type --subject] [--json]
androidsecforge assess explain <analysis-id> <ref>
androidsecforge assess export <analysis-id> --format json|markdown
```
REST: `GET/POST /api/v1/analysis/{id}/assessment`,
`GET /api/v1/analysis/{id}/assessment/conclusions?state=`,
`GET /api/v1/analysis/{id}/assessment/explain/{ref}`,
`GET /api/v1/diff/{id}/assessment`.

## Real acceptance (Magisk v29.0)

On the real Magisk analysis (with the prompt-23 LIVE runtime run present):
**status `ASSESSMENT_INCONCLUSIVE`, 23 subjects, 27 conclusions, 11 open, 0
blockers.** Conclusions included `FINDING_CONFIRMED`/`FINDING_SUPPORTED`/
`FINDING_INCONCLUSIVE`, `RUNTIME_CORROBORATED` (from the LIVE session),
`NATIVE_ANALYSIS_UNAVAILABLE` (ELF-only), `REMEDIATION_REQUIRES_REVIEW`, and the
aggregate `SECURITY_RELEVANT_EVIDENCE_PRESENT` / `SECURITY_REVIEW_REQUIRED` /
`ASSESSMENT_INCONCLUSIVE`. No CVE conclusions (intelligence unpopulated — honest).
Deterministic fingerprint, idempotent rebuild, no `exploitable`, no SAFE/UNSAFE,
and static findings/CVE state left unchanged.

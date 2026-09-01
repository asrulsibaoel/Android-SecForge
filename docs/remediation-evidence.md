# Remediation evidence & fixability

Every recommendation is evidence-backed and auditable without re-running the APK
analysis.

## Evidence model

Each `remediation_evidence` row preserves `source_type`
(`FINDING` / `CVE` / `DEPENDENCY` / `ROOT_CAUSE` / `ATTACK_SURFACE` / `IPC` /
`SECURITY_BOUNDARY` / `CODE` / `RUNTIME`), `source_id` (stable identifier —
finding fingerprint, CVE id, dependency name, node key), `confidence`, a human
`detail`, and a structured `evidence_json`. Timestamps are recorded where
available.

## Fixability

| Class | Meaning |
| --- | --- |
| `DIRECT_FIX` | a known fixed dependency/version exists |
| `CONDITIONAL_FIX` | a fix exists but the installed version/config is unknown |
| `CODE_REVIEW` | requires source/code review |
| `CONFIGURATION_REVIEW` | requires a configuration change/review |
| `ARCHITECTURAL_REVIEW` | requires a design-level change |
| `ENVIRONMENTAL` | depends on runtime/deployment environment |
| `UNKNOWN_FIX` | no reliable remediation information exists |

Fixability is evidence-backed: `DIRECT_FIX` requires a provider-supplied fixed
version; `CONDITIONAL_FIX` is used when identity matches but the version is
unverified.

## Explanation engine

`remediation explain <analysis-id> <item-id>` returns
`WHY_THIS_RECOMMENDATION_EXISTS` — an ordered, provenance-attributed rationale
walking finding → root cause → target → vulnerability intelligence → version
evidence → reachability → exposure → runtime corroboration → recommended action →
fixability → uncertainty. It never uses the word "exploitable".

## Uncertainty handling

- version unknown → "installed version could not be recovered; AFFECTED is not
  asserted".
- native reachability → `UNKNOWN_NATIVE_TARGET` preserved.
- Binder target → recorded as `target=UNKNOWN`, never inferred.
- runtime not observed → "NOT_OBSERVED is not SAFE".

## Deterministic fingerprints

Item fingerprint = `sha256(action | target_type | target)` — order-independent
(CASE 15) and content-derived, so identical analyses produce identical items
(CASE 14). Same-target items merge deterministically (CASE 18), adopting the
most-informative status/fixability (e.g. a CVE match with a fixed version
outranks one without). Plan fingerprint = `sha256(sorted item fingerprints)`.

## Integrity

The remediation layer never mutates findings, CVE state, risk assessments,
attack-surface nodes, or the canonical graph. It reads persisted evidence and
writes only `remediation_*` rows.

# Security verification & validation intelligence

The validation layer (`app/analysis/validation.py`) is a deterministic,
evidence-backed projection over already-persisted evidence that answers: *what
security claim can currently be verified from static evidence, corroborated by
runtime, or remains unverified — and what evidence is still required?*

It is **not** an exploitability engine — there is no `exploitable` state, no
score is mutated, and every uncertainty (`UNKNOWN`, `NOT_REACHABLE`,
`NOT_OBSERVED`, `POSSIBLY_AFFECTED`, `NO_LONGER_DETECTED`,
`UNKNOWN_NATIVE_TARGET`) is preserved. Validation confidence is a **separate
axis** from risk, severity, and remediation priority.

## Validation states

`UNVERIFIED`, `STATIC_SUPPORTED`, `RUNTIME_CORROBORATED`,
`MULTI_SOURCE_CORROBORATED`, `VALIDATION_BLOCKED`, `INCONCLUSIVE`,
`NOT_APPLICABLE`, `SUPERSEDED`. `STATIC_SUPPORTED` ≠ runtime-proven;
`RUNTIME_CORROBORATED` ≠ exploitable; `VALIDATION_BLOCKED` (evidence/capability
absent) is distinct from `UNVERIFIED` (no supporting evidence) and
`INCONCLUSIVE`.

## Claims

A normalized claim identifies claim_type, target, current_state,
validation_state, confidence, evidence_count, independent_source_count,
required_capabilities, missing_evidence, uncertainty, and provenance. Claim types
include `REACHABILITY_CONFIRMED`, `SOURCE_TO_SINK_SUPPORTED`,
`EXPORTED_COMPONENT_CONFIRMED`, `INTENT_INPUT_CONFIRMED`,
`DEEP_LINK_INPUT_CONFIRMED`, `IPC_BOUNDARY_CONFIRMED`, `WEBVIEW_BRIDGE_CONFIRMED`,
`REFLECTION_PATH_CONFIRMED`, `DYNAMIC_LOAD_PATH_CONFIRMED`, `JNI_BOUNDARY_CONFIRMED`,
`NATIVE_USAGE_CONFIRMED`, `DEPENDENCY_PRESENT`, `DEPENDENCY_VERSION_CONFIRMED`,
`CVE_MATCH_SUPPORTED`, `CVE_VERSION_AFFECTED`, `CVE_VERSION_UNVERIFIED`,
`RUNTIME_BEHAVIOR_OBSERVED`, `REMEDIATION_STATE_SUPPORTED`, `APK_CHANGE_CONFIRMED`.
Claims are never invented where supporting evidence does not exist.

## Evidence-source independence

Evidence is classified into families: `STATIC_CODE`, `STATIC_MANIFEST`,
`STATIC_REACHABILITY`, `STATIC_SEMANTICS`, `STATIC_NATIVE`, `DEPENDENCY_METADATA`,
`VULNERABILITY_DATABASE`, `RUNTIME`, `DIFF`, `USER_INVESTIGATION`. Corroboration
counts **distinct families**, not evidence rows: `STATIC_CODE + STATIC_REACHABILITY`
is stronger than `STATIC_CODE + STATIC_CODE`. `USER_INVESTIGATION` (researcher
notes/hypotheses) never counts as corroborating evidence — a hypothesis cannot
change validation truth. Mock runtime observations stay MOCKED and never
corroborate (only a LIVE, non-mock observation elevates to `RUNTIME_CORROBORATED`).

## Confidence

Documented weighted sum (`VALIDATION_WEIGHTS` / `VALIDATION_PENALTIES`), clamped
0–100:

```
confidence = base_evidence(40) + independent_family(15/extra family)
           + direct_target(10) + runtime_corroboration(20) + reachability_confirmed(10)
           + identity_confirmed(10) + version_confirmed(10)
           − unknown_version(15) − unknown_native_target(10) − unresolved_ipc_target(10)
           − not_reachable(10) − possibly_affected(10) − missing_provider_record(5)
           − ambiguous_identity(10)
```

No ML, no hidden multipliers. Kept separate from risk/severity/priority; no
existing score is mutated.

## Requirements & blockers

Each claim type has a deterministic requirement template. Unmet requirements
yield blockers: `MISSING_VERSION`, `NO_LIVE_OBSERVATION`, `UNRESOLVED_IPC_TARGET`,
`MISSING_JNI_TARGET`, `UNKNOWN_NATIVE_TARGET`, `MISSING_PROVIDER_RECORD`,
`INSUFFICIENT_EVIDENCE`, `AMBIGUOUS_IDENTITY`, `NO_RUNTIME_DEVICE`, `NO_FRIDA`,
`NO_COMPILED_TEST_ARTIFACT`. Hard blockers (missing version / no live observation
/ unresolved IPC/JNI target) block the claim; `UNKNOWN_NATIVE_TARGET` is preserved
as an uncertainty and does not block. A blocker is never turned into a positive
finding.

## Integrations

- **Findings** gain additive columns `security_validation_state`,
  `validation_confidence`, `validation_claim_count`, `validation_evidence_count`,
  `validation_blocker_count`, `validation_summary` (the existing runtime
  `validation_state`, severity, confidence, runtime_status are untouched).
- **Remediation** items are validated (`REMEDIATION_STATE_SUPPORTED`); a
  version-unverified update is `VALIDATION_BLOCKED` with `MISSING_VERSION`.
- **Runtime** uses only persisted observations, LIVE vs MOCKED.
- **APK diff** produces `validate_comparison` transitions; a disappeared finding
  stays `NO_LONGER_DETECTED` (never inferred fixed/exploitable).
- **Investigation** hypotheses never change validation state.
- **Knowledge graph** projects `VALIDATION_CLAIM` / `VALIDATION_BLOCKER` /
  `VALIDATION_EVIDENCE` nodes and `VALIDATES` / `SUPPORTED_BY` / `CORROBORATES` /
  `BLOCKED_BY` / `REQUIRES_EVIDENCE` edges with `VALIDATION` provenance — **opt-in**
  (`include_validation=True`), so graph snapshots stay byte-identical by default.

## Orchestrator & determinism

A status-exempt `validation` stage runs after graph_snapshot; it is idempotent
(claims replaced, never duplicated) and never changes finding severity/
confidence/runtime_status, risk, remediation priority, or CVE state. Claim
fingerprint = `sha256(claim_type | target_type | target)` (analysis-independent,
no ids/timestamps/ordering); plan fingerprint = `sha256(sorted claim fingerprints)`.

## CLI / REST / report

```
androidsecforge validation claims|summary|blockers|requirements|findings|remediation|paths|show|explain|export <analysis-id>
  [--state --min-confidence --finding --component --claim-type --blocker] [--json]
```
REST: `GET /api/v1/analysis/{id}/validation[/summary|/claims|/blockers|/requirements|/findings|/remediation|/{claim_id}/explain]`,
`GET /api/v1/diff/{id}/validation`. JSON report gains a `validation` section and
per-finding `validation` metadata; Markdown via `validation export --format markdown`.

`doctor` reports `validation: READY` (offline). Static validation never depends on
ADB/Frida; live runtime corroboration is optional and reported as UNAVAILABLE
without a device.

## Performance

Each source is scanned once with dictionary lookups; reachability reuses
persisted paths; the Java/native graph is never recomputed. No N×M scans.

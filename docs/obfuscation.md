# Obfuscation & anti-analysis intelligence

The obfuscation layer (`app/analysis/obfuscation.py`) is a deterministic,
offline projection over already-persisted evidence (code entities, the canonical
code graph, semantics, native/JNI) that identifies transformations making static
analysis difficult, and the analytical impact that results.

It is **analysis intelligence, not an evasion/bypass engine**. It never mutates
findings, CVE state, severity, risk, remediation, validation, or the canonical
graph; never asserts exploitability; never claims *obfuscated == vulnerable* or
*anti-analysis == malicious*; and preserves observed-fact vs indicator vs UNKNOWN
distinctions (`UNKNOWN`, `UNKNOWN_NATIVE_TARGET`, `POSSIBLY_AFFECTED` all
preserved). Short identifiers or an API name alone are never sufficient to claim
obfuscation/anti-analysis.

## Detectors

- **Identifier obfuscation** (`ANDROID-OBFUSCATION-001`) — ratio of short/generated
  class/method names and package flattening over `code_entities`; graded
  `STRONG_INDICATOR` / `WEAK_INDICATOR` (never on a single short name).
- **String obfuscation** (`002`) — bounded scan of persisted string-bearing
  evidence for base64/hex/unicode-escaped constants + runtime-reconstruction
  sites; never decrypted (`resolved target = UNKNOWN`).
- **Control-flow obfuscation** (`003`) — dispatcher-like fan-out from the
  canonical code graph, `WEAK_INDICATOR` only above a high threshold (normal
  branching is not flagged).
- **Dynamic resolution** (`004`) — reuses persisted `REFLECTION_TARGET` /
  `DYNAMIC_LOAD` semantic edges, classified `RESOLVED` / `EXTERNALLY_INFLUENCED`
  (source reachable from an entry point) / `UNRESOLVED` (target UNKNOWN, never
  inferred). Edges are reused, never duplicated.
- **Native indirection** (`005`) — stripped symbols / sparse exports from
  `native_libraries`; JNI boundaries preserve `UNKNOWN_NATIVE_TARGET` (no
  fabricated native call graph).

## Anti-analysis intelligence

Separately classified indicators (`ANDROID-ANTI-ANALYSIS-001..004`): debugger /
environment (emulator/root) / instrumentation (Frida/Xposed) / integrity, plus
ptrace/timing/anti-hooking. Evidence levels: `INDICATOR` (presence of a name/API),
`SUPPORTED` (multiple independent categories), `CONFIRMED_STATIC` (a native
imported symbol among several), `UNKNOWN`. Presence never becomes "active
anti-analysis" automatically.

## Obfuscation score

Documented weighted sum (`OBFUSCATION_WEIGHTS` − `OBFUSCATION_PENALTIES`), clamped
0–100. It describes **analysis complexity**, a separate axis from severity /
confidence / risk / remediation priority / validation confidence. No ML, no
hidden multipliers.

## Analytical impact

`REDUCED_NAME_CONFIDENCE`, `UNRESOLVED_REFLECTION`, `UNRESOLVED_DYNAMIC_LOAD`,
`REDUCED_NATIVE_RESOLUTION`, `INCREASED_REACHABILITY_UNCERTAINTY`,
`INCREASED_BEHAVIORAL_UNCERTAINTY`. The engine records analytical impact rather
than rewriting any prior finding.

## Integrations

- **Semantics / CVE / risk / remediation / validation** — obfuscation adds
  analytical uncertainty and review-oriented recommendations
  (`REVIEW_REFLECTION` / `REVIEW_DYNAMIC_LOADING` / `REVIEW_NATIVE_INDIRECTION`)
  but never changes CVE state (`AFFECTED`/`POSSIBLY_AFFECTED`/…), severity, risk,
  or validation truth (`UNVERIFIED` never becomes verified).
- **Knowledge graph** — `OBFUSCATION_OBSERVATION` / `ANTI_ANALYSIS_INDICATOR` /
  `ANALYSIS_IMPACT` nodes and `INDICATES_OBFUSCATION` / `INDICATES_ANTI_ANALYSIS`
  / `AFFECTS_ANALYSIS` / `OBSCURES` edges with `OBFUSCATION` provenance —
  **opt-in** (`include_obfuscation=True`); graph snapshots stay byte-identical by
  default.
- **APK diff** — a new `obfuscation` diff category and `obfuscation_from_diff`
  transitions (`OBFUSCATION_INCREASED/DECREASED`, `NEW/REMOVED_ANTI_ANALYSIS_INDICATOR`,
  `ANALYSIS_IMPACT_CHANGED`) by stable content-derived fingerprints. Increased
  obfuscation is **never** a `SECURITY_REGRESSION` on its own — it is
  `INCONCLUSIVE` unless positive security evidence exists.
- **Investigation / graph queries** — named queries `obfuscated-entrypoints`,
  `obfuscated-components`, `anti-analysis`, `unresolved-reflection`,
  `unresolved-dynamic-loading`, `native-indirection`, `analysis-uncertainty`.
  Uncertainty boundaries (`MainActivity → reflection → UNKNOWN`) remain
  traversable, never dropped.

## Orchestrator & determinism

A status-safe `obfuscation` stage runs after validation; it never fails the
analysis when JADX/native/reflection targets are unavailable (categories report
`UNAVAILABLE`), is idempotent, and never mutates other layers. Observation
fingerprint = `sha256(category | indicator | target)` (content-derived, no
ids/timestamps/line numbers); view fingerprint aggregates them + the score.

## CLI / REST / report

```
androidsecforge obfuscation summary|list|impacts|anti-analysis|paths|show|explain|export <analysis-id>
  [--category --target --confidence --state --component] [--json]
```
REST: `GET /api/v1/analysis/{id}/obfuscation[/summary|/observations|/anti-analysis|/impacts|/{obs_id}/explain]`,
`GET /api/v1/diff/{id}/obfuscation`. JSON report gains an `obfuscation` section;
Markdown via `obfuscation export --format markdown`. `doctor: obfuscation READY`
(offline; no external service).

## Performance

Single-pass class/method scan with cached identifier statistics, indexed target
lookup, bounded string/method analysis, reuse of persisted reachability paths —
no N×M scans, no graph reconstruction. Bounds: `ASF_OBFUSCATION_MAX_CLASSES`,
`_MAX_METHODS`, `_MAX_STRINGS`, `_MAX_INDICATORS`.

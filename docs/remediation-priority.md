# Remediation priority

Remediation priority is a **separate, documented axis** from the risk engine
(`app/analysis/risk.py`). It is a deterministic weighted sum — no ML, no hidden
multipliers, no probabilistic black box. Two identical analyses always produce
identical priorities.

## Formula

```
priority_score = sum(weight of each applicable factor)     # clamped at >= 0
```

## Documented factor weights (`PRIORITY_WEIGHTS`)

| Factor | Weight | When it applies |
| --- | --- | --- |
| affected_reachable | +40 | CVE correlation `AFFECTED_REACHABLE` |
| affected_present | +25 | `PRESENT_AFFECTED` / `AFFECTED_NOT_REACHABLE` |
| possibly_affected | +12 | identity matches, version unverified |
| identity_confirmed | +10 | identity confidence EXACT/HIGH |
| reachable | +15 | vulnerable code / component reachable |
| not_reachable | −10 | vulnerable code not reachable |
| external_exposure | +15 | exported component / PUBLIC attack-surface node |
| fixed_version_available | +8 | provider supplies a fixed version |
| kev_known_exploited | +20 | external intelligence (CISA KEV) |
| epss_high | +10 | external intelligence (EPSS ≥ 0.5) |
| runtime_corroborated | +12 | a runtime observation corroborates the finding |
| native_jni_boundary | +6 | involves a native / JNI boundary |
| root_cause_critical | +15 | aggregated root cause is critical |
| root_cause_high | +10 | aggregated root cause is high |
| confirmed_static_finding | +12 | `CONFIRMED_BY_STATIC_ANALYSIS` |
| finding_high_severity | +10 | high-severity finding |
| finding_medium_severity | +5 | medium-severity finding |
| finding_low_severity | +2 | low/info-severity finding |
| unknown_native_target | 0 | neutral — uncertainty is never inflated |

`kev_known_exploited` / `epss_high` are external-intelligence signals; they raise
remediation priority but are **not** an exploitability claim.

## Bands

```
>= 70 CRITICAL   >= 45 HIGH   >= 25 MEDIUM   >= 10 LOW   >= 1 INFO
```

A `VERSION_UNVERIFIED` / `REVIEW_REQUIRED` item with a zero net score is
`UNDETERMINED` rather than forced into a band — uncertainty is never converted
into a remediation certainty. Priority is remediation urgency, never
exploitability.

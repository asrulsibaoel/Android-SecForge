# Risk engine

`backend/app/analysis/risk.py` produces a deterministic, explainable
attack-surface risk score — never an opaque ML score, and never a claim of
exploitability.

## Formula

`score = clamp(Σ positive_factor_weights − Σ mitigation_weights, 0, 100)`.

Every applicable factor is recorded as a `RiskFactor` (name, weight, direction,
evidence). Weights are documented constants in `RISK_WEIGHTS` / `RISK_MITIGATIONS`
and are edited in one place to reconfigure.

### Positive factors (weights)

exported_component 15, external_input 15, sensitive_sink_reachable 20,
dangerous_permission 8, missing_permission_protection 10, webview_javascript 10,
javascript_interface 12, reflection_external_input 10, dynamic_loading_external 15,
jni_boundary 8, native_unsafe_api 8, reachable_cve 20, affected_cve_unreachable 6,
possibly_affected_cve 4, unknown_dependency_version 3, weak_crypto 6,
cleartext_network 6, security_boundary_crossed 8.

### Mitigating factors (subtracted)

permission_protected 10, internal_only 8, source_sink_not_reachable 5,
dependency_not_affected 3, constant_only_reflection_or_dynload 4,
disconnected_source_sink 2.

Every factor is derived from persisted evidence (findings, boundaries,
reachability paths, dependencies, CVE match states). Example: a constant-path
`DexClassLoader` (no external input) yields no `dynamic_loading_external` factor
and adds the `constant_only_reflection_or_dynload` mitigation.

## Severity vs confidence (separate axes)

- **Severity** comes from the score band: 0–19 info, 20–39 low, 40–69 medium,
  70–89 high, 90–100 critical.
- **Confidence** is the average `confidence_score` of the contributing findings
  (low/medium/high). High severity with low confidence is valid and expected.

Rule-defined finding severities are preserved; risk scoring augments, it does not
overwrite them.

## Scopes

An `overall` `RiskAssessment` plus one per non-internal attack-surface node
(scope = node key). The highest-scoring per-node assessment is the highest-risk
entry point.

## CLI

```bash
androidsecforge risk summary <analysis-id> [--json]
androidsecforge risk entrypoints <analysis-id> [--json]
androidsecforge risk explain <analysis-id> [--json]
```

## Limitations & non-claims

- A score is **never** translated to "exploitable". It ranks attack surface, not
  proven impact.
- Weights are heuristic and deterministic; they are documented and tested, not
  calibrated against a labelled dataset.

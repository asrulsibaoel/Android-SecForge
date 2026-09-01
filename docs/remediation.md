# Remediation intelligence

The remediation layer (`app/analysis/remediation.py`) answers: *given everything
AndroidSecForge knows about an APK, what should be fixed first, why, what is
responsible, what version/configuration would address it, and what evidence
supports the recommendation?*

It is a deterministic **projection** over already-persisted evidence — findings,
CVE matches, root causes, attack surface, reachability, semantics, native/JNI,
security boundaries, runtime observations. It never mutates any source data or
the canonical graph, never produces automatic patches, never asserts
exploitability, and preserves every uncertainty state (`UNKNOWN`,
`POSSIBLY_AFFECTED`, `NOT_REACHABLE`, `NOT_OBSERVED`, `NO_LONGER_DETECTED`).

## State model

`OPEN`, `REVIEW_REQUIRED`, `VERSION_UNVERIFIED`, `RECOMMENDED`,
`CONDITIONALLY_RECOMMENDED`, `REMEDIATED`, `NO_LONGER_DETECTED`, `INCONCLUSIVE`,
`NOT_APPLICABLE`, `NEW_REMEDIATION_REQUIRED`. None implies exploitability.

## Actions (recommendations, not fixes)

`UPDATE_DEPENDENCY`, `REMOVE_DEPENDENCY`, `REPLACE_DEPENDENCY`,
`VERIFY_DEPENDENCY_VERSION`, `REVIEW_DEPENDENCY_VERSION`, `UPDATE_NATIVE_LIBRARY`,
`REVIEW_CODE_PATH`, `REVIEW_EXPORTED_COMPONENT`, `REVIEW_INTENT_INPUT`,
`REVIEW_DEEP_LINK_INPUT`, `REVIEW_WEBVIEW_CONFIGURATION`, `REVIEW_WEBVIEW_BRIDGE`,
`REVIEW_REFLECTION`, `REVIEW_DYNAMIC_LOADING`, `REVIEW_IPC_BOUNDARY`,
`REVIEW_NATIVE_JNI_BOUNDARY`, `REVIEW_NATIVE_API_USAGE`, `REVIEW_TLS_CONFIGURATION`,
`REVIEW_CRYPTO_CONFIGURATION`, `REVIEW_STORAGE`, `REVIEW_PROCESS_EXECUTION_PATH`,
`REMOVE_HARDCODED_SECRET`, `REVIEW_RUNTIME_BEHAVIOR`.

## Sources

Dependency/CVE matches → dependency remediation (see below); findings → mapped
per rule; PUBLIC attack-surface components carrying a finding/boundary →
`REVIEW_EXPORTED_COMPONENT`; IPC transactions → `REVIEW_IPC_BOUNDARY`; JNI
boundaries → `REVIEW_NATIVE_JNI_BOUNDARY`. A recommendation is never created just
because a package exists.

## Dependency remediation

- `AFFECTED` + known fixed version → `UPDATE_DEPENDENCY`, `DIRECT_FIX`,
  `RECOMMENDED`, `recommended_state = ">= X"`.
- `AFFECTED` + no fixed version → `REVIEW_DEPENDENCY_VERSION` (no version invented).
- `POSSIBLY_AFFECTED` (version unknown) → `VERIFY_DEPENDENCY_VERSION`,
  `VERSION_UNVERIFIED`; if a fixed version exists it becomes
  `CONDITIONALLY_RECOMMENDED` with a two-step action (verify, then upgrade
  ">= X after confirming the bundled version"). **AFFECTED is never asserted.**
- `NOT_AFFECTED` → no item.

## Runtime interaction

Runtime observations are corroborating evidence only, tagged
`STATIC_ONLY` / `RUNTIME_CORROBORATED` / `RUNTIME_NOT_OBSERVED` /
`RUNTIME_UNAVAILABLE`. `RUNTIME_CORROBORATED` raises priority;
`RUNTIME_NOT_OBSERVED` never downgrades or removes the static finding.

## APK-diff interaction

`remediation_from_diff` maps prompt-15 CVE/finding transitions:
`NEW_MATCH`/new finding → `NEW_REMEDIATION_REQUIRED`; a disappeared finding →
`NO_LONGER_DETECTED` (never "fixed"); an `AFFECTED → NOT_AFFECTED` transition with
positive installed-version evidence → `REMEDIATED`; otherwise `INCONCLUSIVE`.

## CLI / REST / report

```
androidsecforge remediation plan|list|show|explain|paths|summary|export <analysis-id>
  [--priority --status --action --fixability --component --dependency --cve --min-confidence] [--json]
```
REST: `GET /api/v1/analysis/{id}/remediation[/summary|/{item_id}|/{item_id}/explain]`,
`GET /api/v1/diff/{id}/remediation`. The analysis JSON report gains a
`remediation` section; Markdown export via `remediation export --format markdown`.

See [remediation-priority](remediation-priority.md),
[remediation-evidence](remediation-evidence.md),
[remediation-testing](remediation-testing.md).

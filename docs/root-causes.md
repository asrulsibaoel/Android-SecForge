# Root causes

A root cause aggregates the findings that are different manifestations of the
same underlying issue. Root causes are **deterministic**: the same inputs produce
the same `identifier = RC-<CATEGORY>-<sha256(apk|category|group)[:10]>`.

## Categories

`EXPORTED_COMPONENT_INPUT`, `IPC_EXPOSURE`, `UNSAFE_WEBVIEW_INPUT`,
`DANGEROUS_DYNAMIC_LOADING`, `REFLECTION_EXTERNAL_INPUT`, `COMMAND_EXECUTION`,
`JNI_REACHABLE_SURFACE`, `NATIVE_UNSAFE_API`, `INSECURE_NETWORK_CONFIGURATION`,
`WEAK_CRYPTO`, `DEPENDENCY_CVE`, `HARDCODED_SECRET`, `DEBUGGABLE_BUILD`,
`BACKUP_ENABLED`.

## Classification rules

Each finding maps to a category by its rule id (`_RULE_ROOT_CAUSE`), with two
dynamic routes:

- Reachability findings (`ANDROID-REACH-*`) route by the sink named in the
  finding title (WebView → `UNSAFE_WEBVIEW_INPUT`, reflection →
  `REFLECTION_EXTERNAL_INPUT`, dynamic loading → `DANGEROUS_DYNAMIC_LOADING`,
  command execution → `COMMAND_EXECUTION`, JNI boundary → `JNI_REACHABLE_SURFACE`,
  native API → `NATIVE_UNSAFE_API`).
- Native (`ASF-NATIVE-*`) → `NATIVE_UNSAFE_API`; CVE (`ANDROID-CVE-*`) →
  `DEPENDENCY_CVE`.

Component/dependency/library categories group per target; the rest group per
category. Duplicate findings are excluded. A root cause is created **only** when
at least one supporting finding exists — never invented.

## Contents

`RootCause` stores category, title, description, aggregated severity (max of
members) and confidence (highest-confidence member), affected components / code
nodes / dependencies, boundaries crossed, and reachable-path summaries.
`RootCauseFinding` links members (which back-link via `finding.root_cause_id`);
`RootCauseEvidence` records supporting rules and path chains.

## CLI

```bash
androidsecforge root-causes list <analysis-id> [--json]
androidsecforge root-causes show <analysis-id> [--json]
```

## Limitations

Grouping is by rule/target, not by a shared proven dataflow slice; two findings
in the same category on the same component are grouped even if they arise from
different call paths.

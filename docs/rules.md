# Security rule engine

Rules are **data-driven**: metadata lives in JSON under
`backend/app/rules/definitions/`, loaded by `backend/app/rules/engine.py`. The rule
catalogue is versioned via `ruleset_version()` (a content hash) and recorded on every
analysis for reproducibility.

## Rule schema

```json
{
  "id": "ANDROID-WEBVIEW-001",
  "title": "WebView JavaScript enabled",
  "category": "webview",
  "type": "code",
  "severity": "medium",
  "confidence": "medium",
  "status": "POTENTIAL",
  "description": "...",
  "remediation": "...",
  "references": ["..."],
  "patterns": ["setJavaScriptEnabled\\s*\\(\\s*true\\s*\\)"],
  "require_all": false,
  "mask": false,
  "condition": "debuggable_enabled"
}
```

- `type: manifest` rules evaluate a named `condition` over the normalized `ParsedManifest`
  (e.g. `debuggable_enabled`, `exported_component_without_permission`).
- `type: code` rules scan decompiled sources with `patterns` (regular expressions). With
  `require_all: true`, every pattern must co-occur in a file before a finding is emitted —
  so a lone suspicious API name does not produce a finding.
- `mask: true` redacts matched literals (used by the secret-detection rule).

## Current rules

Manifest: `ANDROID-MANIFEST-001` (debuggable), `-002` (allowBackup), `-003` (cleartext),
`ANDROID-COMPONENT-001` (exported component without permission), `-002` (exported provider).

Code: `ANDROID-WEBVIEW-001/002` (JavaScript enabled / JS interface), `ANDROID-TLS-001/002`
(permissive TrustManager / hostname verifier), `ANDROID-CRYPTO-001` (weak algorithm),
`ANDROID-SECRET-001` (hardcoded secret, masked).

## Finding status

Manifest observations that are directly verifiable are `CONFIRMED_BY_STATIC_ANALYSIS`.
Code pattern matches are `POTENTIAL` — an indicator, not a proven vulnerability, until
reachability/runtime evidence exists (future slices).

## Adding a rule

Add a JSON object to the appropriate definitions file, then add a positive and a negative
fixture in `backend/tests/test_rules.py`. No engine code change is required for standard
manifest conditions and code patterns.

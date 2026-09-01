# Attack surface model

`backend/app/analysis/attack_surface.py` builds a structured attack surface from
existing manifest/semantic/native evidence. Nothing is guessed.

## Nodes

`EXPORTED_ACTIVITY` / `EXPORTED_SERVICE` / `EXPORTED_RECEIVER` /
`EXPORTED_PROVIDER` (from components), `DEEP_LINK`, `WEBVIEW_BRIDGE`,
`BINDER_ENTRY`, `JNI_BOUNDARY` (from security boundaries), and `NATIVE_LIBRARY`
(bundled `.so`).

## Exposure classification (deterministic)

| Situation | Exposure |
| --- | --- |
| Exported component, no permission | `PUBLIC` |
| Exported component, with permission | `PERMISSION_PROTECTED` |
| Conditionally exported (intent-filter) | `PUBLIC` |
| Provider export version-dependent / unresolved | `UNKNOWN` |
| Not exported | `INTERNAL` (not added as attack surface) |
| Deep link | `PUBLIC` |
| WebView JS bridge / Binder entry | `UNKNOWN` (reachability of the caller not proven) |
| JNI boundary / native library | `INTERNAL` |

## Edges

`LEADS_TO` (surface node → a root cause it contributes to, matched by component)
and `REACHES` (entry point → reachable sink, from persisted reachability paths).
No edge is fabricated.

## Per-node risk

Each non-internal surface node receives a per-entry-point risk score from the
risk engine (see [risk-engine.md](risk-engine.md)); the highest-scoring node is
the highest-risk entry point.

## CLI

```bash
androidsecforge attack-surface list <analysis-id> [--json]
androidsecforge attack-surface show <analysis-id> [--json]
androidsecforge attack-surface paths <analysis-id> [--json]
```

## Limitations

Binder and WebView-bridge exposure is `UNKNOWN` because the caller/loaded-content
side cannot be proven statically; these are not assumed `PUBLIC`.

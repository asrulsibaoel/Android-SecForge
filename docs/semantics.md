# Android semantic analysis

The semantics layer (`backend/app/analysis/semantics.py`) teaches the engine
Android execution semantics rather than treating decompiled code as generic
Java. It **extends the existing reachability graph** (never a second graph) so
semantic edges participate in `graph paths` and reachability automatically.

## Framework dispatch & entry points

Instead of ordinary `CALLS` edges, framework invocation is explicit: an
`ANDROID_FRAMEWORK` node dispatches (`FRAMEWORK_DISPATCH`) to each component
lifecycle method **that actually exists** in decompiled code. Each becomes an
`AndroidEntryPoint` with the lifecycle event (CREATE/START/RESUME/RECEIVE/QUERY…),
exported state, permission, and intent filters.

## Semantics covered

| Area | What is modeled | Edge / entity |
| --- | --- | --- |
| Components / lifecycle | Activity/Service/Receiver/Provider/Application entry methods | `android_entry_points`, `FRAMEWORK_DISPATCH` |
| Intents | getIntent/new Intent/startActivity/startService/bindService/sendBroadcast; action/data/component constants (else UNKNOWN) | `intents` |
| Deep links | manifest intent-filter data (scheme/host/path/mime) → component entry | `deep_links`, `DEEP_LINK` |
| IPC / Binder | `onTransact` (service entry, transaction `case` codes), `transact()` (client, UNKNOWN target) | `ipc_transactions`, `IPC_CALL` |
| ContentProvider | exported provider query/insert/update/delete/openFile/call → `CONTENT_PROVIDER_INPUT` source | source + `ACQUIRES` |
| WebView | `addJavascriptInterface(obj, "name")` bridges | `WEBVIEW_BRIDGE` |
| Reflection | `Class.forName("const")` (target resolved) vs dynamic (UNKNOWN) | `REFLECTION_TARGET` |
| Dynamic loading | DexClassLoader/PathClassLoader… with path classification (static/external/app-controlled/UNKNOWN) | `DYNAMIC_LOAD` |
| Crypto | Cipher/MessageDigest/Mac/KeyGenerator `getInstance("ALG")` — algorithm extracted | `semantic_edges` (CRYPTO) |
| Network | HttpURLConnection/OkHttp/Retrofit/Socket; URL constant; TLS custom vs default | `semantic_edges` (NETWORK) |
| Storage | openFileInput/Output, FileInput/OutputStream, SharedPreferences, SQLite/Room | `semantic_edges` (STORAGE) |
| Security boundaries | EXTERNAL_INTENT, BINDER_IPC, WEBVIEW_JS, JNI, DEEP_LINK | `security_boundaries`, `SECURITY_BOUNDARY` |

Constants are extracted only when literally present (comments stripped, string
literals preserved); dynamic values are recorded as `UNKNOWN`. Confidence is
`HIGH` (framework semantics + direct evidence), `MEDIUM`, `LOW`, or `UNKNOWN`, and
is never upgraded without new evidence (e.g. a LOW JNI binding keeps the boundary
at LOW).

## Semantic findings

Emitted only for a security-relevant condition, at INFO/LOW/MEDIUM severity:

- `ANDROID-SEMANTIC-001` exported component receives externally controlled input
- `ANDROID-SEMANTIC-002` exported ContentProvider reaches a file operation
- `ANDROID-SEMANTIC-003` Binder entry reaches a security-sensitive operation
- `ANDROID-SEMANTIC-004` WebView JavaScript interface exposed through a reachable path
- `ANDROID-SEMANTIC-005` external input reaches dynamic class loading

A constant reflection target or a constant-path DexClassLoader with no external
input produces **no** finding, and an unrelated source and sink are never
connected.

## CLI & report

```bash
androidsecforge semantic entrypoints <analysis-id> [--json]
androidsecforge semantic intents <analysis-id> [--json]
androidsecforge semantic ipc <analysis-id> [--json]
androidsecforge semantic deeplinks <analysis-id> [--json]
androidsecforge semantic boundaries <analysis-id> [--json]
```

`graph paths` traverses the semantic edges automatically. The JSON report adds
`android_entry_points`, `intents`, `deep_links`, `ipc_transactions`,
`security_boundaries`, and `semantic_edges`, each with evidence and confidence.

# Live runtime validation & behavioral corroboration

The runtime-validation layer (`app/analysis/runtime_validation.py`) extends the
Runtime Lab (prompts 12–13) with an explicit, auditable lifecycle for running an
APK on a **real, connected** device/emulator and correlating the observed
behavior against the entire static model — findings, code methods, components,
attack surface, reachability, the knowledge graph, CVE intelligence, remediation,
security validation, and the deep native/JNI graph.

It only ever **observes, correlates, validates, and explains**. It adds no
exploit/payload/persistence/privesc/credential-theft/stealth, no automatic
exploitation/patching/APK-or-manifest modification, and no `exploitable` field or
conclusion. Hooks are observation-only (call the original, return it unchanged).

## Modes — LIVE vs MOCKED are never conflated

| Mode | Meaning |
|------|---------|
| `LIVE` | observations from a real (non-mock) adapter on a connected device |
| `MOCKED` | offline test-adapter observations — **never** count as live corroboration |
| `UNAVAILABLE` | no runtime observations recorded |

Only genuinely `LIVE` evidence can move a finding to `CONFIRMED_RUNTIME_BEHAVIOR`
or a validation claim to `RUNTIME_CORROBORATED`. `MOCKED` evidence is recorded
and visible but stays `RUNTIME_INCONCLUSIVE` / `UNVERIFIED`. Nothing auto-runs:
live operations happen only on an explicit `runtime validate` / `runtime *`
command, and with no device attached the lifecycle returns
`LIVE_RUNTIME_UNAVAILABLE` — never fabricated data.

## Lifecycle (explicit, audited)

`RuntimeLab.validate(analysis, device, apk_path, profiles, duration, activity)`
runs: select device → verify APK SHA-256 → install → launch → collect logcat /
processes → observe (ADB + optional Frida hooks) → stop → correlate. Every step
writes a `RuntimeAuditEvent`. If Frida is unavailable it continues ADB-only.
`finalize()` stops and (re)builds the correlation run.

## Observation taxonomy (§2)

Each observation is classified into a higher-level taxonomy (stored on
`runtime_observations.taxonomy`): `PROCESS_LIFECYCLE`, `COMPONENT_DISPATCH`,
`ACTIVITY_LAUNCH`, `SERVICE_START`, `BROADCAST_DISPATCH`,
`CONTENT_PROVIDER_ACCESS`, `BINDER_TRANSACTION`, `INTENT_METADATA`,
`DEEP_LINK_DISPATCH`, `WEBVIEW_NAVIGATION`, `REFLECTION_RESOLUTION`,
`DYNAMIC_CLASS_LOADING`, `JNI_INVOCATION`, `NATIVE_API_INVOCATION`, `TLS_NETWORK`,
`FILESYSTEM_ACCESS`, `SECURITY_SENSITIVE_CONFIG`. Secrets (passwords/tokens/keys)
are masked/redacted; no credentials, cookies, private keys, or raw user data are
stored.

## Static ↔ LIVE correlation

Persisted `RuntimeCorrelation` rows link a runtime observation to a static
subject only when identifiers match persisted evidence:

- observed Java method ↔ a static `JAVA_METHOD` code node → `RUNTIME_CONFIRMS`;
- observed Java method ↔ a resolved deep-native JNI binding → `RUNTIME_INVOCATION`
  (a Java→JNI→native→API relationship; `UNKNOWN_NATIVE_TARGET` stays UNKNOWN);
- observed native symbol ↔ a deep-native function → `RUNTIME_INVOCATION`;
- observed native symbol ↔ a native-API observation → `RUNTIME_REACHES`.

No native reachability is fabricated because a native function merely exists.
Runtime evidence can only **raise** validation confidence when identity is strong
and the observation is LIVE; it never converts `UNKNOWN → SAFE`,
`POSSIBLY_AFFECTED → AFFECTED`, `NOT_OBSERVED → NOT_VULNERABLE`, or
`STATIC_SUPPORTED → EXPLOITABLE`. `NOT_OBSERVED` never means safe.

## Finding integration (additive)

Findings gain a `runtime_validation_state` — `CONFIRMED_RUNTIME_BEHAVIOR`,
`RUNTIME_CORROBORATED`, `NOT_OBSERVED`, `RUNTIME_INCONCLUSIVE`, `LIVE_UNAVAILABLE`
— set without changing severity, severity_score, static confidence, risk, CVE
state, or remediation priority.

## Integrations (guarded; supplement-only)

- **Validation (prompt 17)** — new runtime claim types
  `RUNTIME_BEHAVIOR_OBSERVED`, `COMPONENT_DISPATCH_OBSERVED`,
  `REFLECTION_RESOLUTION_OBSERVED`, `DYNAMIC_LOAD_OBSERVED`,
  `JNI_INVOCATION_OBSERVED`, `NATIVE_API_INVOCATION_OBSERVED`,
  `WEBVIEW_BEHAVIOR_OBSERVED`, `IPC_BEHAVIOR_OBSERVED`,
  `NETWORK_SECURITY_BEHAVIOR_OBSERVED`. A claim is `RUNTIME_CORROBORATED` only on
  LIVE evidence; MOCKED leaves it `UNVERIFIED`/`BLOCKED`.
- **Deep native (prompt 20)** — LIVE `Java → JNI → native → API` invocation is
  correlated to the persisted deep-native graph by matching identifiers only.
- **Knowledge graph (prompt 14)** — opt-in `include_runtime_validation=True`
  projects `RUNTIME_CORRELATION` nodes and `RUNTIME_CONFIRMS` /
  `RUNTIME_CORROBORATES` / `RUNTIME_REACHES` / `RUNTIME_INVOCATION` edges with
  `RUNTIME_ADB` / `RUNTIME_FRIDA` provenance and a LIVE marker. The canonical
  graph stays authoritative; default snapshots are byte-identical.
- **APK diff (prompt 15)** — a runtime-behavior diff (`RUNTIME_BEHAVIOR_ADDED` /
  `_REMOVED` / `_UNCHANGED`, or `RUNTIME_OBSERVATION_UNAVAILABLE` when not both
  LIVE). Removed behavior is `NO_LONGER_OBSERVED`, never `FIXED`; only a
  newly-observed reaching/invocation is security-relevant.
- **Remediation (prompt 18)** — runtime corroboration is a priority factor and
  evidence tag; it never marks a remediation `REMEDIATED` on its own (that still
  requires the diff/state/version transition rules).
- **Investigation (prompt 14)** — runtime sessions/observations/correlations are
  pinnable; the timeline shows `STATIC_FINDING`, `LIVE_OBSERVATION`,
  `CORRELATION`, and `VALIDATION_TRANSITION` events. Researcher hypotheses remain
  researcher state and never mutate analytical truth.

## Evidence chain

`runtime explain` / `validation explain` produces a provenance-retaining chain:
Finding → static evidence → attack surface → reachability → runtime session →
LIVE observation → correlated target → validation claim → requirements →
blockers → current validation state.

## Safety bounds (§13)

Config bounds (reaching one records `TRUNCATED` explicitly — evidence is never
silently discarded): `ASF_RUNTIME_MAX_SESSION_DURATION_SECONDS`,
`ASF_RUNTIME_MAX_EVENTS`, `ASF_RUNTIME_MAX_PROCESSES`,
`ASF_RUNTIME_MAX_HOOK_EVENTS`, `ASF_RUNTIME_MAX_ARTIFACTS`,
`ASF_RUNTIME_MAX_CORRELATION_PATHS`, `ASF_RUNTIME_REDACTION_LIMIT`,
`ASF_RUNTIME_VALIDATION_TIMEOUT_SECONDS`, plus the prompt-12 logcat/observation
bounds. Persisted artifacts (masked logcat, process inventory, runtime-event
summary, observation JSON, hook summary, correlation result) each carry a
SHA-256, session, source, timestamp, size, and redaction status.

## Determinism & persistence

`RuntimeValidationRun` and `RuntimeCorrelation` are rebuilt idempotently
(collections cleared and rebuilt — no duplicates). The run fingerprint is
`sha256` over sorted content-derived correlation fingerprints (finding
fingerprints, code-node keys, deep-native fingerprints, observation identity,
mode) — no DB ids or timestamps participate. Migration `0020_runtime_validation`
adds the two tables and the additive `runtime_observations.taxonomy` /
`runtime_observations.redacted` / `findings.runtime_validation_state` columns.

## CLI / REST / doctor

```
androidsecforge runtime validate --analysis <id> --device <serial> [--apk PATH] [--profiles ...] [--duration N] [--activity A]
androidsecforge runtime observe|events|artifacts --session <id>
androidsecforge runtime correlate --analysis <id>
androidsecforge runtime validate-finding --analysis <id> --finding <rule|id>
androidsecforge runtime validate-path --analysis <id> --from <q> [--to <q>]
androidsecforge runtime explain --analysis <id> --subject <ref>
androidsecforge runtime finalize --session <id>
```
All support `--json`; none fabricate LIVE data when no device exists.

REST: `POST /api/v1/runtime/validate`,
`GET /api/v1/analysis/{id}/runtime/validation|correlations`,
`POST /api/v1/analysis/{id}/runtime/correlate`,
`GET /api/v1/analysis/{id}/runtime/explain/{subject}`,
`GET /api/v1/runtime/sessions/{id}/events|artifacts`,
`POST /api/v1/runtime/sessions/{id}/finalize`,
`GET /api/v1/diff/{id}/runtime`. Responses expose whether evidence is
`LIVE` / `MOCKED` / `UNAVAILABLE`.

`runtime doctor` reports `adb`, `device`, `emulator`, `frida`, `frida-server`,
`runtime-validation`, and `native-runtime-correlation` independently
(`READY` / `PARTIAL` / `UNAVAILABLE` / `FAILED`) — no capability is `READY`
unless its dependency is genuinely available.

## Real acceptance (Magisk v29.0)

adb and frida are installed but **no device is attached**, so live validation is
honestly `LIVE_RUNTIME_VALIDATION = UNAVAILABLE`: `runtime validate --device
emulator-5554` returns `LIVE_RUNTIME_UNAVAILABLE`, and `runtime doctor` reports
`runtime-validation = PARTIAL`, `native-runtime-correlation = UNAVAILABLE`. The
offline correlation path was exercised on the real Magisk analysis via a
clearly-`MOCKED` session observing real native symbols (`strcpy`, `dlopen`): it
produced `RUNTIME_INVOCATION`/`RUNTIME_REACHES` correlations to the persisted
deep-native functions/APIs, kept all 17 findings `RUNTIME_INCONCLUSIVE` (MOCKED
never confirms), left the default KG snapshot byte-identical (opt-in added 4
correlation nodes), and asserted no exploitability.

## Real-device discovery & acceptance (prompt 23)

`app/runtime/device.py::discover_device(serial)` is a read-only capability flow
built from **actual ADB output** (never inferred). It classifies
`device_state ∈ {CONNECTED, UNAUTHORIZED, OFFLINE, NOT_CONNECTED, ADB_UNAVAILABLE}`,
reports `frida_host`, checks `frida_server` **on the device** (never inferred from
host Frida → `AVAILABLE | FRIDA_SERVER_UNAVAILABLE | UNKNOWN`), and derives
`runtime_validation` (`READY`/`PARTIAL`/`UNAVAILABLE`) and
`native_runtime_correlation` (`READY` only with a reachable frida-server). Device
metadata is redacted to safe, non-personal fields, each carrying provenance (the
adb commands used). Exposed as `runtime device [--serial]` (CLI) and
`GET /api/v1/runtime/device` (REST).

`RuntimeLab.observe_package_adb(session, package)` collects **LIVE, ADB-only**
observations scoped to the selected package only — process presence (`pidof`) and
package-filtered logcat component dispatch (`START … cmp=<pkg>/<act>` /
`Displayed …`). ADB observations carry `source=ADB` (never Frida), taxonomy is
classified deterministically, secrets are masked, bounds enforced with `TRUNCATED`
recorded. It never attaches to unrelated processes.

**Real acceptance — outcome B (ADB LIVE; Frida-server unavailable).** Exercised
against a genuine physical device: **POCO/Xiaomi (`peridot`, model 24069PC21G),
Android 16 (API 36), arm64-v8a, `user` build (unrooted), authorized & responsive,
serial `d49907fc`.** Host Frida `17.17.0` present; **frida-server absent →
`FRIDA_SERVER_UNAVAILABLE`**, so native/JNI LIVE instrumentation is UNAVAILABLE.
`runtime device` → `device=CONNECTED, runtime-validation=READY,
native-runtime-correlation=PARTIAL`. A LIVE session (adapter=`adb`) installed
Magisk v29.0 (SHA-256 verified against the persisted analysis), launched it
(MainActivity dispatched, pid observed), and collected **6 LIVE ADB observations**
scoped to `com.topjohnwu.magisk` (PROCESS_LIFECYCLE, ACTIVITY_LAUNCH,
COMPONENT/SERVICE/BROADCAST/PROVIDER dispatch) → **6 LIVE correlations
(RUNTIME_ADB), 6 validation claims → RUNTIME_CORROBORATED**. Native findings
stayed `LIVE_UNAVAILABLE` (native behavior needs Frida). Default KG snapshot
byte-identical; opt-in projection added **6 RUNTIME_CORRELATION nodes** with LIVE
marker + RUNTIME_ADB provenance. A SHA-256 artifact was persisted; the session was
finalized (audit: CREATE→SELECT_DEVICE→INSTALL→LAUNCH→OBSERVE→ARTIFACT→STOP→FINALIZE)
and **Magisk was uninstalled** afterward (device restored). No exploitability was
asserted; runtime never overwrote static severity/score/status.

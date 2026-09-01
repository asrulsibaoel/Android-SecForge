# Runtime Lab

The Runtime Lab is an **optional, explicit, offline-degrading** layer that
collects runtime evidence from a device/emulator and correlates it with the
existing static model. It never executes an APK automatically, never installs or
connects silently, and never fabricates observations.

## Execution model (explicit only)

Nothing happens without a user command. A typical flow:

```bash
androidsecforge runtime doctor                       # capability detection
androidsecforge runtime devices                       # list attached devices
androidsecforge runtime session --analysis <id> --device <serial>   # create + select
androidsecforge runtime install  --analysis <id> --device <serial>  # explicit install
androidsecforge runtime launch   --session <sid> --activity .MainActivity
androidsecforge runtime logcat   --session <sid>
androidsecforge runtime processes --session <sid>
androidsecforge runtime frida attach --session <sid> --profiles lifecycle,webview,crypto
androidsecforge runtime stop     --session <sid>
androidsecforge runtime correlate --analysis <id>     # static <-> runtime
```

Every command accepts `--json`. See [adb.md](adb.md), [frida.md](frida.md),
[runtime-correlation.md](runtime-correlation.md), [runtime-safety.md](runtime-safety.md),
[runtime-testing.md](runtime-testing.md).

## Session states

`CREATED → DEVICE_SELECTED → INSTALL_REQUESTED → INSTALLED → LAUNCH_REQUESTED →
RUNNING → INSTRUMENTING → STOPPING → COMPLETED` (or `FAILED` / `CANCELLED`). A
state is only set when the underlying operation actually succeeds.

## Persistence

`runtime_devices`, `runtime_sessions`, `runtime_observations`, `runtime_events`,
`runtime_processes`, `runtime_artifacts`, `runtime_hook_profiles`,
`runtime_audit_events`, plus `findings.runtime_status` /
`findings.runtime_evidence_count` / `findings.validation_state`.

## Artifacts & bounds

Session artifacts live under `workspace/<sha256>/runtime/<session>/`. The original
APK is never modified. Logcat is a bounded dump (`-d`), not a persistent stream;
observations, logcat bytes/lines, and artifacts are all size/count-capped
(`ASF_RUNTIME_*` settings). No unbounded event collection.

## Report

The JSON report gains `runtime_summary` (with `mode`: `LIVE` / `MOCKED` /
`UNAVAILABLE`), `runtime_sessions`, `runtime_observations`,
`runtime_correlations`, and `runtime_validation`. There is intentionally **no**
`exploitable` field.

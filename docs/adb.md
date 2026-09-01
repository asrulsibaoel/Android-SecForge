# ADB adapter

`backend/app/runtime/adb.py` wraps the Android Debug Bridge safely.

## Safety

- Argument arrays only — **never** `shell=True`.
- Strict per-command timeouts (`ASF_RUNTIME_COMMAND_TIMEOUT_SECONDS`).
- stdout/stderr/exit-code captured into a structured `AdbResult`.
- No privilege escalation; `rooted` is inferred only from safely observable build
  props (`ro.debuggable=1` and `ro.secure=0`) and is otherwise `None`.
- Device operations are isolated by `-s <serial>`.

## Detection & discovery

`adb version` and `adb devices -l` are read-only. `runtime devices` lists and
persists attached devices; `runtime device-info <serial>` enriches from
`getprop` (model, manufacturer, Android version, SDK, ABI, emulator flag).

## Explicit operations

`install -r`, `uninstall`, `am start` / `monkey` launch, `am force-stop`,
`logcat -d` (bounded dump, not a stream), `ps -A`, `dumpsys package`. Each is a
distinct method invoked only by an explicit CLI/REST call and recorded in
`runtime_audit_events`.

## Installation

Set `ASF_ADB_PATH` or put `adb` on `PATH` (Android platform-tools). Verify with
`androidsecforge runtime doctor`. When adb is absent, all runtime operations
degrade to honest `UNAVAILABLE` / `FAILED`.

## Parsers

`parse_logcat()` and `parse_ps()` are pure functions (unit-tested without a
device) that normalize threadtime logcat lines and `ps -A` output.

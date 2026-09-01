# Runtime testing

The full test suite runs **without** an Android device, emulator, ADB, or Frida.

## Mock adapters

`backend/tests/test_runtime.py` provides `MockAdb` / `MockFrida` (duck-typed
subclasses of the real adapters) that return canned device/logcat/ps output and
canned observations. This exercises the entire session lifecycle, masking,
persistence, and static↔runtime correlation offline.

**MOCKED is not LIVE.** Each session records the adapter kind
(`metadata.adapter = "mock" | "adb"`), and the report's `runtime_summary.mode`
reports `MOCKED`, `LIVE`, or `UNAVAILABLE` accordingly. A mocked run is never
presented as real runtime capability.

## Coverage (`test_runtime.py`)

logcat/ps parsers, secret masking + truncation, full session lifecycle + audit
trail, install SHA-256 mismatch rejection, offline (no-adb) honest degradation,
Frida attach → masked observation persistence, Frida-unavailable degradation, and
static↔runtime correlation (confirmed / NOT_OBSERVED≠SAFE / native-supports-path).

## Live acceptance

Runtime integration against a real device/emulator + Frida is a separate,
explicit step. If no device is attached, `androidsecforge runtime doctor` reports
`device: NOT_CONNECTED` and live acceptance is `UNAVAILABLE` — it is never faked.
Run the live flow manually:

```bash
androidsecforge runtime doctor
androidsecforge runtime devices
androidsecforge runtime install --analysis <id> --device <serial>
androidsecforge runtime launch  --session <sid>
androidsecforge runtime frida attach --session <sid> --profiles webview,crypto
androidsecforge runtime stop    --session <sid>
androidsecforge runtime correlate --analysis <id> --json
```

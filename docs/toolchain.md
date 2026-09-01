# Toolchain & capability detection

AndroidSecForge treats external tools as optional capabilities. Run:

```bash
androidsecforge doctor          # human-readable
androidsecforge doctor --json   # machine-readable
```

For each tool the report includes `detected`, `path`, `version`, `status`, whether it is `required`, and the `capabilities` it unlocks.

| Tool | Required | Unlocks | Notes |
| --- | --- | --- | --- |
| Python | yes | core runtime | 3.12+ |
| Node.js + npm | for Web UI only | React investigation workspace (`frontend/`) | 18+ (20 LTS+ recommended); not needed for CLI/REST |
| Java (JDK) | no | **JADX and Ghidra** (prerequisite) | JDK 21+ (jadx needs Java 11+; Ghidra 12 needs JDK 21+) |
| JADX | no | Java decompilation, code index, code graph, reachability, semantics | set `ASF_JADX_PATH`; see [jadx.md](jadx.md) |
| Ghidra | no | **deep native** call-chain (functions, call edges, JNI resolution, native-API reachability) | set `ASF_GHIDRA_PATH`; enable with `ASF_GHIDRA_DEEP_ENABLED=true`; see [deep-native.md](deep-native.md) |
| adb (platform-tools) | no | real-device discovery / install / launch / logcat → live runtime validation | set on `PATH`; see [runtime.md](runtime.md) |
| Frida (host) | no | live native/JNI instrumentation → native-runtime correlation | `pip install frida-tools`; also needs frida-server on device (root) |
| emulator | no | emulator runtime target | any AVD/emulator adb device works |
| apktool | no | — | **not used**; the pipeline parses binary AXML in-process, so its absence has no effect |
| Android SDK | no | APK tooling | detected via `ANDROID_HOME`/`ANDROID_SDK_ROOT` or `adb` location |

Statuses: `AVAILABLE`, `CAPABILITY_UNAVAILABLE` (optional and missing), `MISSING` (required and missing).

## Installation pointers

See [installation.md](installation.md) for the full setup guide. Quick pointers:

- **JADX**: download from https://github.com/skylot/jadx/releases, unzip, and set `ASF_JADX_PATH` to `bin/jadx` (or put it on `PATH`). Requires Java 11+.
- **Ghidra**: download from https://github.com/NationalSecurityAgency/ghidra/releases, unzip, set `ASF_GHIDRA_PATH` to the install dir, and enable deep native with `ASF_GHIDRA_DEEP_ENABLED=true`. Requires JDK 21+. Deep analysis is slow (~1 min per native library) — see [deep-native.md](deep-native.md).
- **adb / platform-tools**: install via Android Studio or the [platform-tools](https://developer.android.com/tools/releases/platform-tools) zip; put `adb` on `PATH`. Enables runtime validation ([runtime.md](runtime.md)).
- **Frida**: `pip install frida-tools` (host). Live native/JNI instrumentation also needs frida-server on the device, which requires root.
- **Node.js**: install Node 18+ (20 LTS+ recommended) for the Web UI (`cd frontend && npm install`).

The framework never installs software silently. `doctor` only detects; automatic installation, if added later, will be explicit opt-in.

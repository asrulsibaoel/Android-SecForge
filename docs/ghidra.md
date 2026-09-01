# Ghidra integration (optional)

Ghidra is an **optional** deep native-analysis backend. ELF parsing, symbols,
dependencies, JNI discovery, and native rules all work without it — Ghidra only
adds recovered function information for stripped or complex binaries.

## Detection

`androidsecforge doctor` reports Ghidra via `ASF_GHIDRA_PATH`,
`GHIDRA_INSTALL_DIR`/`GHIDRA_HOME`, or an `analyzeHeadless` on `PATH`. It is never
installed silently.

## Behavior

The `ghidra` pipeline stage resolves to one of:

| Situation | Stage status | `ghidra_status` |
| --- | --- | --- |
| Not installed | UNAVAILABLE | UNAVAILABLE |
| Installed but not enabled | SKIPPED | DISABLED |
| Installed and enabled | COMPLETE | COMPLETE |

Ghidra runs only when both available **and** explicitly enabled
(`ASF_GHIDRA_ENABLED=true`), because analyzing many libraries is expensive.
Ghidra's absence never degrades the overall analysis status — an APK whose other
stages complete is still `COMPLETE`.

## Invocation

Each library is imported into an isolated, throwaway project via
`analyzeHeadless` (argument array, never `shell=True`), with a per-file timeout
(`ASF_GHIDRA_TIMEOUT_SECONDS`) and captured stdout/stderr/exit-code. A post-script
(`backend/app/analysis/ghidra_scripts/ExportFunctions.py`, Jython) emits
normalized function records (name, address, size, namespace) as JSON, which are
persisted as `NativeFunction` rows with `source=Ghidra`. Ghidra's internal project
is not copied into the database — only normalized results.

## Installation

Download from https://ghidra-sre.org/, unzip, and set `GHIDRA_INSTALL_DIR` (or
`ASF_GHIDRA_PATH` to the install dir or the `analyzeHeadless` launcher). Requires
a compatible JDK. This project does not pin or install Ghidra.

# Native (ELF) analysis

AndroidSecForge treats native libraries as first-class artifacts. Discovery and
ELF parsing run as part of the standard pipeline and require no external tools.

## Discovery

Every `lib/<abi>/*.so` in the APK is enumerated, hashed (SHA-256), and extracted
into the per-APK workspace (`workspace/<sha256>/native/<abi>/`). The original APK
is never modified. Supported ABI directories include `arm64-v8a`,
`armeabi-v7a`, `x86`, and `x86_64` (any `lib/<abi>/` is recorded).

## ELF parsing

A self-contained parser (`backend/app/analysis/elf.py`, no `pyelftools`
dependency) extracts, for ELF32/ELF64 and both endiannesses:

- header: class, endianness, machine/architecture, type, entry point
- section headers and the section-header string table
- `.dynsym`/`.dynstr` — dynamic (exported/imported) symbols
- `.symtab`/`.strtab` — static symbols (absent in stripped binaries)
- `.dynamic` — `DT_NEEDED` dependencies and `DT_SONAME`

Malformed or truncated input is reported as `status=FAILED` for that library
(`ok=False` with a reason) without affecting other libraries or raising. Stripped
binaries are handled gracefully: `.dynsym` still yields exports/imports;
`symbols_available`/`stripped` are reported honestly. No function names are ever
invented.

## Model

- **NativeLibrary** — path, ABI, filename, size, SHA-256, ELF class, architecture,
  endianness, type, entry point, SONAME, stripped, status, error.
- **NativeFunction** — name, address, symbol type, binding, visibility, size, and
  `kind` (`exported` / `imported` / `local`), `is_jni`, `source` (`ELF`/`Ghidra`),
  `confidence`.
- **NativeDependency** — a `DT_NEEDED` entry (the dependency graph APK → library →
  NEEDED library).

## Native security heuristics

Data-driven rules (`backend/app/rules/definitions/native.json`) scan each
library's *imported* symbols for dangerous C APIs (`strcpy`, `system`, `popen`,
scanf-family, insecure temp files, weak crypto primitives). These are
**indicators, not confirmed vulnerabilities** — findings say "potential unsafe API
usage", carry `status=POTENTIAL`, and cite the library and imported symbol. See
[rules.md](rules.md) and [findings.md](findings.md).

## CLI

```bash
androidsecforge native list <analysis-id> [--json]
androidsecforge native inspect <analysis-id> [--json]
androidsecforge native functions <analysis-id> [--json]
androidsecforge native jni <analysis-id> [--json]
```

The JSON report adds `native_libraries`, `native_functions`,
`native_dependencies`, `jni_bindings`, `native_findings`, and `ghidra_status`.

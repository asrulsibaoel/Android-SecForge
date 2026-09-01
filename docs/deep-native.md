# Deep native / Ghidra correlation

The deep-native layer (`app/native/deep_native.py`) extends the existing ELF/JNI
analysis (prompt 8) with deeper native intelligence that correlates persisted
native evidence with **optional** Ghidra static analysis. Its focus is
**Java ↔ JNI ↔ native ↔ native-API correlation**, not exploitability.

It is a **pure supplement**. It never mutates findings, CVE state, severity,
risk, remediation priority, validation state, runtime state, or the canonical
code graph; it never asserts exploitability and introduces no `exploitable`
field or conclusion. Core distinctions are preserved verbatim:

- a native function **present** ≠ reachable from Java;
- a JNI export **present** ≠ the Java side invokes it;
- a dangerous native API **present** ≠ a vulnerability;
- `UNKNOWN` / `UNKNOWN_NATIVE_TARGET` are preserved, never inferred.

## Modes (Ghidra is optional; offline is fully functional)

| Mode | Meaning |
|------|---------|
| `GHIDRA_AVAILABLE` | live Ghidra headless was run (`ASF_GHIDRA_DEEP_ENABLED=1` + a detected install) |
| `FIXTURE` | a clearly-marked offline Ghidra export was supplied (tests / reproducible acceptance) |
| `ELF_ONLY` | no Ghidra — binaries/functions/imports/exports/JNI/API-**present** still produced |

Capability is reported honestly by `app/native/ghidra_adapter.py::capability()`
(`READY` / `PARTIAL` / `UNAVAILABLE` / `ERROR`) and surfaced in `doctor`
(`native_deep READY`, `native_ghidra <state>`). When Ghidra is unavailable the
layer continues with ELF/JNI and simply never establishes native call-chain
reachability.

## Evidence, identity, provenance

Ghidra output is imported as **persisted evidence** with full provenance
(`source_type` ELF/GHIDRA/JNI, artifact, file, function, symbol, address,
`evidence_id`, confidence, timestamp) in `NativeDeepEvidence`. ELF and Ghidra
observations are reconciled by **stable content-derived identity** — binary
`sha256` + architecture + normalized name / entry — never by DB ids, Ghidra
temporary ids, or name similarity alone. A reconciled function carries
`source = ELF+GHIDRA`; Ghidra supplements, never silently replaces, ELF evidence.

Persisted tables (migration `0019_deep_native`): `native_analysis_runs`,
`native_binaries`, `native_deep_functions`, `native_deep_symbols`,
`native_strings`, `native_call_edges`, `native_references`,
`native_deep_jni_bindings`, `native_api_observations`, `native_deep_evidence`.

## JNI correlation (static + dynamic)

Each JNI binding is classified `STATIC_NAMING` (`Java_*`), `DYNAMIC_REGISTER`
(`RegisterNatives`), or `UNRESOLVED`, and its state is `RESOLVED` (matched to a
native function by content identity) or `UNKNOWN` (target preserved as
`UNKNOWN_NATIVE_TARGET`). Dynamic registrations that resolve to a native function
become valid reachability starts.

## Native API reachability (only Ghidra edges establish it)

API observations use explicit states: `NATIVE_API_PRESENT` (an API is imported /
present), `NATIVE_CALL_CHAIN_REACHES_API` (a Ghidra call chain from a **resolved
JNI entry** reaches the API). Without Ghidra call edges the target stays
`NATIVE_API_PRESENT` — reachability is **never fabricated**. `native_paths`
answers bounded `Java → JNI → native → API` queries and keeps
`UNKNOWN_NATIVE_TARGET` visible as a valid path boundary.

## Integrations (all guarded; supplement-only)

- **Native CVE signatures** — `native_cve_signatures` correlates provider
  `NATIVE_SYMBOL` / `JNI` signatures against native functions, states
  `MATCHED` / `PARTIAL_MATCH` / `UNRESOLVED_TARGET` / `NOT_MATCHED` / `UNKNOWN`.
  It **never** converts a signature match into `AFFECTED` or exploitability and
  never changes CVE state.
- **Validation** — adds claim types `NATIVE_TARGET_RESOLVED`,
  `JNI_BINDING_CONFIRMED`, `NATIVE_CALL_PATH_CONFIRMED`,
  `NATIVE_API_REACHABILITY_SUPPORTED`, `NATIVE_TARGET_UNRESOLVED`. Ghidra is one
  source family (`STATIC_NATIVE`), so it corroborates but never inflates to
  multi-source on its own; existing claims are unchanged.
- **Remediation** — recommendation-only `REVIEW_NATIVE_*` items
  (`NATIVE_DEEP_JNI` / `NATIVE_DEEP_API` target types) that never assert a
  vulnerable/exploitable native path.
- **Obfuscation** — an informational `native_deep_correlation` note only; it
  never changes the obfuscation score, any observation state, or any
  vulnerability state.
- **APK diff** — a `native_deep` category by stable fingerprints; removed =
  `NO_LONGER_DETECTED`; a new binary/function/symbol is not security-relevant;
  **only** a new `NATIVE_CALL_CHAIN_REACHES_API` path is `security_relevant`.
- **Knowledge graph** — `NATIVE_ANALYSIS` / `NATIVE_BINARY` /
  `NATIVE_FUNCTION_DEEP` / `NATIVE_API` / `JNI_BINDING_DEEP` nodes and
  `ANALYZED_BY` / `EXPORTS` / `IMPORTS` / `BINDS_TO` / `NATIVE_CALLS` /
  `REACHES_NATIVE_API` / `SUPPORTED_BY` edges with `GHIDRA` provenance —
  **opt-in** (`include_native_deep=True`), node ids namespaced with fingerprints.
  Graph snapshots stay byte-identical by default (APK-diff snapshot integrity).

## Orchestrator & determinism

A status-safe `native_deep` stage runs after obfuscation; it is status-exempt
(never fails the analysis — ELF-only ⇒ `PARTIAL`, no libraries ⇒ `UNAVAILABLE`),
idempotent (collections cleared and rebuilt — no duplicate logical observations),
and never mutates other layers. The run fingerprint is
`sha256` over sorted content fingerprints of binaries/functions/call-edges/JNI/API
— DB ids and timestamps never participate, so the same native content yields the
same fingerprint across analyses.

## CLI / REST / report

```
androidsecforge native-deep doctor
androidsecforge native-deep analyze <analysis-id>
androidsecforge native-deep summary|binaries|functions|symbols|imports|exports|jni|calls|sinks|evidence|cve <analysis-id> [--json]
androidsecforge native-deep paths <analysis-id> --from <q> [--to <q>] [--max-depth N] [--json]
androidsecforge native-deep explain <analysis-id> <target> [--json]
androidsecforge native-deep export <analysis-id> --format json|markdown
```

REST: `GET /api/v1/analysis/{id}/native[/binaries|/functions|/jni|/calls]`,
`GET /api/v1/analysis/{id}/native/paths?from_query=&to_query=`,
`GET /api/v1/analysis/{id}/native/explain/{target}`,
`GET /api/v1/diff/{id}/native`. The JSON report gains a `native_deep_analysis`
section; Markdown via `native-deep export --format markdown`.

## Performance

Single pass over persisted ELF native functions + a bounded Ghidra export;
dictionary indexes for identity/reconciliation; bounded native call-graph BFS;
reuse of the persisted graph — no N×M scans and no Java-graph recomputation.
Bounds: `ASF_NATIVE_MAX_BINARIES`, `ASF_NATIVE_MAX_FUNCTIONS_PER_BINARY`,
`ASF_NATIVE_MAX_SYMBOLS`, `ASF_NATIVE_MAX_STRINGS`, `ASF_NATIVE_MAX_CALL_EDGES`,
`ASF_NATIVE_MAX_JNI_BINDINGS`, `ASF_NATIVE_MAX_PATH_RESULTS`,
`ASF_NATIVE_PATH_MAX_DEPTH`, `ASF_NATIVE_ANALYSIS_TIMEOUT_SECONDS`,
`ASF_NATIVE_MAX_OUTPUT_BYTES`.

## Real acceptance (Magisk v29.0, Ghidra unavailable)

`analyze_apk` on Magisk v29.0 (24 `.so`) yields `mode=ELF_ONLY`,
`ghidra=UNAVAILABLE`, 24 binaries, 1242 native functions, 119
`NATIVE_API_PRESENT` observations, **0** call edges and **0**
`NATIVE_CALL_CHAIN_REACHES_API` (honest — no Ghidra call graph, and Magisk has no
`Java_*` JNI entry points). A clearly-marked `FIXTURE` Ghidra export over one real
binary (`libmagiskboot.so`) then demonstrates the full pipeline: a resolved
`RegisterNatives` binding + call chain makes `Native.boot → Java_..._boot →
strcpy` `REACHABLE` and marks `strcpy` `NATIVE_CALL_CHAIN_REACHES_API`.

# Testing

```bash
make test          # or: /usr/bin/python -m pytest -q
```

Tests live in `backend/tests/` and require no external tools or physical devices — JADX is
mocked, and the test APK is generated in-process.

## Coverage

| Area | File |
| --- | --- |
| AXML encode/decode, attributes, malformed input | `test_axml.py` |
| Manifest normalization, exposure states, permission classification | `test_manifest.py` |
| Rule engine (positive/negative per rule, masking, require_all) | `test_rules.py` |
| Code indexer (classes/methods/fields) | `test_code_index.py` |
| JADX adapter (available/unavailable/timeout/failed, mocked) | `test_jadx.py` |
| Real JADX executable (live, capability-gated) | `test_jadx_integration.py` |
| ELF parsing (header/arch/symbols/NEEDED/stripped) | `test_elf.py` |
| JNI demangling + Java-side detection + bindings | `test_jni.py` |
| Native discovery + per-library failure isolation | `test_native.py` |
| Native rule engine (imported-symbol indicators) | `test_native_rules.py` |
| Ghidra adapter (unavailable/failure/timeout/success) | `test_ghidra.py` |
| Native pipeline persistence + Ghidra optional | `test_orchestrator_native.py` |
| Reachability engine (call graph, sources/sinks, 5 cases, confidence, bounded) | `test_reachability.py` |
| Reachability persistence (graph/paths, mocked-JADX finding) | `test_orchestrator_reachability.py` |
| Android semantics engine (9 cases, detectors, confidence) | `test_semantics.py` |
| Semantics persistence (entry points/boundaries/deep links, mocked-JADX findings) | `test_orchestrator_semantics.py` |
| Version-range engine (numeric, prerelease, ranges, UNKNOWN) | `test_versions.py` |
| Dependency inventory (Java fingerprints, native bundled/system) | `test_dependencies.py` |
| CVE matching + reachability correlation + false-positive control | `test_cve.py` |
| CVE pipeline persistence (offline empty DB, fixtures + mocked JADX) | `test_orchestrator_cve.py` |
| Correlation, root causes, dedup, path summary, negative cases | `test_correlation.py` |
| End-to-end scenarios A–J (webview/dynload/JNI/perm-protected/risk) | `test_orchestrator_correlation.py` |
| Runtime Lab (mock ADB/Frida: lifecycle, masking, correlation, offline) | `test_runtime.py` |
| Knowledge graph (projection, node identity, edge fingerprints, provenance, snapshot determinism, queries, path uncertainty, UNKNOWN/POSSIBLY_AFFECTED/LOW preservation, exports, cross-analysis isolation) | `test_knowledge_graph.py` |
| Investigation workspace (lifecycle, findings, hypothesis lifecycle, notes, bookmarks, timeline, path pinning, exports, integrity: hypotheses/notes never alter findings) | `test_investigation.py` |
| Obfuscation & anti-analysis (17 cases: descriptive vs shortened identifiers, encoded strings, constant/external reflection + dynamic-load, control-flow threshold, single vs multiple anti-analysis indicators, stripped native, UNKNOWN_NATIVE_TARGET/UNKNOWN preserved, CVE-state non-mutation, A→A zero-change, new-anti-analysis diff, disconnected source/sink, determinism, read-only, no-exploitable) | `test_obfuscation.py`, `test_orchestrator_obfuscation.py` |
| Deep native / Ghidra correlation (26 cases: capability honesty, ELF-only mode, ELF↔Ghidra identity reconciliation, JNI static-naming/RegisterNatives-dynamic/unresolved (UNKNOWN_NATIVE_TARGET preserved), Ghidra call-graph import, native-API PRESENT vs REACHED, reachability never fabricated without call edges, dynamic-register resolves-and-reaches, native CVE signatures never AFFECTED/exploitable, path uncertainty boundaries, explain state distinctions, bounded FIXTURE parser, determinism (DB-id-independent fingerprint) + idempotency, validation/remediation/obfuscation non-mutation, opt-in KG projection snapshot-safe, diff new-reachable-API security-relevant, report/markdown, real Magisk ELF evidence) | `test_native_deep.py`, `test_orchestrator_native_deep.py` |
| Live runtime validation & behavioral corroboration (25 cases: LIVE confirms / MOCKED never confirms / LIVE_UNAVAILABLE≠safe / ran-live-not-observed=NOT_OBSERVED, device-unavailable→LIVE_RUNTIME_UNAVAILABLE, validate lifecycle stays MOCKED, static-method / JNI / native-API correlation, native reachability never fabricated, observation taxonomy, artifact redaction+SHA-256, TRUNCATED recorded not silent, validation runtime claims (LIVE=RUNTIME_CORROBORATED, MOCKED never), no-mutation-of-static-truth, opt-in KG projection snapshot byte-identical, remediation runtime factor never REMEDIATED, runtime-behavior diff + NEWLY_OBSERVED + RUNTIME_OBSERVATION_UNAVAILABLE, deterministic DB-id-free fingerprint + idempotency, cross-analysis isolation, evidence-chain provenance, investigation pin + CORRELATION/LIVE_OBSERVATION timeline, report no-exploitable) | `test_runtime_validation.py` (mock ADB/Frida adapters — MOCKED stays MOCKED) |
| UI REST additions (bounded `/analyses` list clamp + read-only; findings serializer additive id/runtime axes + explain reachable + never mutated) | `test_api_ui_endpoints.py` |
| Real-device runtime discovery (12 cases: device-state classification CONNECTED/UNAUTHORIZED/OFFLINE/NOT_CONNECTED/ADB_UNAVAILABLE, frida-server never inferred from host, native READY only with server, unauthorized leaks no metadata, component-line parsing, LIVE ADB observation scoped to package + source=ADB + taxonomy, LIVE-never-MOCKED, redaction + bounds/TRUNCATED, runtime never overwrites static truth, artifact SHA-256 + redaction) | `test_runtime_device.py` (mock ADB/Frida — no physical device required) |
| Security assessment & decision intelligence (15 cases: no exploitable / no SAFE-UNSAFE, finding conclusion states CONFIRMED/SUPPORTED/BLOCKED, runtime-confirmed finding STRONGLY_SUPPORTED, CVE POSSIBLY_AFFECTED≠AFFECTED + MISSING_VERSION blocker + AFFECTED-reachable disclaims exploitability, runtime LIVE corroborated vs MOCKED-never-corroborated vs UNAVAILABLE≠NOT_OBSERVED, native ELF_ONLY unavailable + UNKNOWN_NATIVE_TARGET blocker preserved, never REMEDIATED from runtime, runtime never overwrites static truth, conclusions reference existing evidence not duplicates, deterministic + idempotent fingerprint, overall INCONCLUSIVE + SECURITY_REVIEW_REQUIRED, explain chain provenance, conservative diff NO_LONGER_PRESENT≠FIXED, cross-analysis isolation) | `test_assessment.py` |
| **Frontend** (39 vitest cases): security-semantics non-collapse (MOCKED≠LIVE, UNKNOWN≠SAFE, POSSIBLY_AFFECTED≠AFFECTED, NO_LONGER_DETECTED≠FIXED, PRESENT≠REACHED, indicator≠behavior, unknown-verbatim); API client loading/success/**empty**/404/400/500/network; StatusBadge/ModeBadge + EvidenceItem UNKNOWN preservation; DataTable deterministic sort + empty; ResultGate honest states; GraphView bounded + TRUNCATED + node-select + UNKNOWN-edge-dashed; Findings filters + MOCKED-vs-LIVE per row + drawer/no-exploitable; researcher-input-never-mutates-truth | `frontend/src/test/*.test.ts(x)` — run `npm run test` (offline, API mocked) |
| Security validation (24 cases: static/multi-source/blocked/unverified states, evidence-family independence, LIVE vs MOCKED runtime, UNKNOWN_NATIVE_TARGET/IPC-target preservation, CVE version validation, POSSIBLY_AFFECTED never AFFECTED, remediation validation, diff transitions, hypothesis non-interference, deterministic fingerprints, idempotent persistence, opt-in KG projection, snapshot-safe) | `test_validation.py`, `test_orchestrator_validation.py` |
| Remediation planning (18 required cases + persistence/integrity/explain/no-exploitable + end-to-end orchestrator + KG opt-in projection) | `test_remediation.py`, `test_orchestrator_remediation.py` |
| Vulnerability intelligence (23 cases: NVD/OSV import, provider conflict, aliases, CPE/PURL/Maven/SONAME normalization, version ranges, fixed versions, code/native signatures, UNKNOWN/POSSIBLY_AFFECTED, reachable/non-reachable CVE, KEV/EPSS separate axis, freshness/stale, bundle checksum failure + corrupted bundle, KG intel projection + determinism, diff CVE transitions, cross-analysis isolation) | `test_intel.py` |
| APK diff (28 cases: identical→NO_CHANGE, per-category adds/removes/changes, CVE transitions preserving state, finding NO_LONGER_DETECTED, risk delta, security regression/improvement/inconclusive, UNKNOWN/UNKNOWN_NATIVE_TARGET preserved, snapshot-mismatch rejected, deterministic fingerprint + repeated comparison, direction matters, provenance preserved, attack-surface/reachability delta, bounded truncation, graph-delta export, no cross-analysis mutation) | `test_diff.py` |
| Orchestrator (complete/partial, persistence, failure recovery) | `test_orchestrator.py` |
| CLI (`analyze`, `findings`, `--json`, reproducibility) | `test_cli.py` |
| Ingestion, legacy manifest/framework/DEX | `test_apk_ingestion.py` |
| REST API routes | `test_api.py` |

## Test APK

`AndroidSecForge-TestApp` is built by `backend/app/testapp/builder.py`
(`make test-apk` → `analysis/test-apks/AndroidSecForge-TestApp.apk`). It has a real binary
AXML manifest and deterministic fixtures: debuggable/backup/cleartext flags, exported
activity/service/provider, an implicitly-exported receiver, a deep link, dangerous and
custom permissions, and two DEX files. It contains no real credentials and contacts nothing.

## Fixtures

Shared fixtures are in `conftest.py`: `db_session` (in-memory relational DB),
`isolated_storage` (tmp artifact/workspace paths), `no_jadx` (force JADX unavailable for
deterministic results), `test_apk`, `native_so`, `native_apk`, and `make_analysis` (a
factory that builds a realistic, fully-populated `Analysis` directly from models — no
JADX/device needed — for knowledge-graph + investigation tests).

## Native fixture (compiler-gated)

`backend/app/testapp/native_fixture.c` is compiled at test time by
`compile_native_fixture()` into a real shared object (JNI_OnLoad, one `Java_*`
export, a normal export, imported libc functions, and one deliberately unsafe
`strcpy`). Tests that need it (`test_elf.py`, `test_native.py`,
`test_orchestrator_native.py`, the native CLI test) **skip cleanly when no host C
compiler (`cc`/`gcc`/`clang`) is available** — ELF output is never fabricated.

## Determinism

Results do not depend on the host toolchain: `no_jadx` forces the JADX-absent path, and a
separate test mocks a JADX success to exercise the code-index and code-rule path.

## Live JADX integration tests

`test_jadx_integration.py` invokes the real `jadx` binary (never mocked). It skips unless
both JADX is discoverable and a real APK is provided:

```bash
ASF_JADX_PATH="$HOME/tools/jadx/bin/jadx" \
ASF_TEST_APK=/path/to/real.apk \
make test
```

Without those it skips, so the default suite stays portable and independent of JADX.

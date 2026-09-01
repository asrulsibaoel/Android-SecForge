# AndroidSecForge

**A modular Android security research & assessment framework.** It takes a real APK
end-to-end through a normalized, relational analysis model — static, native, CVE,
runtime, graph, and decision intelligence — where every external tool is an
*optional capability* that degrades honestly when absent, and every result is
evidence-backed and explainable.

### Design principles

- **Graceful degradation** — the pipeline always runs; a missing tool narrows scope, it never fakes a result. An *unavailable capability is never a successful stage*, and a *failed analysis is never "no findings"*.
- **No exploitability, ever** — nothing is labelled `exploitable`; results never collapse to SAFE/UNSAFE.
- **States stay distinct** — `UNKNOWN` ≠ NOT_FOUND, `NOT_OBSERVED`/`NOT_REACHABLE` ≠ safe, `POSSIBLY_AFFECTED` ≠ AFFECTED, `MOCKED` ≠ LIVE, `NATIVE_API_PRESENT` ≠ reachable, an indicator ≠ confirmed behavior.
- **One source of truth** — the backend/DB is authoritative; the Web UI is a presentation layer that stores no analytical truth and duplicates no logic.
- **Deterministic & explainable** — content-derived fingerprints, documented scoring factors (severity, risk, priority, confidence as *separate* axes), and a "why" behind every finding, claim, and conclusion.

---

## Analysis pipeline

```mermaid
flowchart TB
    APK["APK / AAB / APKS / APKM"] --> ING["Ingest + SHA-256 · dedup · immutable"]

    subgraph STATIC["Static analysis"]
        ING --> MAN["Manifest · permissions · components"]
        ING --> DEX["DEX extraction"]
        DEX -.->|jadx| CODE["Code index + Java call graph"]
        ING --> NAT["Native ELF + JNI discovery"]
        NAT -.->|Ghidra deep| DEEP["Native call-chain + JNI reachability"]
    end

    subgraph REASON["Findings & intelligence"]
        RULES["Rule engine → findings"] --> RS["Reachability · Android semantics"]
        RS --> CO["Correlation · root causes · attack surface"]
        CO --> RK["CVE intelligence · explainable risk"]
        RK --> AS["Validation · remediation · obfuscation · assessment"]
    end

    MAN --> RULES
    CODE --> RULES
    NAT --> RULES

    CODE --> KG["Knowledge-graph projection + snapshot"]
    DEEP --> KG

    AS --> DB[("Relational DB")]
    KG --> DB
    DB --> CLI["CLI"]
    DB --> REST["REST API"]
    REST --> UI["React Web UI"]

    DEVICE["Device · adb / Frida"] -.->|LIVE runtime| RS
```

> Dotted edges need an optional capability — **jadx** (Java decompilation), **Ghidra deep**
> (native call-chain), or a **live device** via adb/Frida. When one is absent the pipeline
> continues and reports that capability's state honestly (`UNAVAILABLE` / `PARTIAL`), never
> a fabricated success.

---

## Features covered

### Static analysis
| Feature | What it does |
| --- | --- |
| **Ingestion** | `.apk` / `.aab` / `.apks` / `.apkm` with SHA-256/1/MD5 fingerprints and a hash-derived workspace; the original file is never modified; deduped by content hash. |
| **Binary AXML decoding** | Self-contained parser (no external tool) for the string pool, namespaces, elements, and typed attributes; plain-XML bundles too. |
| **Manifest normalization** | Typed relational model — package, versions, SDKs, flags, permissions, components. |
| **Attack-surface / components** | Android exposure semantics: `INTERNAL` / `EXPORTED` / `CONDITIONALLY_EXPORTED` / `UNKNOWN` (not a naïve `exported=true`). |
| **Permission intelligence** | Protection-level classification (`NORMAL`/`DANGEROUS`/`SIGNATURE`/`UNKNOWN`) from an embedded dataset. |
| **DEX extraction** | Every `classes*.dex` hashed with header-derived class/method/field/string counts. |
| **JADX integration** *(optional)* | Real subprocess decompilation with honest `SUCCESS`/`TIMEOUT`/`FAILED`/`UNAVAILABLE`; feeds the code index. |
| **Code index** | Packages, classes (superclass/interfaces), methods, and fields from decompiled sources. |
| **Rule engine** | JSON-defined rules (id/severity/confidence/refs); code rules require pattern co-occurrence, so a bare API name is never a finding; secrets masked. |
| **Dataflow & reachability** | Conservative Java call graph, source/sink/entry models, bounded path search → `REACHABLE`/`NOT_REACHABLE`/`UNKNOWN`; a source and sink merely coexisting is never a finding. |
| **Android semantics** | Lifecycle dispatch, intents, deep links, IPC/Binder, ContentProvider inputs, WebView JS bridges, reflection, dynamic loading, storage/crypto/network, and explicit security boundaries. |

### Native analysis
| Feature | What it does |
| --- | --- |
| **ELF + JNI** | Self-contained ELF parser (no `pyelftools`) over `lib/**/*.so` — arch/SONAME/NEEDED/exported+imported symbols (stripped-safe), Java↔JNI↔ELF relationship, dangerous imported C APIs as *indicators*. |
| **Deep native / Ghidra correlation** *(optional)* | Correlates persisted native evidence with Ghidra static analysis by content-derived identity; classifies JNI registration (`STATIC_NAMING`/`DYNAMIC_REGISTER`/`UNRESOLVED`), imports the native call graph, and distinguishes `NATIVE_API_PRESENT` vs `NATIVE_CALL_CHAIN_REACHES_API` (reachability only from a resolved JNI entry — never fabricated). ELF-only mode is fully functional. |

### Vulnerability & threat intelligence
| Feature | What it does |
| --- | --- |
| **Dependency & CVE** | Unified Java + native dependency inventory matched against an **offline-first**, provider-neutral CVE database with a numeric version-range engine; version and reachability tracked separately; never a CVE from a name match alone. |
| **Multi-provider intel** | Import adapters for NVD / OSV / GHSA / test data (failures isolated, NVD never mandatory), CPE/PURL/Maven/SONAME identity normalization, provider conflict resolution, KEV/EPSS on a separate axis, checksum-validated offline bundles, and freshness tracking. |

### Reasoning, scoring & decisions
| Feature | What it does |
| --- | --- |
| **Correlation & root causes** | Deterministic finding dedup (stable fingerprints), shared-evidence correlation, aggregated root causes. |
| **Explainable risk** | Documented factor weights + mitigations; severity, risk, confidence as separate axes; ranks entry points, never claims exploitability. |
| **Security validation** | What can be VERIFIED from static evidence, CORROBORATED by live runtime, or remains UNVERIFIED — counting *independent evidence families*, with explicit blockers and a "why" engine. Mock stays MOCKED. |
| **Remediation intelligence** | Evidence-backed *recommendations* (never auto-patches): `UPDATE_DEPENDENCY` with a fixed version, `VERIFY_DEPENDENCY_VERSION` when unknown, review actions for components/IPC/JNI/TLS/crypto; documented priority + fixability. |
| **Obfuscation & anti-analysis** | Identifier/string/control-flow obfuscation and debugger/emulator/root/Frida indicators, with an *analysis-complexity* score (a separate axis) and explicit analytical impact. Obfuscation never implies vulnerability. |
| **Assessment & decision intelligence** | Synthesizes every layer into auditable decision states (`CONFIRMED`…`REQUIRES_REVIEW`…`BLOCKED`…`SUPERSEDED`) via inspectable `rule_id` + rationale + evidence references. No ML, no hidden weights, never "exploitable", never SAFE/UNSAFE. |

### Runtime (optional, explicit, safe)
| Feature | What it does |
| --- | --- |
| **Runtime Lab** | Real ADB adapter (safe subprocess, no `shell=True`) for discovery/install/launch/logcat/process, and an **observation-only** Frida adapter (call original, return unchanged). Nothing auto-runs; every step is user-invoked and audited. |
| **Live runtime validation** | Runs an APK on a real device/emulator and correlates a 17-type observation taxonomy against the static model — LIVE and MOCKED never conflated; `NOT_OBSERVED` never means safe; runtime never overwrites static truth. |
| **Device capability discovery** | Read-only `CONNECTED`/`UNAUTHORIZED`/`OFFLINE`/`NOT_CONNECTED` + frida-server checked *on the device* (never inferred from host Frida). |

### Graph, comparison & workspace
| Feature | What it does |
| --- | --- |
| **Knowledge graph** | Evidence-centric *projection* over the canonical code graph (no second graph) with provenance on every edge and a deterministic snapshot hash; safe named-query registry + bounded path investigation. |
| **Investigation workspace** | Pin nodes/paths, attach findings, take notes, record hypotheses (`OPEN`/`SUPPORTED`/`REFUTED`/`UNKNOWN`) that never alter machine findings; JSON/GraphML/DOT/Markdown export. |
| **Comparative diff (A→B)** | Direction-sensitive, snapshot-verified diff by stable identity (never line numbers); a disappeared finding is `NO_LONGER_DETECTED` (not "fixed"); conservative `SECURITY_REGRESSION`/`IMPROVEMENT`/`MIXED`/`INCONCLUSIVE` verdict. |

### Interfaces
| Feature | What it does |
| --- | --- |
| **CLI** | `androidsecforge …` — analyze, inspect, and every intelligence layer, with `--json`. |
| **REST API** | Read-only reports plus web intake (`/api/v1/apk`, `/api/v1/analyses`, execution progress) — see [web-intake](docs/web-intake.md). |
| **React Web UI** | Presentation layer over the API: dashboard, per-analysis workspace (findings, attack surface, graph, CVE, remediation, validation, runtime, native, obfuscation, diff, assessment, evidence), APK upload + real progress, and a self-authored bounded SVG graph. Never a second source of truth. |
| **Persistence** | Relational model (SQLite by default, PostgreSQL via Docker/Alembic). |

---

## Screenshots

> Images live in [`docs/screenshots/`](docs/screenshots/) — drop your PNG captures there using the filenames below and they render automatically (see that folder's [README](docs/screenshots/README.md)).

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/dashboard.png" alt="Dashboard"><br><sub><b>Dashboard</b> — recent analyses + honest capability chips</sub></td>
    <td width="50%"><img src="docs/screenshots/new-analysis.png" alt="New Analysis"><br><sub><b>New Analysis</b> — drag-and-drop APK upload</sub></td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/progress.png" alt="Progress"><br><sub><b>Progress</b> — live per-stage pipeline</sub></td>
    <td><img src="docs/screenshots/findings.png" alt="Findings"><br><sub><b>Findings</b> — per-analysis workspace</sub></td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/knowledge-graph.png" alt="Knowledge Graph"><br><sub><b>Knowledge Graph</b> — bounded evidence graph</sub></td>
    <td><img src="docs/screenshots/assessment.png" alt="Assessment"><br><sub><b>Assessment</b> — decision-intelligence conclusions</sub></td>
  </tr>
</table>

---

## Installation & prerequisites

Full guide: **[docs/installation.md](docs/installation.md)**. At a glance:

- **Required (core):** Python **3.12+** and pip. That runs the whole static pipeline + REST API.
- **Required for the Web UI:** Node.js **18+** (20 LTS+ recommended) — for the React workspace in `frontend/`.
- **Nice to have (optional analyzers, each adds depth; the pipeline degrades honestly without them):**
  - **Java (JDK 21+)** — prerequisite for jadx and Ghidra.
  - **jadx** → DEX→Java decompilation, code graph, reachability, semantics (`ASF_JADX_PATH`).
  - **Ghidra** → deep native call-chain / JNI reachability (`ASF_GHIDRA_PATH` + `ASF_GHIDRA_DEEP_ENABLED=true`).
  - **adb** (platform-tools) → live runtime validation on a device/emulator.
  - **Frida** (host + frida-server on a rooted device) → live native/JNI instrumentation.
- **Not required:** apktool — not used (binary AXML is parsed in-process).

Run `androidsecforge doctor` any time to see exactly what is detected.

## Run locally

```bash
python -m pip install -e '.[test]'
androidsecforge doctor                 # detect optional external tools
make test-apk                          # build analysis/test-apks/AndroidSecForge-TestApp.apk
androidsecforge analyze analysis/test-apks/AndroidSecForge-TestApp.apk
androidsecforge analyze ./real.apk --json > report.json
```

`analyze` prints an `analysis_id`, per-stage status, capability states, and findings. Result is `PARTIAL` when an optional analyzer (e.g. JADX) is unavailable, `COMPLETE` when every stage succeeds, and `FAILED` only on a fundamental failure. Other commands:

```bash
androidsecforge analysis show <analysis-id> [--json]
androidsecforge findings <analysis-id> [--json]
androidsecforge dex inspect <analysis-id> [--json]
```

Set `ASF_DATABASE_URL`, `ASF_ARTIFACT_STORAGE_PATH`, `ASF_WORKSPACE_PATH`, and `ASF_JADX_PATH` to configure storage and tools.

## Web service

```bash
androidsecforge serve   # http://127.0.0.1:8000
```

`/health`, `/docs`, artifact endpoints under `/api/v1/apk`, and analysis reports under `/api/v1/analysis/{id}`.

## Web UI

The React investigation workspace lives in `frontend/` and is a presentation layer over the REST API (needs Node 18+):

```bash
cd frontend
npm install
npm run dev             # http://127.0.0.1:5173  (proxies /api -> :8000)
```

Start the backend (`androidsecforge serve`) first. From the browser you can upload an APK, create an analysis, and watch real per-stage progress — see [docs/web-intake.md](docs/web-intake.md).

## PostgreSQL

```bash
docker compose up -d postgres
ASF_DATABASE_URL=postgresql+psycopg://androidsecforge:androidsecforge@localhost:5432/androidsecforge make migrate
```

## Documentation

See `docs/`: [installation](docs/installation.md), [toolchain](docs/toolchain.md), [apk-analysis](docs/apk-analysis.md), [axml](docs/axml.md), [jadx](docs/jadx.md), [native](docs/native.md), [jni](docs/jni.md), [ghidra](docs/ghidra.md), [reachability](docs/reachability.md), [semantics](docs/semantics.md), [cve](docs/cve.md), [correlation](docs/correlation.md), [root-causes](docs/root-causes.md), [attack-surface](docs/attack-surface.md), [risk-engine](docs/risk-engine.md), [graph-export](docs/graph-export.md), [runtime](docs/runtime.md), [adb](docs/adb.md), [frida](docs/frida.md), [runtime-correlation](docs/runtime-correlation.md), [runtime-safety](docs/runtime-safety.md), [knowledge-graph](docs/knowledge-graph.md), [investigation](docs/investigation.md), [provenance](docs/provenance.md), [graph-queries](docs/graph-queries.md), [investigation-export](docs/investigation-export.md), [graph-integrity](docs/graph-integrity.md), [apk-diff](docs/apk-diff.md), [vulnerability-intelligence](docs/vulnerability-intelligence.md), [remediation](docs/remediation.md), [remediation-priority](docs/remediation-priority.md), [remediation-evidence](docs/remediation-evidence.md), [security-validation](docs/security-validation.md), [obfuscation](docs/obfuscation.md), [deep-native](docs/deep-native.md), [runtime-validation](docs/runtime-validation.md), [assessment](docs/assessment.md), [web-intake](docs/web-intake.md), [frontend](docs/frontend.md), [ui-architecture](docs/ui-architecture.md), [ui-security-semantics](docs/ui-security-semantics.md), [ui-graph](docs/ui-graph.md), [ui-investigation](docs/ui-investigation.md), [ui-testing](docs/ui-testing.md), [rules](docs/rules.md), [findings](docs/findings.md), [testing](docs/testing.md).

## Safety

The default authorization mode is `SAFE`. Dynamic instrumentation and active validation will require an explicit `LAB` or `AUTHORIZED_ASSESSMENT` mode. APKs are treated as untrusted input: subprocess argument arrays (never `shell=True`), timeouts, and size limits. The framework does not implement indiscriminate scanning, credential theft, persistence, propagation, or autonomous exploitation.

## License

Licensed under the **Apache License 2.0** — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

```
Copyright 2026 The AndroidSecForge authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

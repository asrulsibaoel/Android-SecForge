# Provenance

Every knowledge-graph node and edge that represents analytical knowledge is
traceable to the evidence that produced it. Provenance is attached during
projection (`app/analysis/knowledge_graph.py`) and never claims stronger origin
than actually exists.

## Provenance record

Each `Provenance` entry carries:

- `source_type` — one of the sources below
- `source_artifact` — the artifact it came from (APK sha, `.so` path, CVE id, …)
- `file_path` — decompiled source path where available
- `source_line` — line where available
- `location` — class / method / component where available
- `evidence_id` — the persisted `evidence` row id where applicable
- `confidence` — carried from the underlying entity (never upgraded)
- `timestamp` — analysis or runtime timestamp where applicable

Fields that are not genuinely known are left `null` — provenance is never padded
with invented file paths or line numbers.

## Source types

| Source | Meaning |
| --- | --- |
| `MANIFEST` | binary/plain `AndroidManifest.xml` |
| `DEX` | DEX inventory / APK identity |
| `JADX` | JADX-decompiled Java |
| `SMALI` | smali (when apktool used) |
| `ELF` | native ELF parsing |
| `JNI` | Java↔native binding discovery |
| `GHIDRA` | optional native decompilation |
| `STATIC_RULE` | data-driven rule engine / correlation |
| `REACHABILITY` | dataflow / reachability engine |
| `SEMANTICS` | Android execution-semantics pass |
| `CVE_DATABASE` | local offline CVE database |
| `RUNTIME_ADB` | ADB-observed runtime facts |
| `RUNTIME_FRIDA` | Frida observation-only instrumentation |
| `USER_NOTE` | researcher annotation (clearly machine-distinct) |

## How provenance is assigned

- **Nodes** take the source of the entity they project: a component →
  `MANIFEST`, a decompiled method → `JADX`, a native function → `ELF`, a CVE
  match → `CVE_DATABASE`, a runtime observation → `RUNTIME_FRIDA`/`RUNTIME_ADB`.
- **Evidence** nodes carry the persisted `evidence.source` mapped to a provenance
  source, plus the evidence row id.
- **Edges** take a provenance source derived from the edge type
  (`CALLS`→`JADX`, `FLOWS_TO`→`REACHABILITY`, `WEBVIEW_BRIDGE`→`SEMANTICS`,
  `MATCHES_CVE`→`CVE_DATABASE`, `RUNTIME_OBSERVED`→`RUNTIME_FRIDA`), and record
  the underlying evidence text in `evidence_refs`.

Researcher notes and hypotheses are the only `USER_NOTE`-sourced content and are
always presented as annotations, never as machine evidence.

# Dependency & CVE intelligence

AndroidSecForge correlates a unified dependency inventory against a local CVE
database and folds in the existing reachability engine. It is **offline-first**:
analysis reads the local database and never requires network access; a name match
is never sufficient to declare a vulnerability.

## Core principle — states, not verdicts

Identity, version, and reachability confidence are tracked separately:

- **version match**: `AFFECTED` / `NOT_AFFECTED` / `POSSIBLY_AFFECTED` / `UNKNOWN`
- **correlation state machine**: `NOT_PRESENT` → `PRESENT_UNKNOWN_VERSION` /
  `PRESENT_NOT_AFFECTED` / `PRESENT_AFFECTED` → `AFFECTED_REACHABLE` /
  `AFFECTED_NOT_REACHABLE`, plus `UNKNOWN`.

`UNKNOWN` is never downgraded to `NOT_AFFECTED`, and `VALIDATED` is intentionally
not a state in this milestone (there is no runtime validation yet).

## Dependency inventory

- **Java**: package namespaces are fingerprinted against a curated signature set
  (`app/analysis/fingerprints.py`). Versions come **only** from embedded metadata
  (`META-INF/**/pom.properties`, `*.version`) — never inferred from a prefix.
- **Native**: bundled `lib/<abi>/*.so`, SONAME, and `DT_NEEDED` from the existing
  ELF analysis, classified as **bundled** / **application** / **system** (platform
  libraries like `libc.so` are not treated as bundled vulns). Versions are taken
  from a SONAME/filename suffix when present.

Identity confidence and version confidence are separate columns; versions are
never invented.

## Version engine

`app/analysis/versions.py` compares versions numerically (so `1.10.0 > 1.9.0`),
handles pre-release ordering, and supports inclusive/exclusive/open-ended ranges
and exact versions with SEMVER/MAVEN/ANDROID/GENERIC strategies. If a comparison
cannot be made reliably it returns `UNKNOWN`.

## CVE database (provider-neutral, offline)

Tables `vulnerabilities`, `vulnerability_references`, `affected_products`,
`affected_version_ranges` form an analysis-independent local DB. Populate it with:

```bash
androidsecforge cve import <nvd-or-normalized.json>   # offline import
androidsecforge cve import-fixtures                   # deterministic TEST_DATA
androidsecforge cve sync [--keyword okhttp]           # NVD, best-effort/optional
androidsecforge cve search <query> [--json]
androidsecforge cve show <CVE-ID> [--json]
```

`sync` (NVD) is separate from analysis and fails gracefully offline. Test
fixtures are clearly flagged `TEST_DATA` and never mixed with production data.

## Matching + reachability correlation

```bash
androidsecforge dependency list <analysis-id> [--json]
androidsecforge dependency inspect <analysis-id> [--json]
androidsecforge cve analyze <analysis-id> [--json]   # (re-)correlate, offline
```

Matching is batch-indexed by normalized identity (product / package / CPE), then
version-filtered, then reachability-correlated. For an `AFFECTED` dependency, the
engine checks whether the vulnerable package's classes are reachable from an
entry point/source in the existing code graph (`AFFECTED_REACHABLE` /
`AFFECTED_NOT_REACHABLE`); native reachability requires a proven JNI boundary and
is otherwise `UNKNOWN` (no native call graph is fabricated without Ghidra).

## Findings

- `ANDROID-CVE-001` vulnerable dependency detected (affected; reachability unknown)
- `ANDROID-CVE-002` dependency affected but version uncertain (possibly-affected)
- `ANDROID-CVE-003` affected dependency with reachable vulnerable code
- `ANDROID-CVE-004` vulnerability present but vulnerable code not reachable

Severity is evidence-based and never automatically CRITICAL. Every finding
carries dependency, CVE, affected range, match method, version state, and
reachability evidence. The JSON report adds `dependencies`,
`vulnerability_matches`, `vulnerability_findings`, and `cve_metadata`.

# Installation

AndroidSecForge runs on any Linux/macOS/WSL machine. External analysis tools are
**optional capabilities**: the pipeline always runs and reports honestly, and each
missing tool narrows scope rather than breaking the run (an unavailable capability
is never reported as a successful stage, and a failed analysis is never reported as
"no findings"). Install the core, then add whichever optional tools you need.

---

## 1. Prerequisites

### Required (core backend)

| Requirement | Version | Notes |
| --- | --- | --- |
| **Python** | **3.12+** | Developed/tested on 3.14. |
| **pip** / venv | recent | On externally-managed Pythons (Kali/Debian, PEP 668) use a venv — see §2. |

That is enough to ingest APKs and run the full **static** pipeline (manifest,
permissions, components, DEX, native ELF/JNI, rules, graph, reachability, CVE,
risk, assessment) and the REST API.

### Required only for the Web UI

| Requirement | Version | Notes |
| --- | --- | --- |
| **Node.js** | **18+** (20 LTS+ recommended) | Needed to build/run the React workspace in `frontend/`. |
| **npm** | ships with Node | |

The CLI and REST API work without Node; Node is only for the browser workspace.

### Nice to have (optional analyzers — each unlocks more depth)

| Tool | Unlocks | Without it you get | Install |
| --- | --- | --- | --- |
| **Java (JDK)** — **21+** | Prerequisite **for jadx and Ghidra** | jadx/Ghidra can't run | `apt install openjdk-21-jdk` (or any JDK 21+). jadx needs Java 11+; Ghidra 12 needs JDK 21+. |
| **jadx** | DEX→Java decompilation → code index, Java code graph, reachability, semantics, Java-level findings (TLS/crypto/reflection/IPC) | Native + manifest analysis only; result is `COMPLETED_WITH_LIMITATIONS`, `code_analysis` UNAVAILABLE | Download a release from https://github.com/skylot/jadx/releases, unzip, point `ASF_JADX_PATH` at `bin/jadx`. |
| **Ghidra** — 11+/12 | **Deep native** call-chain: functions, call edges, JNI resolution, native-API **reachability** | ELF-only native analysis (`NATIVE_API_PRESENT`, no call-chain reachability) | Download from https://github.com/NationalSecurityAgency/ghidra/releases, unzip, set `ASF_GHIDRA_PATH` to the unzipped dir. Enable with `ASF_GHIDRA_DEEP_ENABLED=true`. Needs JDK 21+. |
| **adb** (Android platform-tools) | Real-device discovery / install / launch / logcat → **live runtime validation** | Runtime validation `UNAVAILABLE` (offline) | Android Studio, or the [platform-tools](https://developer.android.com/tools/releases/platform-tools) zip; put `adb` on `PATH`. |
| **Frida** (host) | Live **native/JNI instrumentation** → native-runtime correlation | Runtime is ADB-only; native-runtime correlation `UNAVAILABLE` | `pip install frida-tools`. Also needs **frida-server on the device**, which requires **root** — see [runtime.md](runtime.md). |

### Not required

- **apktool** — **not used** by the pipeline. AndroidSecForge decodes binary AXML
  and the manifest with its own in-process parser, so apktool's absence has **no
  effect**. (`ASF_APKTOOL_PATH` exists only as an unused config placeholder.)

After installing, run `androidsecforge doctor` to see exactly what was detected and
what each capability is.

---

## 2. Install the backend

### Standard (recommended)

```bash
git clone <repo-url> android-tester && cd android-tester
python -m pip install -e '.[test]'
```

This installs the `androidsecforge` console script plus the FastAPI service and test
dependencies (`pytest`, `httpx`). Runtime deps: fastapi, uvicorn, pydantic(-settings),
sqlalchemy, psycopg, typer, python-multipart.

Verify:

```bash
androidsecforge doctor
```

### Externally-managed Python (PEP 668, e.g. Kali/Debian)

If `pip install` refuses because the interpreter is externally managed, use a venv:

```bash
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -e '.[test]'
```

### Without installing the console script (module form)

The CLI is fully usable straight from the source tree:

```bash
PYTHONPATH=backend python -m app.cli doctor
PYTHONPATH=backend python -m app.cli analyze ./app.apk --json
```

The `Makefile` targets (`make doctor`, `make api`, `make migrate`, `make test-apk`,
`make test`) already use this module form and need no install.

---

## 3. Database

SQLite is the default (`sqlite:///./androidsecforge.db`); tables are created
automatically on first run — nothing to do.

For a shared/multi-user setup, use PostgreSQL:

```bash
docker compose up -d postgres           # postgres:16-alpine
export ASF_DATABASE_URL="postgresql+psycopg://androidsecforge:androidsecforge@localhost:5432/androidsecforge"
make migrate                            # alembic upgrade head
```

---

## 4. Run the backend

```bash
androidsecforge serve                   # http://127.0.0.1:8000
# or, from the source tree with autoreload:
make api                                # uvicorn app.main:app --reload on :8000
```

Sanity-check the API: `curl http://127.0.0.1:8000/health` → `{"status":"ok"}`.

---

## 5. Run the Web UI (optional)

```bash
cd frontend
npm install
npm run dev                             # http://127.0.0.1:5173
```

The dev server proxies `/api` → `http://localhost:8000`, so start the backend
(§4) first. From the browser you can upload an APK, create an analysis, and watch
real per-stage progress. Production build: `npm run build` (outputs `frontend/dist/`).

---

## 6. Enable the deep analyzers (jadx + Ghidra deep)

The static pipeline runs without these; enabling them gives the **complete**
analysis. Configure them in a `.env` file (copy the template, then edit — **no
paths are hardcoded anywhere**):

```bash
cp .env.example .env
# edit .env:
#   ASF_JADX_PATH=/path/to/jadx/bin/jadx        # DEX -> Java decompilation
#   ASF_GHIDRA_PATH=/path/to/ghidra_11.x_PUBLIC # Ghidra install dir
#   ASF_GHIDRA_DEEP_ENABLED=true                # deep native call-chain
```

Then start the full-pipeline server (it loads `.env`, so nothing to export):

```bash
./backend/run-full-pipeline.sh
```

Verify with `androidsecforge doctor` (expect `jadx READY`, `ghidra READY`), or the
Runtime/Native tabs in the UI. (`.env` is gitignored — see `.env.example` for every
option. A bare `androidsecforge serve` also reads a repo-root `.env`, but does not
apply the full-pipeline defaults that `run-full-pipeline.sh` sets.)

**Trade-offs (this is expected, not a hang):**

- jadx adds ~7–10 s per analysis.
- **Ghidra deep adds roughly ~1 minute per native library** (e.g. a 24-lib app ≈ ~27 min).
  The progress screen will legitimately sit on `native_deep` for that time.
- **Run one native-heavy analysis at a time** — a long Ghidra-deep run holds the
  SQLite write lock, so a concurrent analysis can hit "database is locked". (Use
  PostgreSQL to relax this.)

**The legacy standalone `ghidra` stage** (`ASF_GHIDRA_ENABLED`) is separate and left
**off** by default: it is redundant with Ghidra deep, and its post-script is a Jython
`.py` GhidraScript that Ghidra 12 cannot run. "Ghidra deep" is `ASF_GHIDRA_DEEP_ENABLED`.

> **Developer note — the test suite stays hermetic regardless of `.env`.** An
> autouse fixture (`no_ghidra` in `backend/tests/conftest.py`) forces Ghidra to
> appear absent during tests — and because both the standalone and the deep paths
> resolve Ghidra through the same detector, the deep path falls back to `ELF_ONLY`
> too. jadx isn't invoked on the synthetic in-process test APKs. So `make test`
> passes fast (~40 s) even with `ASF_GHIDRA_DEEP_ENABLED=true` and `ASF_JADX_PATH`
> set — verified. Put your config in `.env` with confidence.

---

## 7. Verify the install end-to-end

```bash
androidsecforge doctor                                  # capability report
make test-apk                                           # build a local test APK
androidsecforge analyze analysis/test-apks/AndroidSecForge-TestApp.apk
androidsecforge analyze ./real.apk --json > report.json
make test                                               # run the backend test suite
```

`analyze` prints an `analysis_id`, per-stage status, capability states, and findings.
Status is `COMPLETE` when every stage succeeds, `PARTIAL` / `COMPLETED_WITH_LIMITATIONS`
when an optional analyzer (e.g. jadx) is unavailable, and `FAILED` only on a
fundamental failure.

---

## 8. Configuration reference

All settings use the `ASF_` prefix (see `backend/app/core/config.py`) and can be set
as environment variables or in a `.env` file (copy `.env.example`; `.env` is
gitignored). pydantic reads `.env` from the working directory; `run-full-pipeline.sh`
loads the repo-root `.env` explicitly.

| Variable | Purpose | Default |
| --- | --- | --- |
| `ASF_DATABASE_URL` | Database connection | `sqlite:///./androidsecforge.db` |
| `ASF_ARTIFACT_STORAGE_PATH` | Where uploaded APKs are stored (by hash) | `./artifacts` |
| `ASF_WORKSPACE_PATH` | Per-APK working directory root | `./workspace` |
| `ASF_JADX_PATH` | jadx executable (enables Java decompilation) | discovered on `PATH` |
| `ASF_JADX_TIMEOUT_SECONDS` | jadx subprocess timeout | `600` |
| `ASF_GHIDRA_PATH` | Ghidra install dir (enables detection) | discovered |
| `ASF_GHIDRA_ENABLED` | Legacy standalone per-library ghidra stage | `false` |
| `ASF_GHIDRA_DEEP_ENABLED` | **Deep native call-chain (Ghidra deep)** | `false` |
| `ASF_FRIDA_PATH` | Host Frida CLI (if not on `PATH`) | discovered |
| `ASF_FRIDA_SERVER_PATH_ON_DEVICE` | frida-server path checked on device | `/data/local/tmp/frida-server` |
| `ASF_UPLOAD_MAX_FILE_SIZE` | Per-file upload limit (web intake) | 512 MiB |
| `ASF_ANALYSIS_MAX_CONCURRENT_EXECUTIONS` | Concurrent web analyses | `2` |

Developer-specific absolute paths are never hardcoded — always use env vars or `.env`.

See also: [toolchain.md](toolchain.md) (capability detection), [jadx.md](jadx.md),
[ghidra.md](ghidra.md) / [deep-native.md](deep-native.md), [runtime.md](runtime.md),
[web-intake.md](web-intake.md) (browser upload/analysis flow), [frontend.md](frontend.md).

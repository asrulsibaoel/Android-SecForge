# JADX integration

JADX is an **optional** decompiler. The adapter lives in `backend/app/analysis/jadx.py`.

## Installation (reproducible)

JADX is a standalone Java application (JRE 11+; this project verified against JADX 1.5.6 on Java 25). Two options on Kali Linux:

**Portable release (no root, recommended):**

```bash
mkdir -p "$HOME/tools" && cd "$HOME/tools"
TAG=$(curl -sS https://api.github.com/repos/skylot/jadx/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
VER=${TAG#v}
curl -sSL -o jadx.zip "https://github.com/skylot/jadx/releases/download/${TAG}/jadx-${VER}.zip"
mkdir -p jadx && (cd jadx && unzip -q ../jadx.zip)
chmod +x jadx/bin/jadx
export ASF_JADX_PATH="$HOME/tools/jadx/bin/jadx"   # or add jadx/bin to PATH
"$ASF_JADX_PATH" --version
```

**Kali package (requires root):**

```bash
sudo apt-get update && sudo apt-get install -y jadx   # provides jadx on PATH
```

Point AndroidSecForge at it via `ASF_JADX_PATH`, or ensure `jadx` is on `PATH`. Confirm with `androidsecforge doctor` (jadx should show `capability: READY`).

## Detection

The executable is resolved from `ASF_JADX_PATH` (if it points to a file) or from `PATH`.
`androidsecforge doctor` reports its status and version.

## Invocation

When available, JADX is invoked as a subprocess with an argument array (never
`shell=True`):

```
jadx --no-res --no-debug-info --deobf -d <workspace>/jadx <apk>
```

- A timeout (`ASF_JADX_TIMEOUT_SECONDS`, default 600s) is enforced.
- Output goes to an isolated per-APK workspace directory.
- stdout/stderr tails, exit code, version, and duration are captured.

## Result states

| State | Meaning |
| --- | --- |
| `SUCCESS` | Exit 0, or non-zero but partial `sources/` were produced. |
| `TIMEOUT` | Exceeded the configured timeout. |
| `FAILED` | Ran but produced no sources. |
| `UNAVAILABLE` | JADX is not installed/configured. |

Only `SUCCESS` feeds the code index. `UNAVAILABLE`/`TIMEOUT`/`FAILED` leave the analysis
`PARTIAL` with `code_analysis = UNAVAILABLE` — decompiled output is never fabricated.

## Without JADX

DEX header inventory, manifest, permissions, components, and manifest rules all work
without JADX. Only source-level code rules and the code index require it.

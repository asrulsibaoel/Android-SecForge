"""Provider-neutral Ghidra adapter (prompt 20).

Abstracts capability detection, binary import, analysis invocation, and result
extraction behind one controlled boundary. The rest of the application depends on
the normalized ``GhidraExport`` — never on Ghidra CLI syntax. All external
execution uses a fixed argument array (never a user-supplied command string),
with time/output/function bounds. Ghidra is optional; when absent the adapter
reports UNAVAILABLE and callers fall back to ELF-only evidence.

Fixture exports (for offline tests) are parsed by ``parse_export`` and clearly
marked ``FIXTURE`` — never reported as LIVE.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from app.analysis import ghidra as _ghidra_headless
from app.core.config import settings

# Capability states.
READY = "READY"
PARTIAL = "PARTIAL"
UNAVAILABLE = "UNAVAILABLE"
ERROR = "ERROR"

# Java GhidraScript (compiled/run by Ghidra headless — Ghidra 11/12 dropped Jython,
# so a .py post-script needs PyGhidra; a .java script needs nothing extra).
_DEEP_SCRIPT = Path(__file__).resolve().parent.parent / "analysis" / "ghidra_scripts" / "ExportDeepNative.java"


@dataclass
class GhidraExport:
    """Normalized deep-native export from Ghidra (or a FIXTURE)."""
    program: str
    language: str | None = None
    architecture: str | None = None
    source: str = "GHIDRA"  # GHIDRA | FIXTURE
    functions: list[dict] = field(default_factory=list)   # {name, address, size, namespace, exported, imported}
    calls: list[dict] = field(default_factory=list)        # {src, dst, src_addr, dst_addr}
    imports: list[dict] = field(default_factory=list)      # {name, library}
    exports: list[dict] = field(default_factory=list)      # {name, address}
    symbols: list[dict] = field(default_factory=list)      # {name, type, address, kind}
    strings: list[dict] = field(default_factory=list)      # {value, address}
    references: list[dict] = field(default_factory=list)   # {from, to, type}
    jni_registrations: list[dict] = field(default_factory=list)  # {java_class, java_method, signature, native}
    truncated: bool = False


def capability() -> dict:
    """Detect Ghidra capability without assuming it exists. Never raises."""
    try:
        executable = _ghidra_headless.analyze_headless_executable()
    except Exception as error:  # detection must never break
        return {"state": ERROR, "reason": str(error), "path": None, "version": None, "headless": False}
    if executable is None:
        return {"state": UNAVAILABLE, "reason": "Ghidra analyzeHeadless not found on PATH or via ASF_GHIDRA_PATH/"
                                                "GHIDRA_INSTALL_DIR", "path": None, "version": None, "headless": False}
    version = _ghidra_headless._version(executable)
    enabled = bool(settings.ghidra_deep_enabled)
    state = READY if enabled else PARTIAL
    reason = ("headless analyzer present and deep analysis enabled" if enabled
              else "headless analyzer present but deep analysis disabled (set ASF_GHIDRA_DEEP_ENABLED=true)")
    return {"state": state, "reason": reason, "path": executable, "version": version, "headless": True,
            "deep_enabled": enabled}


# ---------------------------------------------------------------------------
# Fixture parsing (offline; clearly marked FIXTURE)
# ---------------------------------------------------------------------------


def parse_export(payload: dict, *, source: str = "FIXTURE") -> GhidraExport:
    """Parse a Ghidra deep-export payload (dict) into a normalized export.
    Bounded to configured caps. Malformed fields are skipped, never guessed."""
    fmax = settings.native_max_functions_per_binary
    smax = settings.native_max_symbols
    cmax = settings.native_max_call_edges
    strmax = settings.native_max_strings

    def _rows(key, cap):
        rows = payload.get(key, []) or []
        return rows[:cap], len(rows) > cap

    functions, tf = _rows("functions", fmax)
    calls, tc = _rows("calls", cmax)
    symbols, ts = _rows("symbols", smax)
    strings, tstr = _rows("strings", strmax)
    return GhidraExport(
        program=str(payload.get("program", "unknown")),
        language=payload.get("language"), architecture=payload.get("architecture"),
        source=source,
        functions=[_norm_fn(f) for f in functions],
        calls=[{"src": str(c.get("src", "")), "dst": str(c.get("dst", "")),
                "src_addr": str(c.get("src_addr", "")), "dst_addr": str(c.get("dst_addr", ""))}
               for c in calls if c.get("src") and c.get("dst")],
        imports=[{"name": str(i.get("name", "")), "library": i.get("library")} for i in payload.get("imports", [])],
        exports=[{"name": str(e.get("name", "")), "address": str(e.get("address", ""))}
                 for e in payload.get("exports", [])],
        symbols=[{"name": str(s.get("name", "")), "type": s.get("type"), "address": str(s.get("address", "")),
                  "kind": s.get("kind", "local")} for s in symbols if s.get("name")],
        strings=[{"value": str(s.get("value", ""))[:1024], "address": str(s.get("address", ""))}
                 for s in strings if s.get("value")],
        references=[{"from": str(r.get("from", "")), "to": str(r.get("to", "")), "type": r.get("type", "DATA")}
                    for r in payload.get("references", [])],
        jni_registrations=[{"java_class": r.get("java_class"), "java_method": r.get("java_method"),
                            "signature": r.get("signature"), "native": r.get("native")}
                           for r in payload.get("jni_registrations", []) if r.get("java_method")],
        truncated=tf or tc or ts or tstr)


def _norm_fn(f: dict) -> dict:
    return {"name": str(f.get("name", "")), "address": str(f.get("address", "")),
            "size": int(f.get("size", 0) or 0), "namespace": str(f.get("namespace", "")),
            "exported": bool(f.get("exported", False)), "imported": bool(f.get("imported", False))}


def parse_export_file(path: str | Path, *, source: str = "FIXTURE") -> GhidraExport | None:
    try:
        raw = Path(path).read_bytes()
        if len(raw) > settings.native_max_output_bytes:
            raw = raw[: settings.native_max_output_bytes]
        return parse_export(json.loads(raw.decode("utf-8", "ignore")), source=source)
    except (OSError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# Live analysis (opt-in; bounded; controlled boundary)
# ---------------------------------------------------------------------------


def analyze(so_path: str | Path, workspace: str | Path, timeout: int | None = None) -> tuple[str, GhidraExport | None]:
    """Run bounded headless Ghidra deep analysis on one binary. Returns
    (mode, export_or_None). Only invoked when capability is READY; otherwise
    returns (ELF_ONLY, None) so callers fall back to ELF evidence.

    Uses a fixed argument array (no shell, no user command strings)."""
    cap = capability()
    if cap["state"] != READY or not _DEEP_SCRIPT.is_file():
        return ("ELF_ONLY", None)
    so_path = Path(so_path)
    project_dir = Path(workspace) / "ghidra_deep"
    project_dir.mkdir(parents=True, exist_ok=True)
    output = project_dir / f"{so_path.name}.deep.json"
    timeout = timeout or int(settings.native_analysis_timeout_seconds)
    arguments = [
        cap["path"], str(project_dir), "asf_deep_project", "-import", str(so_path),
        "-scriptPath", str(_DEEP_SCRIPT.parent), "-postScript", _DEEP_SCRIPT.name, str(output),
        "-deleteProject", "-analysisTimeoutPerFile", str(timeout),
    ]
    started = time.monotonic()
    try:
        subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return ("GHIDRA_AVAILABLE", None)  # ran but produced nothing usable
    export = parse_export_file(output, source="GHIDRA") if output.exists() else None
    _ = round(time.monotonic() - started, 3)
    return ("GHIDRA_AVAILABLE", export)

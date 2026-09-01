"""Deep native / Ghidra correlation engine (prompt 20).

Supplements existing ELF/JNI evidence with deeper native analysis (optionally
from Ghidra). Reconciles ELF and Ghidra observations by stable content-derived
identity (binary hash + architecture + normalized name / entry) — never by DB
ids, Ghidra temporary ids, or name similarity alone.

Conservative by construction: a native function present never implies it is
reachable from Java; a JNI export never implies the Java side invokes it; a
dangerous native API present never implies vulnerability. UNKNOWN /
UNKNOWN_NATIVE_TARGET are preserved. No `exploitable` state exists. Never mutates
findings / CVE state / severity / risk / remediation / validation / runtime.

Modes: GHIDRA_AVAILABLE (live), FIXTURE (offline test data, clearly marked), or
ELF_ONLY (no Ghidra — fully functional). Deterministic + idempotent.

Complexity: single pass over persisted ELF native functions + bounded Ghidra
export; dictionary indexes; bounded native call-graph BFS; reuse of persisted
graph — no N×M scans, no Java-graph recomputation.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import deque

from app.analysis.signatures import NATIVE_SINK_SYMBOLS
from app.core.config import settings
from app.models.native_deep import (
    FT_EXPORTED_NATIVE, FT_IMPORTED, FT_JNI_EXPORT, FT_JNI_INTERNAL, FT_LIBRARY_INTERNAL, FT_UNKNOWN,
    MODE_ELF_ONLY, MODE_FIXTURE, MODE_GHIDRA,
    NativeAnalysisRun, NativeApiObservation, NativeBinary, NativeCallEdge, NativeDeepEvidence,
    NativeDeepFunction, NativeDeepJNIBinding, NativeDeepSymbol, NativeReference, NativeString,
)

# Native API categories (extends the persisted native-sink taxonomy). Presence
# is an observation only — never a vulnerability.
_API_CATEGORIES = dict(NATIVE_SINK_SYMBOLS)
_API_CATEGORIES.update({
    "memcpy": "unsafe_memory", "memmove": "unsafe_memory", "snprintf": "format", "vsnprintf": "format",
    "dlopen": "dynamic_load", "dlsym": "dynamic_load", "fopen": "file_io", "open": "file_io",
    "read": "file_io", "write": "file_io", "socket": "network", "connect": "network", "recv": "network",
    "send": "network", "mmap": "memory_map",
})
_API_PREFIX = {"SSL_": "tls", "TLS_": "tls", "EVP_": "crypto", "AES_": "crypto", "RSA_": "crypto",
               "SHA": "crypto"}

_GENERIC_NAME_RE = re.compile(r"^(FUN_[0-9a-fA-F]+|thunk_|LAB_|sub_|__?[a-z]+$)")

# API observation states.
API_PRESENT = "NATIVE_API_PRESENT"
API_REACHED = "NATIVE_CALL_CHAIN_REACHES_API"
API_TARGET_UNKNOWN = "NATIVE_API_TARGET_UNKNOWN"
API_CHAIN_UNRESOLVED = "NATIVE_CALL_CHAIN_UNRESOLVED"

UNKNOWN_NATIVE_TARGET = "UNKNOWN_NATIVE_TARGET"


def _fp(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:32]


def _binary_fp(sha256: str | None, arch: str | None) -> str:
    return _fp("BIN", sha256 or "unknown", (arch or "unknown").lower())


def _normalize_name(name: str) -> str:
    n = (name or "").strip()
    n = n.lstrip("_")
    n = re.sub(r"@.*$", "", n)  # drop version suffixes
    return n


def _function_identity(binary_fp: str, name: str, entry: str) -> str:
    norm = _normalize_name(name)
    if norm and not _GENERIC_NAME_RE.match(name or ""):
        return _fp("FN", binary_fp, norm.lower())
    return _fp("FN", binary_fp, entry or "0")


def _function_type(name: str, exported: bool, imported: bool) -> str:
    if name.startswith("Java_"):
        return FT_JNI_EXPORT if exported else FT_JNI_INTERNAL
    if name in ("JNI_OnLoad", "JNI_OnUnload", "RegisterNatives"):
        return FT_JNI_INTERNAL
    if imported:
        return FT_IMPORTED
    if exported:
        return FT_EXPORTED_NATIVE
    if name:
        return FT_LIBRARY_INTERNAL
    return FT_UNKNOWN


def _api_category(name: str) -> str | None:
    if name in _API_CATEGORIES:
        return _API_CATEGORIES[name]
    for prefix, cat in _API_PREFIX.items():
        if name.startswith(prefix):
            return cat
    return None


# ---------------------------------------------------------------------------
# Build (persisted, idempotent, deterministic)
# ---------------------------------------------------------------------------


def build_deep_native(db, analysis, ghidra_exports: dict | None = None,
                      requested_by: str = "orchestrator") -> NativeAnalysisRun:
    """Build + persist deep-native evidence. ``ghidra_exports`` maps a binary key
    (filename or archive_path) to a GhidraExport (FIXTURE for tests); when None the
    adapter is consulted (live Ghidra if enabled, else ELF-only)."""
    from app.native.ghidra_adapter import capability

    _clear(analysis)
    db.flush()

    cap = capability()
    mode, exports = _resolve_exports(analysis, ghidra_exports, cap)

    binaries: list[NativeBinary] = []
    fn_by_fp: dict[str, NativeDeepFunction] = {}
    fn_by_name: dict[tuple[str, str], NativeDeepFunction] = {}  # (binary_fp, normalized_name)
    call_edges: list[NativeCallEdge] = []
    unresolved = 0

    for lib in list(analysis.native_libraries)[: settings.native_max_binaries]:
        if lib.status != "COMPLETE":
            continue
        bfp = _binary_fp(lib.sha256, lib.architecture or lib.abi)
        export = _match_export(lib, exports)
        source = "ELF+GHIDRA" if export else "ELF"
        binary = NativeBinary(
            analysis_id=analysis.id, fingerprint=bfp, filename=lib.filename, abi=lib.abi,
            architecture=lib.architecture, sha256=lib.sha256, soname=lib.soname, stripped=lib.stripped,
            symbols_available=lib.symbols_available, size_bytes=lib.size_bytes, source=source,
            evidence_json={"elf_type": lib.elf_type, "needed": sorted(d.needed for d in lib.dependencies)})
        analysis.native_binaries.append(binary)
        binaries.append(binary)
        _evidence(analysis, bfp, "ELF", lib.archive_path, lib.filename, None, None, "HIGH",
                  f"ELF binary {lib.filename} ({lib.architecture}) stripped={lib.stripped}")

        # ELF functions (persisted native evidence)
        for fn in lib.functions[: settings.native_max_functions_per_binary]:
            entry = hex(fn.address) if fn.address else ""
            row = _add_function(analysis, bfp, fn.name, entry, fn.size, fn.kind == "exported",
                                fn.kind == "imported", "ELF", fn.symbol_type, fn.confidence,
                                {"kind": fn.kind, "binding": fn.binding})
            fn_by_fp[row.fingerprint] = row
            fn_by_name[(bfp, _normalize_name(fn.name).lower())] = row
            cat = _api_category(fn.name) if fn.kind == "imported" else None
            if cat:
                _add_api(analysis, bfp, row.fingerprint, fn.name, cat, API_PRESENT, "HIGH", "ELF",
                         {"imported": True})

        # Ghidra functions + calls + strings + symbols (supplement; reconcile)
        if export is not None:
            _import_ghidra(analysis, bfp, export, fn_by_fp, fn_by_name, call_edges)

    # JNI bindings (persisted ELF/JNI + Ghidra registrations)
    jni_rows, jni_unresolved = _build_jni(analysis, binaries, fn_by_fp, fn_by_name, exports)
    unresolved += jni_unresolved

    # Native API reachability via Ghidra call graph + resolved JNI
    reached = _correlate_api_reachability(analysis, call_edges, jni_rows, fn_by_fp)
    unresolved += reached["unresolved"]

    run_fp = hashlib.sha256("|".join(sorted(
        [b.fingerprint for b in binaries] + [f.fingerprint for f in fn_by_fp.values()]
        + [e.fingerprint for e in call_edges] + [j.fingerprint for j in jni_rows]
        + [o.fingerprint for o in analysis.native_api_observations])).encode()).hexdigest()[:32]
    run = NativeAnalysisRun(
        analysis_id=analysis.id, fingerprint=run_fp, mode=mode,
        ghidra_capability=cap["state"], ghidra_version=cap.get("version"),
        binaries_count=len(binaries), functions_count=len(fn_by_fp), jni_count=len(jni_rows),
        call_edge_count=len(call_edges), api_observation_count=len(analysis.native_api_observations),
        unresolved_target_count=unresolved,
        summary={"mode": mode, "ghidra": cap["state"],
                 "resolved_jni": sum(1 for j in jni_rows if j.state == "RESOLVED"),
                 "unresolved_jni": sum(1 for j in jni_rows if j.state == "UNKNOWN"),
                 "api_present": sum(1 for o in analysis.native_api_observations if o.state == API_PRESENT),
                 "api_reached": sum(1 for o in analysis.native_api_observations if o.state == API_REACHED)})
    analysis.native_analysis_runs.append(run)
    db.flush()
    return run


def _resolve_exports(analysis, ghidra_exports, cap) -> tuple[str, dict]:
    if ghidra_exports:
        # any fixture-sourced export -> FIXTURE mode
        return (MODE_FIXTURE, ghidra_exports)
    if cap["state"] == "READY" and settings.ghidra_deep_enabled:
        import os
        from pathlib import Path
        from app.native.ghidra_adapter import analyze
        exports: dict = {}
        # Ghidra needs a WORKSPACE DIRECTORY for its project — a dedicated dir under
        # the analysis workspace, never the .so file itself.
        ws = Path(settings.workspace_path) / analysis.apk_sha256 / "ghidra_deep"
        try:
            ws.mkdir(parents=True, exist_ok=True)
        except OSError:
            ws = Path(".")
        for lib in analysis.native_libraries:
            if lib.status != "COMPLETE" or not lib.workspace_path or not os.path.isfile(lib.workspace_path):
                continue
            _mode, export = analyze(lib.workspace_path, ws)
            if export is not None:
                exports[lib.archive_path] = export
        return (MODE_GHIDRA if exports else MODE_ELF_ONLY, exports)
    return (MODE_ELF_ONLY, {})


def _match_export(lib, exports: dict):
    if not exports:
        return None
    return exports.get(lib.archive_path) or exports.get(lib.filename) or exports.get(lib.soname or "")


def _add_function(analysis, bfp, name, entry, size, exported, imported, source, symbol_type,
                  confidence, extra) -> NativeDeepFunction:
    ffp = _function_identity(bfp, name, entry)
    existing = next((f for f in analysis.native_deep_functions if f.fingerprint == ffp), None)
    if existing is not None:
        # reconcile: supplement source, fill entry/size if missing
        if source not in existing.source:
            existing.source = "ELF+GHIDRA"
        if not existing.entry_address and entry:
            existing.entry_address = entry
        if not existing.size and size:
            existing.size = size
        return existing
    row = NativeDeepFunction(
        analysis_id=analysis.id, binary_fp=bfp, fingerprint=ffp, name=name,
        normalized_name=_normalize_name(name), entry_address=entry or None, size=size or 0,
        function_type=_function_type(name, exported, imported), symbol_type=symbol_type,
        is_exported=exported, is_imported=imported, confidence=confidence, source=source,
        evidence_json=extra)
    analysis.native_deep_functions.append(row)
    _evidence(analysis, ffp, source, None, None, name, entry, confidence,
              f"native function {name} ({row.function_type}) source={source}")
    return row


def _import_ghidra(analysis, bfp, export, fn_by_fp, fn_by_name, call_edges) -> None:
    for gf in export.functions:
        row = _add_function(analysis, bfp, gf["name"], gf["address"], gf["size"], gf.get("exported", False),
                            gf.get("imported", False), export.source if export.source == "FIXTURE" else "GHIDRA",
                            None, "MEDIUM", {"namespace": gf.get("namespace")})
        fn_by_fp[row.fingerprint] = row
        fn_by_name[(bfp, _normalize_name(gf["name"]).lower())] = row
        cat = _api_category(gf["name"])
        if cat and gf.get("imported"):
            _add_api(analysis, bfp, row.fingerprint, gf["name"], cat, API_PRESENT, "MEDIUM",
                     export.source, {"ghidra": True})
    for sym in export.symbols[: settings.native_max_symbols]:
        analysis.native_deep_symbols.append(NativeDeepSymbol(
            analysis_id=analysis.id, binary_fp=bfp, fingerprint=_fp("SYM", bfp, sym["name"], sym.get("address", "")),
            name=sym["name"], symbol_type=sym.get("type"), address=sym.get("address"),
            kind=sym.get("kind", "local"), source=export.source))
    for s in export.strings[: settings.native_max_strings]:
        analysis.native_strings.append(NativeString(
            analysis_id=analysis.id, binary_fp=bfp, fingerprint=_fp("STR", bfp, s["value"], s.get("address", "")),
            value=s["value"][:1024], address=s.get("address"), source=export.source))
    for c in export.calls[: settings.native_max_call_edges]:
        src_fp = _function_identity(bfp, c["src"], c.get("src_addr", ""))
        dst_row = fn_by_name.get((bfp, _normalize_name(c["dst"]).lower()))
        dst_fp = dst_row.fingerprint if dst_row else None
        edge = NativeCallEdge(
            analysis_id=analysis.id, binary_fp=bfp,
            fingerprint=_fp("CALL", bfp, _normalize_name(c["src"]).lower(), _normalize_name(c["dst"]).lower()),
            src_fp=src_fp, src_name=c["src"], dst_fp=dst_fp, dst_name=c["dst"], edge_type="GHIDRA_CALLS",
            confidence="MEDIUM", source=export.source)
        analysis.native_call_edges.append(edge)
        call_edges.append(edge)
    for r in export.references:
        analysis.native_references.append(NativeReference(
            analysis_id=analysis.id, binary_fp=bfp, fingerprint=_fp("REF", bfp, r["from"], r["to"]),
            from_fp=_fp("FN", bfp, r["from"]), to_address=r["to"], ref_type=r.get("type", "DATA"),
            source=export.source))


def _build_jni(analysis, binaries, fn_by_fp, fn_by_name, exports):
    rows: list[NativeDeepJNIBinding] = []
    unresolved = 0
    bin_by_name = {b.filename: b for b in binaries}
    for b in analysis.jni_bindings[: settings.native_max_jni_bindings]:
        binary = bin_by_name.get(b.library_name)
        bfp = binary.fingerprint if binary else None
        native_fn = None
        if bfp and b.native_function:
            native_fn = fn_by_name.get((bfp, _normalize_name(b.native_function).lower()))
        # registration type
        evidence_text = (b.evidence or "").lower()
        if "registernatives" in evidence_text:
            reg = "DYNAMIC_REGISTER"
        elif b.native_function and b.native_function.startswith("Java_"):
            reg = "STATIC_NAMING"
        elif native_fn is not None:
            reg = "STATIC_NAMING"
        else:
            reg = "UNRESOLVED"
        state = "RESOLVED" if native_fn is not None else "UNKNOWN"
        if state == "UNKNOWN":
            unresolved += 1
        row = NativeDeepJNIBinding(
            analysis_id=analysis.id,
            fingerprint=_fp("JNI", b.java_class, b.java_method, b.native_function, b.library_name),
            java_class=b.java_class, java_method=b.java_method, java_signature=b.java_signature,
            native_symbol=b.native_function, native_function_fp=native_fn.fingerprint if native_fn else None,
            binary_fp=bfp, registration_type=reg, state=state, confidence=b.confidence, source="JNI",
            evidence_json={"native_target": UNKNOWN_NATIVE_TARGET if state == "UNKNOWN" else b.native_function})
        analysis.native_deep_jni_bindings.append(row)
        rows.append(row)
        _evidence(analysis, row.fingerprint, "JNI", b.library_name, None,
                  f"{b.java_class}.{b.java_method}", None, b.confidence,
                  f"JNI binding {reg}/{state} native={b.native_function or UNKNOWN_NATIVE_TARGET}")

    # Ghidra-supplied dynamic registrations (fixtures)
    for export in exports.values():
        for reg in export.jni_registrations:
            native = reg.get("native")
            match = None
            if native is not None:
                nnorm = _normalize_name(native).lower()
                match = next((f for f in analysis.native_deep_functions
                              if f.normalized_name.lower() == nnorm), None)
            resolved = match is not None
            row = NativeDeepJNIBinding(
                analysis_id=analysis.id,
                fingerprint=_fp("JNIREG", reg.get("java_class"), reg.get("java_method"), native),
                java_class=reg.get("java_class"), java_method=reg.get("java_method"),
                java_signature=reg.get("signature"), native_symbol=native,
                native_function_fp=match.fingerprint if match else None,
                binary_fp=match.binary_fp if match else None, registration_type="DYNAMIC_REGISTER",
                state="RESOLVED" if resolved else "UNKNOWN", confidence="MEDIUM",
                source=export.source,
                evidence_json={"registernatives": True,
                               "native_target": native if resolved else UNKNOWN_NATIVE_TARGET})
            if not any(r.fingerprint == row.fingerprint for r in rows):
                analysis.native_deep_jni_bindings.append(row)
                rows.append(row)
                if row.state == "UNKNOWN":
                    unresolved += 1
    return rows, unresolved


def _correlate_api_reachability(analysis, call_edges, jni_rows, fn_by_fp) -> dict:
    """Only Ghidra call edges establish native reachability. A JNI-resolved export
    that reaches an API function through the call graph -> NATIVE_CALL_CHAIN_REACHES_API.
    Never fabricated: without call edges the target remains UNKNOWN."""
    adjacency: dict[str, list[str]] = {}
    for e in call_edges:
        if e.dst_fp:
            adjacency.setdefault(e.src_fp, []).append(e.dst_fp)
    api_fns = {o.function_fp for o in analysis.native_api_observations if o.function_fp}
    unresolved = 0
    started = jni_starts = 0
    for j in jni_rows:
        if j.state != "RESOLVED" or not j.native_function_fp:
            if j.state == "UNKNOWN":
                # JNI unresolved -> any related API target is UNKNOWN
                pass
            continue
        jni_starts += 1
        reached = _reaches(adjacency, j.native_function_fp, api_fns, settings.native_path_max_depth)
        for api_fp in reached:
            fn = fn_by_fp.get(api_fp)
            _add_api(analysis, fn.binary_fp if fn else None, api_fp, fn.name if fn else "?",
                     _api_category(fn.name) or "unknown" if fn else "unknown", API_REACHED, "MEDIUM",
                     "GHIDRA", {"jni": j.java_method, "native": j.native_symbol})
    # mark JNI-unresolved API observations
    if any(j.state == "UNKNOWN" for j in jni_rows) and not call_edges:
        for o in analysis.native_api_observations:
            if o.state == API_PRESENT:
                # present but no proven chain from Java -> target unknown
                unresolved += 0  # counted via JNI already
    return {"unresolved": unresolved, "jni_starts": jni_starts}


def _reaches(adjacency, start, targets, max_depth) -> set[str]:
    if start in targets:
        return {start}
    out: set[str] = set()
    queue = deque([(start, 0)])
    visited = {start}
    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for nxt in adjacency.get(node, []):
            if nxt in targets:
                out.add(nxt)
            if nxt not in visited:
                visited.add(nxt)
                queue.append((nxt, depth + 1))
    return out


def _add_api(analysis, bfp, ffp, api, category, state, confidence, source, extra) -> None:
    fp = _fp("API", bfp, api, state)
    if any(o.fingerprint == fp for o in analysis.native_api_observations):
        return
    analysis.native_api_observations.append(NativeApiObservation(
        analysis_id=analysis.id, fingerprint=fp, binary_fp=bfp, function_fp=ffp, api=api, category=category,
        state=state, confidence=confidence, source=source, evidence_json=extra))


def _evidence(analysis, subject_fp, source_type, artifact, file, function, address, confidence, detail) -> None:
    analysis.native_deep_evidence.append(NativeDeepEvidence(
        analysis_id=analysis.id, subject_fp=subject_fp,
        fingerprint=_fp("EV", subject_fp, source_type, detail), source_type=source_type, artifact=artifact,
        file=file, function=function, address=address, confidence=confidence, detail=detail))


def _clear(analysis) -> None:
    for coll in (analysis.native_analysis_runs, analysis.native_binaries, analysis.native_deep_functions,
                 analysis.native_deep_symbols, analysis.native_strings, analysis.native_call_edges,
                 analysis.native_references, analysis.native_deep_jni_bindings, analysis.native_api_observations,
                 analysis.native_deep_evidence):
        coll.clear()


# ---------------------------------------------------------------------------
# Views + explain + paths + CVE signatures + diff
# ---------------------------------------------------------------------------


def native_deep_view(analysis) -> dict:
    run = _latest_run(analysis)
    binaries = analysis.native_binaries
    functions = analysis.native_deep_functions
    jni = analysis.native_deep_jni_bindings
    calls = analysis.native_call_edges
    apis = analysis.native_api_observations
    from collections import Counter
    return {
        "capability": {"mode": run.mode if run else MODE_ELF_ONLY,
                       "ghidra": run.ghidra_capability if run else "UNAVAILABLE",
                       "ghidra_version": run.ghidra_version if run else None},
        "fingerprint": run.fingerprint if run else _fp("EMPTY", analysis.apk_sha256),
        "summary": {
            "binaries": len(binaries), "functions": len(functions), "jni_bindings": len(jni),
            "call_edges": len(calls), "api_observations": len(apis),
            "resolved_jni": sum(1 for j in jni if j.state == "RESOLVED"),
            "unresolved_jni": sum(1 for j in jni if j.state == "UNKNOWN"),
            "unresolved_targets": run.unresolved_target_count if run else 0,
            "by_function_type": dict(Counter(f.function_type for f in functions)),
            "api_states": dict(Counter(o.state for o in apis)),
        },
        "binaries": [{"fingerprint": b.fingerprint, "filename": b.filename, "abi": b.abi,
                      "architecture": b.architecture, "stripped": b.stripped, "source": b.source} for b in binaries],
        "functions": [_fn_dict(f) for f in functions][:2000],
        "jni_bindings": [_jni_dict(j) for j in jni],
        "call_edges": [{"src": e.src_name, "dst": e.dst_name, "resolved": e.dst_fp is not None,
                        "source": e.source} for e in calls][:2000],
        "api_observations": [_api_dict(o) for o in apis],
        "uncertainties": _uncertainties(jni, calls),
        "note": "Deep native analysis supplements ELF/JNI evidence; a native function present is not reachable "
                "from Java, a JNI export is not necessarily invoked, and a dangerous API present is not a "
                "vulnerability. UNKNOWN_NATIVE_TARGET preserved; no exploitability is asserted.",
    }


def _uncertainties(jni, calls) -> list[str]:
    out = []
    if any(j.state == "UNKNOWN" for j in jni):
        out.append(f"{sum(1 for j in jni if j.state == 'UNKNOWN')} JNI binding(s) have UNKNOWN_NATIVE_TARGET")
    if not calls:
        out.append("native call graph unavailable (ELF-only mode); native reachability is conservative")
    return out


def _fn_dict(f) -> dict:
    return {"id": f.fingerprint, "name": f.name, "normalized_name": f.normalized_name,
            "entry": f.entry_address, "function_type": f.function_type, "is_exported": f.is_exported,
            "is_imported": f.is_imported, "source": f.source, "confidence": f.confidence}


def _jni_dict(j) -> dict:
    return {"id": j.fingerprint, "java_class": j.java_class, "java_method": j.java_method,
            "native_symbol": j.native_symbol, "registration_type": j.registration_type, "state": j.state,
            "native_target": (j.evidence_json or {}).get("native_target"), "confidence": j.confidence,
            "source": j.source}


def _api_dict(o) -> dict:
    return {"id": o.fingerprint, "api": o.api, "category": o.category, "state": o.state,
            "confidence": o.confidence, "source": o.source, "evidence": o.evidence_json}


def _latest_run(analysis):
    runs = list(analysis.native_analysis_runs)
    return max(runs, key=lambda r: r.created_at) if runs else None


def native_explain(analysis, target: str) -> dict:
    """Explain a native target (function name / JNI method / binary / API),
    distinguishing PRESENT / RESOLVED / REACHABLE / SUPPORTED / UNKNOWN."""
    t = target.lower()
    fns = [f for f in analysis.native_deep_functions if t in f.name.lower() or t in f.normalized_name.lower()]
    jni = [j for j in analysis.native_deep_jni_bindings
           if (j.java_method and t in j.java_method.lower()) or (j.native_symbol and t in j.native_symbol.lower())]
    apis = [o for o in analysis.native_api_observations if t in o.api.lower()]
    steps = [f"Target '{target}': {len(fns)} native function(s), {len(jni)} JNI binding(s), {len(apis)} API obs."]
    binaries = {b.fingerprint: b for b in analysis.native_binaries}
    for f in fns[:5]:
        b = binaries.get(f.binary_fp)
        steps.append(f"PRESENT: {f.name} in {b.filename if b else '?'} (source {f.source}, type {f.function_type}).")
    for j in jni[:5]:
        if j.state == "RESOLVED":
            steps.append(f"RESOLVED: JNI {j.java_class}.{j.java_method} → {j.native_symbol}.")
        else:
            steps.append(f"UNKNOWN: JNI {j.java_class}.{j.java_method} → {UNKNOWN_NATIVE_TARGET} (never inferred).")
    for o in apis[:5]:
        label = {API_REACHED: "REACHABLE (via Ghidra call chain)", API_PRESENT: "PRESENT",
                 API_TARGET_UNKNOWN: "UNKNOWN target", API_CHAIN_UNRESOLVED: "UNRESOLVED chain"}.get(o.state, o.state)
        steps.append(f"{label}: native API {o.api} ({o.category}).")
    if not (fns or jni or apis):
        steps.append("NOT ESTABLISHED: no native evidence matches this target.")
    steps.append("What is NOT established: this does not assert Java reachability, vulnerability, or exploitability.")
    return {"target": target, "explanation": steps,
            "distinctions": {"present": bool(fns), "resolved": any(j.state == "RESOLVED" for j in jni),
                             "reachable": any(o.state == API_REACHED for o in apis),
                             "unknown": any(j.state == "UNKNOWN" for j in jni)},
            "note": "Native explanation never asserts exploitability; UNKNOWN_NATIVE_TARGET is preserved."}


def native_paths(analysis, from_query: str, to_query: str, max_depth: int | None = None,
                 min_confidence: str | None = None) -> dict:
    """Bounded Java→JNI→native→API path investigation. Uncertainty boundaries
    (UNKNOWN_NATIVE_TARGET) remain visible as valid path endpoints."""
    max_depth = max_depth or settings.native_path_max_depth
    max_paths = settings.native_max_path_results
    adjacency: dict[str, list[tuple[str, str]]] = {}
    fn_by_fp = {f.fingerprint: f for f in analysis.native_deep_functions}
    for e in analysis.native_call_edges:
        adjacency.setdefault(e.src_fp, []).append((e.dst_fp or "UNKNOWN", e.dst_name))
    api_fns = {o.function_fp: o for o in analysis.native_api_observations if o.function_fp}

    starts = [j for j in analysis.native_deep_jni_bindings
              if (from_query.lower() in (j.java_method or "").lower()
                  or from_query.lower() in (j.java_class or "").lower())]
    paths: list[dict] = []
    started = time.monotonic()
    for j in starts:
        if len(paths) >= max_paths:
            break
        head = [{"kind": "JNI", "label": f"{j.java_class}.{j.java_method}", "state": j.state}]
        if j.state != "RESOLVED" or not j.native_function_fp:
            head.append({"kind": "NATIVE", "label": UNKNOWN_NATIVE_TARGET, "state": "UNKNOWN"})
            paths.append({"nodes": head, "status": "UNKNOWN", "boundary": UNKNOWN_NATIVE_TARGET})
            continue
        for chain in _bfs_native(adjacency, j.native_function_fp, fn_by_fp, api_fns, to_query, max_depth,
                                 max_paths - len(paths), started):
            paths.append({"nodes": head + chain["nodes"], "status": chain["status"],
                          "boundary": chain.get("boundary")})
    return {"from": from_query, "to": to_query, "paths": paths, "count": len(paths),
            "bounds": {"max_depth": max_depth, "max_paths": max_paths},
            "note": "Uncertainty boundaries (UNKNOWN_NATIVE_TARGET) are preserved as valid endpoints; "
                    "no native reachability is fabricated."}


def _bfs_native(adjacency, start_fp, fn_by_fp, api_fns, to_query, max_depth, limit, started) -> list[dict]:
    out: list[dict] = []
    start_fn = fn_by_fp.get(start_fp)
    queue = deque([(start_fp, [{"kind": "NATIVE", "label": start_fn.name if start_fn else start_fp,
                                "state": "RESOLVED"}])])
    visited = {start_fp}
    while queue and len(out) < limit:
        if time.monotonic() - started > settings.graph_query_timeout_seconds:
            break
        node, path = queue.popleft()
        if node in api_fns:
            o = api_fns[node]
            if not to_query or to_query.lower() in o.api.lower():
                out.append({"nodes": path + [{"kind": "NATIVE_API", "label": o.api, "state": "REACHABLE"}],
                            "status": "REACHABLE"})
            continue
        if len(path) > max_depth:
            continue
        for dst_fp, dst_name in adjacency.get(node, []):
            if dst_fp == "UNKNOWN":
                out.append({"nodes": path + [{"kind": "NATIVE", "label": UNKNOWN_NATIVE_TARGET, "state": "UNKNOWN"}],
                            "status": "UNKNOWN", "boundary": UNKNOWN_NATIVE_TARGET})
                continue
            if dst_fp in visited:
                continue
            visited.add(dst_fp)
            dfn = fn_by_fp.get(dst_fp)
            queue.append((dst_fp, path + [{"kind": "NATIVE", "label": dfn.name if dfn else dst_name,
                                           "state": "RESOLVED"}]))
    return out


def native_cve_signatures(analysis) -> list[dict]:
    """Correlate provider-supplied native CVE signatures against native functions.
    States MATCHED / PARTIAL_MATCH / UNRESOLVED_TARGET / NOT_MATCHED / UNKNOWN.
    NEVER converts a signature match into AFFECTED or exploitability."""
    out: list[dict] = []
    fn_names = {f.normalized_name.lower() for f in analysis.native_deep_functions}
    resolved_jni = any(j.state == "RESOLVED" for j in analysis.native_deep_jni_bindings)
    reached = {o.api for o in analysis.native_api_observations if o.state == API_REACHED}
    for m in analysis.vulnerability_matches:
        vuln = getattr(m, "vulnerability", None)
        if vuln is None:
            continue
        for sig in vuln.signatures:
            if sig.kind not in ("NATIVE_SYMBOL", "JNI") or not sig.native_symbol:
                continue
            sym = _normalize_name(sig.native_symbol).lower()
            present = sym in fn_names
            if present and sym in {a.lower() for a in reached}:
                state = "MATCHED"
            elif present and resolved_jni:
                state = "PARTIAL_MATCH"
            elif present:
                state = "PARTIAL_MATCH"
            elif not analysis.native_deep_jni_bindings:
                state = "UNKNOWN"
            elif any(j.state == "UNKNOWN" for j in analysis.native_deep_jni_bindings):
                state = "UNRESOLVED_TARGET"
            else:
                state = "NOT_MATCHED"
            out.append({"cve_id": m.cve_id, "native_symbol": sig.native_symbol, "state": state,
                        "version_state": m.version_state, "note": "signature correlation never changes CVE state"})
    return out


def native_deep_from_diff(comparison) -> dict:
    """A→B deep-native diff by stable content-derived fingerprints. Address
    changes are metadata, not removal. Conservative security impact."""
    a, b = comparison.baseline, comparison.candidate
    va, vb = native_deep_view(a), native_deep_view(b)

    def idx(v, key, id_key="id"):
        return {x[id_key]: x for x in v[key]}

    changes = []
    for key, kind in (("functions", "native_function"), ("jni_bindings", "jni_binding"),
                      ("api_observations", "native_api")):
        ai, bi = idx(va, key), idx(vb, key)
        for fp in sorted(set(ai) - set(bi)):
            changes.append({"kind": kind, "change": "REMOVED", "id": fp, "status": "NO_LONGER_DETECTED",
                            "detail": ai[fp].get("name") or ai[fp].get("api") or ai[fp].get("java_method")})
        for fp in sorted(set(bi) - set(ai)):
            item = bi[fp]
            sec = kind == "native_api" and item.get("state") == API_REACHED
            changes.append({"kind": kind, "change": "ADDED", "id": fp,
                            "status": "NEW_NATIVE_PATH" if sec else "ADDED", "security_relevant": sec,
                            "detail": item.get("name") or item.get("api") or item.get("java_method")})
    new_reached = any(c.get("security_relevant") for c in changes)
    security_impact = "SECURITY_REGRESSION" if new_reached else "INCONCLUSIVE" if changes else "NO_MATERIAL_CHANGE"
    from collections import Counter
    return {"baseline_fingerprint": va["fingerprint"], "candidate_fingerprint": vb["fingerprint"],
            "changes": changes, "summary": dict(Counter(c["change"] for c in changes)),
            "security_impact": security_impact,
            "note": "A removed native function is NO_LONGER_DETECTED, never automatically FIXED; unresolved changes "
                    "are INCONCLUSIVE. Only a confirmed new reachable native API path (positive evidence) may "
                    "contribute to SECURITY_REGRESSION. Nothing is exploitable."}

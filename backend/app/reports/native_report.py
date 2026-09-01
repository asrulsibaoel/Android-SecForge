"""Deep native / Ghidra report + export (prompt 20): JSON and Markdown.

Renders persisted native-deep evidence. Distinguishes PRESENT / RESOLVED /
REACHABLE / UNKNOWN; preserves UNKNOWN_NATIVE_TARGET; never asserts exploitability.
"""

from __future__ import annotations

import json

from app.native import deep_native as D


def native_deep_section(analysis) -> dict:
    view = D.native_deep_view(analysis)
    return {
        "capability": view["capability"],
        "summary": view["summary"],
        "binaries": view["binaries"],
        "functions": view["functions"],
        "symbols": [{"name": s.name, "kind": s.kind, "source": s.source} for s in analysis.native_deep_symbols][:1000],
        "imports": [f["name"] for f in view["functions"] if f["is_imported"]][:1000],
        "exports": [f["name"] for f in view["functions"] if f["is_exported"]][:1000],
        "jni_bindings": view["jni_bindings"],
        "call_edges": view["call_edges"],
        "api_paths": view["api_observations"],
        "cve_signatures": D.native_cve_signatures(analysis),
        "evidence": [{"subject": e.subject_fp, "source_type": e.source_type, "detail": e.detail,
                      "confidence": e.confidence} for e in analysis.native_deep_evidence][:500],
        "uncertainties": view["uncertainties"],
        "fingerprint": view["fingerprint"],
        "note": view["note"],
    }


def native_markdown(analysis) -> str:
    view = D.native_deep_view(analysis)
    s = view["summary"]
    manifest = analysis.manifest
    L: list[str] = []
    a = L.append
    a("# Deep native / Ghidra report")
    a("")
    a(f"- APK sha256: `{analysis.apk_sha256}`")
    if manifest and manifest.package:
        a(f"- Package: `{manifest.package}`")
    a(f"- Mode: **{view['capability']['mode']}**  ·  Ghidra: **{view['capability']['ghidra']}**")
    a(f"- Fingerprint: `{view['fingerprint']}`")
    a("")
    a("## Native analysis summary")
    a("")
    a(f"- binaries={s['binaries']} functions={s['functions']} jni_bindings={s['jni_bindings']} "
      f"call_edges={s['call_edges']} api_observations={s['api_observations']}")
    a(f"- resolved_jni={s['resolved_jni']} unresolved_jni={s['unresolved_jni']} "
      f"unresolved_targets={s['unresolved_targets']}")
    a(f"- function types: {s['by_function_type']}")
    a("")
    a("## JNI bridge summary")
    a("")
    if not view["jni_bindings"]:
        a("_None._")
    for j in view["jni_bindings"][:80]:
        a(f"- {j['java_class']}.{j['java_method']} → {j['native_symbol'] or j['native_target']} "
          f"[{j['registration_type']}/{j['state']}]")
    a("")
    a("## Resolved native paths")
    a("")
    reached = [o for o in view["api_observations"] if o["state"] == D.API_REACHED]
    if not reached:
        a("_None (native reachability requires Ghidra call-graph evidence)._")
    for o in reached[:60]:
        a(f"- native API {o['api']} ({o['category']}) REACHABLE via call chain")
    a("")
    a("## Unresolved native paths")
    a("")
    unresolved = [j for j in view["jni_bindings"] if j["state"] == "UNKNOWN"]
    if not unresolved:
        a("_None._")
    for j in unresolved[:60]:
        a(f"- {j['java_class']}.{j['java_method']} → UNKNOWN_NATIVE_TARGET")
    a("")
    a("## Security-relevant API observations")
    a("")
    for o in [o for o in view["api_observations"] if o["state"] in (D.API_PRESENT, D.API_REACHED)][:80]:
        a(f"- {o['api']} ({o['category']}) [{o['state']}] source={o['source']}")
    a("")
    a("## Provenance")
    a("")
    from collections import Counter
    a(f"- evidence sources: {dict(Counter(e.source_type for e in analysis.native_deep_evidence))}")
    a("")
    a("## Limitations")
    a("")
    for u in view["uncertainties"]:
        a(f"- {u}")
    a("- A native function present is not reachable from Java; a JNI export is not necessarily invoked; a "
      "dangerous native API present is not a vulnerability. No exploitability is asserted.")
    a("")
    return "\n".join(L)


def export_native(analysis, fmt: str = "json") -> str:
    fmt = (fmt or "json").lower()
    if fmt == "json":
        return json.dumps(native_deep_section(analysis), indent=2, default=str)
    if fmt in ("markdown", "md"):
        return native_markdown(analysis)
    raise ValueError(f"unsupported native export format: {fmt}")

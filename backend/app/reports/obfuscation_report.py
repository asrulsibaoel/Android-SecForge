"""Obfuscation report + export (prompt 19): JSON and Markdown.

Renders the deterministic in-memory obfuscation view. Every observation exposes
evidence and confidence; the score describes analysis complexity (not severity);
UNKNOWN / UNKNOWN_NATIVE_TARGET are preserved; nothing asserts exploitability.
"""

from __future__ import annotations

import json

from app.analysis import obfuscation as O


def obfuscation_section(analysis) -> dict:
    view = O.obfuscation_view(analysis)
    return {
        "summary": view["summary"],
        "score": view["score"],
        "observations": view["observations"],
        "anti_analysis": view["anti_analysis"],
        "analysis_impacts": view["analysis_impacts"],
        "uncertainties": view["uncertainties"],
        "recommended_review": view["recommended_review"],
        "provenance": {"fingerprint": view["fingerprint"], "weights": O.OBFUSCATION_WEIGHTS,
                       "penalties": O.OBFUSCATION_PENALTIES},
        "note": view["note"],
    }


def obfuscation_markdown(analysis) -> str:
    view = O.obfuscation_view(analysis)
    s = view["summary"]
    manifest = analysis.manifest
    L: list[str] = []
    a = L.append
    a("# Obfuscation & anti-analysis report")
    a("")
    a(f"- APK sha256: `{analysis.apk_sha256}`")
    if manifest and manifest.package:
        a(f"- Package: `{manifest.package}`")
    a(f"- Fingerprint: `{view['fingerprint']}`")
    a("")
    a("## 1. Summary")
    a("")
    a(f"- Observations: {s['observations']}  ·  anti-analysis indicators: {s['anti_analysis_indicators']}  ·  "
      f"analysis impacts: {s['analysis_impacts']}")
    a(f"- By category: {s['by_category']}")
    a(f"- Availability: {s['availability']}")
    a("")
    a("## 2. Obfuscation score")
    a("")
    a(f"- **{view['score']['score']}/100 ({view['score']['band']})** — {view['score']['note']}")
    a(f"- Factors: " + ", ".join(f"{f['name']}(+{f['weight']})" for f in view["score"]["factors"]))
    if view["score"]["penalties"]:
        a(f"- Penalties: " + ", ".join(f"{p['name']}(-{p['weight']})" for p in view["score"]["penalties"]))
    a("")

    def obs_section(title, category):
        a(f"## {title}")
        a("")
        rows = [o for o in view["observations"] if o["category"] == category]
        if not rows:
            a(f"_None ({s['availability'].get(_avail_key(category), 'UNKNOWN')})._")
        for o in rows:
            a(f"- [{o['state']}] {o['indicator']} (confidence {o['confidence']}, {o['source_type']}) "
              f"target={o['target'] or 'APK'} [`{o['id'][:12]}`]")
        a("")

    obs_section("3. Identifier analysis", O.CAT_IDENTIFIER)
    obs_section("4. String analysis", O.CAT_STRING)
    obs_section("5. Control-flow indicators", O.CAT_CONTROL_FLOW)
    obs_section("6. Reflection / dynamic resolution", O.CAT_DYNAMIC_RESOLUTION)
    obs_section("7. Native indirection", O.CAT_NATIVE_INDIRECTION)

    a("## 8. Anti-analysis indicators")
    a("")
    if not view["anti_analysis"]:
        a("_None._")
    for i in view["anti_analysis"]:
        a(f"- [{i['evidence_level']}] {i['category']} — `{i['indicator']}` (confidence {i['confidence']}, "
          f"{i['source_type']}) [`{i['id'][:12]}`]")
    a("")
    a("> Presence of a name/API is an INDICATOR only, not active anti-analysis behavior; anti-analysis is not "
      "proof of maliciousness.")
    a("")

    a("## 9. Analytical impact")
    a("")
    if not view["analysis_impacts"]:
        a("_None._")
    for i in view["analysis_impacts"]:
        a(f"- {i['impact_category']}: {i['description']} (confidence {i['confidence']})")
    a("")

    a("## 10. Uncertainties")
    a("")
    if not view["uncertainties"]:
        a("_None recorded._")
    for u in view["uncertainties"]:
        a(f"- {u}")
    a("")

    a("## 11. Evidence")
    a("")
    for o in view["observations"][:60]:
        a(f"- `{o['id'][:12]}` {o['finding_type']} {o['category']}: {json.dumps(o['evidence_json'])[:160]}")
    a("")

    a("## 12. Recommended review areas")
    a("")
    if not view["recommended_review"]:
        a("_None._")
    for r in view["recommended_review"]:
        a(f"- {r['action']} — {r['reason']}")
    a("")
    return "\n".join(L)


def _avail_key(category: str) -> str:
    return {O.CAT_IDENTIFIER: "identifier", O.CAT_STRING: "string", O.CAT_CONTROL_FLOW: "control_flow",
            O.CAT_DYNAMIC_RESOLUTION: "dynamic_resolution", O.CAT_NATIVE_INDIRECTION: "native"}.get(category, "")


def export_obfuscation(analysis, fmt: str = "json") -> str:
    fmt = (fmt or "json").lower()
    if fmt == "json":
        return json.dumps(obfuscation_section(analysis), indent=2, default=str)
    if fmt in ("markdown", "md"):
        return obfuscation_markdown(analysis)
    raise ValueError(f"unsupported obfuscation export format: {fmt}")

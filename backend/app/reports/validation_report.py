"""Validation report + export (prompt 18): JSON and Markdown.

Renders the deterministic in-memory validation view. Every claim links to its
evidence families, blockers, and requirements; uncertainties are preserved;
nothing asserts exploitability.
"""

from __future__ import annotations

import json

from app.analysis import validation as V

_STATE_ORDER = {"MULTI_SOURCE_CORROBORATED": 0, "RUNTIME_CORROBORATED": 1, "STATIC_SUPPORTED": 2,
                "INCONCLUSIVE": 3, "VALIDATION_BLOCKED": 4, "UNVERIFIED": 5, "NOT_APPLICABLE": 6, "SUPERSEDED": 7}


def validation_section(analysis) -> dict:
    view = V.validation_view(analysis)
    return {
        "summary": view["summary"],
        "claims": view["claims"],
        "evidence": [{"claim": c["id"], **e} for c in view["claims"] for e in c["evidence"]],
        "blockers": view["blockers"],
        "requirements": view["requirements"],
        "transitions": [],  # populated for diff-based validation via /diff endpoints
        "uncertainties": view["uncertainties"],
        "provenance": {"fingerprint": view["fingerprint"],
                       "weights": V.VALIDATION_WEIGHTS, "penalties": V.VALIDATION_PENALTIES},
        "note": view["note"],
    }


def validation_markdown(analysis) -> str:
    view = V.validation_view(analysis)
    s = view["summary"]
    L: list[str] = []
    a = L.append
    manifest = analysis.manifest
    a("# Security validation report")
    a("")
    a(f"- APK sha256: `{analysis.apk_sha256}`")
    if manifest and manifest.package:
        a(f"- Package: `{manifest.package}`")
    a(f"- Validation fingerprint: `{view['fingerprint']}`")
    a(f"- Claims: {s['total']}  ·  states {s['by_state']}")
    a(f"- Live runtime validation: **{s['live_runtime_validation']}**")
    a("")
    a("> Validation reflects evidence quality and verification state only — never exploitability. "
      "UNKNOWN / NOT_REACHABLE / NOT_OBSERVED / POSSIBLY_AFFECTED are preserved.")
    a("")

    def section(title, states):
        a(f"## {title}")
        a("")
        rows = [c for c in view["claims"] if c["validation_state"] in states]
        if not rows:
            a("_None._")
        for c in sorted(rows, key=lambda c: (-c["confidence"], c["claim_type"])):
            a(f"- **{c['claim_type']}** — {c['target'] or '-'} "
              f"(confidence {c['confidence']}/100, {c['independent_source_count']} independent families: "
              f"{', '.join(c['source_families']) or 'none'}) [`{c['id'][:12]}`]")
        a("")

    a("## Validation summary")
    a("")
    a(f"- static_supported={s['static_supported']} multi_source={s['multi_source']} "
      f"runtime_corroborated={s['runtime_corroborated']} unverified={s['unverified']} blocked={s['blocked']}")
    a("")
    section("Static-supported / multi-source claims", {"STATIC_SUPPORTED", "MULTI_SOURCE_CORROBORATED"})
    section("Runtime-corroborated claims", {"RUNTIME_CORROBORATED"})
    section("Unverified claims", {"UNVERIFIED"})

    a("## Blockers")
    a("")
    if not view["blockers"]:
        a("_None._")
    for b in view["blockers"]:
        a(f"- `{b['blocker']}` — {b['reason']} (missing: {b['missing']})")
    a("")

    a("## Evidence requirements")
    a("")
    unmet = [r for r in view["requirements"] if not r["satisfied"]]
    if not unmet:
        a("_All checked requirements satisfied._")
    for r in unmet[:80]:
        a(f"- {r['requirement']} — unsatisfied ({r['detail']})")
    a("")

    a("## Finding validation")
    a("")
    for f in analysis.findings:
        st = getattr(f, "security_validation_state", "UNVERIFIED")
        if st == "UNVERIFIED" and getattr(f, "validation_claim_count", 0) == 0:
            continue
        a(f"- `{f.rule_id}` @ {f.component or '-'}: {st} "
          f"(confidence {getattr(f, 'validation_confidence', 0)}, "
          f"{getattr(f, 'validation_claim_count', 0)} claim(s))")
    a("")

    a("## Uncertainties")
    a("")
    if not view["uncertainties"]:
        a("_None recorded._")
    for u in view["uncertainties"]:
        a(f"- {u}")
    a("")
    return "\n".join(L)


def export_validation(analysis, fmt: str = "json") -> str:
    fmt = (fmt or "json").lower()
    if fmt == "json":
        return json.dumps(validation_section(analysis), indent=2, default=str)
    if fmt in ("markdown", "md"):
        return validation_markdown(analysis)
    raise ValueError(f"unsupported validation export format: {fmt}")

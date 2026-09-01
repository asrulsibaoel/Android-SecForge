"""Remediation report + export (prompt 17): JSON and Markdown.

Renders the deterministic in-memory remediation plan. Every recommendation links
to its evidence; uncertainties are preserved; nothing asserts exploitability.
"""

from __future__ import annotations

import json

from app.analysis import remediation as R

_PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNDETERMINED": 5}


def remediation_section(analysis) -> dict:
    """The `remediation` section embedded in the analysis JSON report."""
    view = R.plan_view(analysis)
    return {
        "summary": view["summary"],
        "priority_distribution": view["priority_distribution"],
        "items": view["items"],
        "actions": [{"item": i["id"], **a} for i in view["items"] for a in i["actions"]],
        "evidence": [{"item": i["id"], **e} for i in view["items"] for e in i["evidence"]],
        "dependencies": view["dependencies"],
        "uncertainties": view["uncertainties"],
        "note": view["note"],
    }


def remediation_markdown(analysis) -> str:
    view = R.plan_view(analysis)
    manifest = analysis.manifest
    L: list[str] = []
    a = L.append
    a("# Remediation plan")
    a("")
    a(f"- APK sha256: `{analysis.apk_sha256}`")
    if manifest and manifest.package:
        a(f"- Package: `{manifest.package}`")
    a(f"- Plan fingerprint: `{view['fingerprint']}`")
    s = view["summary"]
    a(f"- Items: {s['total']}  ·  priority {s['by_priority']}")
    a("")
    a("> Remediation priority is a separate axis from risk. No item asserts exploitability; "
      "UNKNOWN / POSSIBLY_AFFECTED / NOT_REACHABLE / NOT_OBSERVED are preserved.")
    a("")
    a("## Recommendations")
    a("")
    if not view["items"]:
        a("_No remediation items._")
    for it in sorted(view["items"], key=lambda i: (_PRIORITY_ORDER.get(i["priority"], 9), -i["priority_score"])):
        a(f"### [{it['priority']}] {it['action']} — {it['target'] or '-'}")
        a("")
        a(f"- Status: **{it['status']}**  ·  fixability: **{it['fixability']}**  ·  "
          f"priority score: {it['priority_score']}  ·  confidence: {it['confidence']}")
        a(f"- Current: {it['current_state'] or '-'}")
        if it["recommended_state"]:
            a(f"- Recommended: {it['recommended_state']}")
        a(f"- {it['description']}")
        a("- Evidence:")
        for e in it["evidence"]:
            a(f"  - ({e['source_type']}) {e['detail']} [`{e.get('source_id') or '-'}`]")
        if it["uncertainties"]:
            a("- Uncertainties:")
            for u in it["uncertainties"]:
                a(f"  - {u}")
        a("- Priority factors: " + ", ".join(f"{f['name']}(+{f['weight']})" for f in it["priority_factors"]))
        a("")
    if view["uncertainties"]:
        a("## Uncertainties")
        a("")
        for u in view["uncertainties"]:
            a(f"- {u}")
        a("")
    return "\n".join(L)


def export_remediation(analysis, fmt: str = "json") -> str:
    fmt = (fmt or "json").lower()
    if fmt == "json":
        return json.dumps(remediation_section(analysis), indent=2, default=str)
    if fmt in ("markdown", "md"):
        return remediation_markdown(analysis)
    raise ValueError(f"unsupported remediation export format: {fmt}")

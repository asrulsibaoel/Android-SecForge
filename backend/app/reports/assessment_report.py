"""Assessment / decision-intelligence report (prompt 24): JSON + Markdown.

Renders the deterministic decision synthesis. Decision states express evidentiary
strength, never exploitability, and are never collapsed into SAFE/UNSAFE.
"""

from __future__ import annotations

import json

from app.assessment import engine as E
from app.assessment import taxonomy as T


def assessment_section(analysis) -> dict:
    """In-memory view for the JSON report. If no assessment is persisted yet, the
    view returns an honest empty/INCONCLUSIVE shape (never invented conclusions)."""
    return E.assessment_view(analysis)


def assessment_markdown(analysis) -> str:
    view = E.assessment_view(analysis)
    manifest = analysis.manifest
    L: list[str] = []
    a = L.append
    a("# Security assessment & decision intelligence")
    a("")
    a(f"- APK sha256: `{analysis.apk_sha256}`")
    if manifest and manifest.package:
        a(f"- Package: `{manifest.package}`")
    a(f"- Overall: **{view['status']}**")
    a(f"- Fingerprint: `{view['fingerprint']}`")
    a("")
    a("## Summary")
    a("")
    summ = view.get("summary", {})
    a(f"- conclusions={summ.get('conclusions', 0)} open={summ.get('open', 0)} blockers={summ.get('blockers', 0)}")
    a(f"- by decision state: {summ.get('by_decision_state', {})}")
    a("")
    a("## Conclusions")
    a("")
    if not view["conclusions"]:
        a("_No conclusions (no persisted assessment)._")
    for c in view["conclusions"][:200]:
        a(f"- **{c['decision_state']}** · {c['conclusion_type']} · {c['subject_type']} "
          f"`{c['subject_ref'][:48]}` — {c['rationale']}  \n  _rule {c['rule_id']}_"
          + ("".join(f"  \n  ⚠ blocker: {b['blocker']} — {b['reason']}" for b in c["blockers"])))
    a("")
    a("## Uncertainty & rules")
    a("")
    a("Decision states are evidentiary strength, not exploitability. "
      "POSSIBLY_AFFECTED ≠ AFFECTED · NOT_OBSERVED/NOT_REACHABLE ≠ safe · MOCKED ≠ LIVE · "
      "UNKNOWN_NATIVE_TARGET preserved. Every conclusion references existing evidence and mutates nothing.")
    a("")
    a("## Decision-state legend")
    a("")
    for s in T.DECISION_STATES:
        a(f"- `{s}`")
    a("")
    return "\n".join(L)


def export_assessment(analysis, fmt: str = "json") -> str:
    fmt = (fmt or "json").lower()
    if fmt == "json":
        return json.dumps(assessment_section(analysis), indent=2, default=str)
    if fmt in ("markdown", "md"):
        return assessment_markdown(analysis)
    raise ValueError(f"unsupported assessment export format: {fmt}")

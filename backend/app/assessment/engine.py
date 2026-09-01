"""Deterministic decision engine (prompt 24 §3).

Synthesizes persisted evidence from every prior layer into explicit, inspectable
security conclusions. Every rule below is documented and deterministic — no ML, no
hidden weights, no opaque multipliers, no "risk of exploit". Every conclusion
references existing IDs / fingerprints (it never duplicates a canonical record and
never mutates one). It produces decision states, never SAFE/UNSAFE, and never an
`exploitable` judgement.

Rule ids are stable strings so a reader can trace exactly which rule produced a
conclusion (see ``rule_id`` on each conclusion).
"""

from __future__ import annotations

import hashlib
from collections import Counter

from app.core.config import settings
from app.models.assessment import (
    Assessment, AssessmentSubject, AssessmentSummary, DecisionBlocker, DecisionDependency,
    DecisionEvidence, DecisionRequirement, SecurityConclusion,
)
from app.assessment import taxonomy as T


def _fp(*parts) -> str:
    return hashlib.sha256("|".join("" if p is None else str(p) for p in parts).encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_assessment(db, analysis, requested_by: str = "cli") -> Assessment:
    """Build + persist a deterministic assessment. Idempotent (prior assessments
    cleared and rebuilt); a pure projection over persisted evidence."""
    analysis.assessments.clear()
    db.flush()

    a = Assessment(analysis_id=analysis.id, fingerprint="", status=T.ASSESSMENT_INCONCLUSIVE,
                   requested_by=requested_by, truncated={}, summary={})
    analysis.assessments.append(a)
    db.flush()

    ctx = _Ctx(a)
    _assess_findings(analysis, ctx)
    _assess_cve(analysis, ctx)
    _assess_runtime(analysis, ctx)
    _assess_native(analysis, ctx)
    _assess_remediation(analysis, ctx)
    _assess_overall(analysis, ctx)

    # deterministic content fingerprint (no db ids / timestamps)
    a.fingerprint = _fp("ASSESS", analysis.apk_sha256, *sorted(c.fingerprint for c in a.conclusions))
    a.subject_count = len(a.subjects)
    a.conclusion_count = len(a.conclusions)
    a.open_count = sum(1 for c in a.conclusions if c.decision_state in T.OPEN_STATES)
    a.blocker_count = sum(len(c.blockers) for c in a.conclusions)
    a.status = ctx.overall_status
    a.truncated = ctx.truncated
    # persisted summaries
    for dim, counts in (("by_decision_state", Counter(c.decision_state for c in a.conclusions)),
                        ("by_conclusion_type", Counter(c.conclusion_type for c in a.conclusions)),
                        ("by_subject_type", Counter(c.subject_type for c in a.conclusions))):
        a.summaries.append(AssessmentSummary(dimension=dim, counts=dict(counts)))
    a.summary = {"by_decision_state": dict(Counter(c.decision_state for c in a.conclusions)),
                 "by_conclusion_type": dict(Counter(c.conclusion_type for c in a.conclusions)),
                 "subjects": len(a.subjects), "conclusions": len(a.conclusions),
                 "open": a.open_count, "blockers": a.blocker_count}
    db.flush()
    return a


class _Ctx:
    def __init__(self, assessment: Assessment):
        self.a = assessment
        self.truncated: dict = {}
        self.overall_status = T.ASSESSMENT_INCONCLUSIVE
        self._subject_keys: set[str] = set()

    def subject(self, subject_type: str, subject_ref: str, label: str) -> None:
        key = f"{subject_type}:{subject_ref}"
        if key in self._subject_keys:
            return
        if len(self.a.subjects) >= settings.assessment_max_subjects:
            self.truncated["subjects"] = self.truncated.get("subjects", 0) + 1
            return
        self._subject_keys.add(key)
        self.a.subjects.append(AssessmentSubject(
            fingerprint=_fp("SUBJ", subject_type, subject_ref), subject_type=subject_type,
            subject_ref=subject_ref, label=label[:512]))

    def conclude(self, subject_type, subject_ref, conclusion_type, decision_state, rule_id, rationale,
                 evidence, confidence="MEDIUM", blockers=None, requirements=None, dependencies=None):
        if len(self.a.conclusions) >= settings.assessment_max_conclusions:
            self.truncated["conclusions"] = self.truncated.get("conclusions", 0) + 1
            return None
        ev_refs = sorted(f"{e[0]}:{e[1]}" for e in evidence)
        c = SecurityConclusion(
            fingerprint=_fp("CONC", subject_type, subject_ref, conclusion_type, decision_state, *ev_refs),
            subject_type=subject_type, subject_ref=subject_ref, conclusion_type=conclusion_type,
            decision_state=decision_state, confidence=confidence, rule_id=rule_id, rationale=rationale[:2000])
        self.a.conclusions.append(c)
        cap = settings.assessment_max_evidence_per_conclusion
        for i, (layer, ref, mode, provenance, detail) in enumerate(evidence):
            if i >= cap:
                self.truncated["evidence"] = self.truncated.get("evidence", 0) + 1
                break
            c.evidence.append(DecisionEvidence(source_layer=layer, evidence_ref=str(ref), mode=mode,
                                               provenance=provenance, detail=(detail or "")[:2000]))
        for b in (blockers or []):
            c.blockers.append(DecisionBlocker(blocker=b[0], reason=b[1], missing=b[2] if len(b) > 2 else ""))
        for r in (requirements or []):
            c.requirements.append(DecisionRequirement(requirement=r[0], satisfied=r[1],
                                                      detail=r[2] if len(r) > 2 else ""))
        for d in (dependencies or []):
            c.dependencies.append(DecisionDependency(depends_on=d[0], dependency_type=d[1] if len(d) > 1 else "CONCLUSION",
                                                     detail=d[2] if len(d) > 2 else ""))
        return c


# ---------------------------------------------------------------------------
# Finding conclusions
# ---------------------------------------------------------------------------


def _assess_findings(analysis, ctx) -> None:
    for f in analysis.findings:
        ref = str(f.id)
        ctx.subject(T.SUBJECT_FINDING, ref, f"{f.rule_id}: {f.title or ''}")
        svs = getattr(f, "security_validation_state", "UNVERIFIED") or "UNVERIFIED"
        rvs = getattr(f, "runtime_validation_state", "LIVE_UNAVAILABLE") or "LIVE_UNAVAILABLE"
        base_ev = [(T.LAYER_FINDINGS, f.fingerprint or f.rule_id, T.MODE_STATIC, "STATIC",
                    f"finding {f.rule_id} [{f.severity}/{f.confidence}] status={f.status}")]
        val_ev = base_ev + [(T.LAYER_VALIDATION, f.fingerprint or f.rule_id, T.MODE_STATIC, "VALIDATION",
                             f"security_validation_state={svs}")]

        if getattr(f, "is_duplicate", False):
            ctx.conclude(T.SUBJECT_FINDING, ref, T.FINDING_INCONCLUSIVE, T.SUPERSEDED, "R-FIND-DUP",
                         "finding is a duplicate of another (superseded).", base_ev, confidence=f.confidence)
            continue
        if f.status == "CONFIRMED_BY_STATIC_ANALYSIS":
            ctx.conclude(T.SUBJECT_FINDING, ref, T.FINDING_CONFIRMED, T.CONFIRMED, "R-FIND-STATIC-CONFIRMED",
                         "finding confirmed by static analysis.", base_ev, confidence="HIGH")
            continue
        if rvs == "CONFIRMED_RUNTIME_BEHAVIOR" or svs in ("MULTI_SOURCE_CORROBORATED",):
            ev = val_ev + [(T.LAYER_RUNTIME, ref, T.MODE_LIVE, "RUNTIME_ADB",
                            f"runtime_validation_state={rvs}")]
            ctx.conclude(T.SUBJECT_FINDING, ref, T.FINDING_SUPPORTED, T.STRONGLY_SUPPORTED, "R-FIND-MULTI",
                         "finding corroborated by multiple independent evidence families (incl. LIVE runtime).",
                         ev, confidence="HIGH")
            continue
        if svs == "RUNTIME_CORROBORATED":
            ev = val_ev + [(T.LAYER_RUNTIME, ref, T.MODE_LIVE, "RUNTIME_ADB", f"runtime_validation_state={rvs}")]
            ctx.conclude(T.SUBJECT_FINDING, ref, T.FINDING_SUPPORTED, T.STRONGLY_SUPPORTED, "R-FIND-RUNTIME",
                         "finding corroborated by LIVE runtime evidence.", ev, confidence="HIGH")
            continue
        if svs == "STATIC_SUPPORTED":
            ctx.conclude(T.SUBJECT_FINDING, ref, T.FINDING_SUPPORTED, T.SUPPORTED, "R-FIND-STATIC-SUPPORTED",
                         "finding supported by static validation evidence.", val_ev, confidence=f.confidence)
            continue
        if svs == "VALIDATION_BLOCKED":
            ctx.conclude(T.SUBJECT_FINDING, ref, T.FINDING_BLOCKED, T.BLOCKED, "R-FIND-BLOCKED",
                         "finding validation is blocked — a required capability/evidence is missing.", val_ev,
                         confidence=f.confidence,
                         blockers=[("VALIDATION_BLOCKED", "validation reports a hard blocker", "supporting evidence")])
            continue
        if svs in ("UNVERIFIED", "INCONCLUSIVE") and f.status in ("POTENTIAL", "REVIEW_REQUIRED", None):
            ctx.conclude(T.SUBJECT_FINDING, ref, T.FINDING_UNVERIFIED, T.UNVERIFIED, "R-FIND-UNVERIFIED",
                         "finding is not yet verified by independent evidence (NOT a safety verdict).", val_ev,
                         confidence=f.confidence,
                         requirements=[("independent_evidence", False, "needs static/runtime corroboration")])
            continue
        ctx.conclude(T.SUBJECT_FINDING, ref, T.FINDING_INCONCLUSIVE, T.INCONCLUSIVE, "R-FIND-INCONCLUSIVE",
                     "available evidence is insufficient to reach a stronger conclusion.", val_ev,
                     confidence=f.confidence)


# ---------------------------------------------------------------------------
# CVE conclusions
# ---------------------------------------------------------------------------


def _assess_cve(analysis, ctx) -> None:
    for m in analysis.vulnerability_matches:
        ref = f"{m.cve_id}:{getattr(m.dependency, 'name', '') if getattr(m, 'dependency', None) else ''}"
        ctx.subject(T.SUBJECT_CVE, ref, f"{m.cve_id}")
        version = (m.version_state or "UNKNOWN").upper()
        reach = (getattr(m, "reachability_state", None) or "UNKNOWN").upper()
        identity = (getattr(m, "identity_confidence", None) or "UNKNOWN").upper()
        ev = [(T.LAYER_CVE, m.cve_id, T.MODE_STATIC, "VULNERABILITY_DATABASE",
               f"version_state={version} reachability={reach} identity={identity}")]

        if version == "NOT_AFFECTED":
            ctx.conclude(T.SUBJECT_CVE, ref, T.CVE_NOT_AFFECTED, T.NOT_APPLICABLE, "R-CVE-NOT-AFFECTED",
                         "installed version is outside the affected range.", ev, confidence="HIGH")
            continue
        if version == "AFFECTED" and reach == "REACHABLE" and identity in ("EXACT", "HIGH"):
            ctx.conclude(T.SUBJECT_CVE, ref, T.CVE_CONFIRMED, T.STRONGLY_SUPPORTED, "R-CVE-AFFECTED-REACHABLE",
                         "affected version present with a reachable code path and strong identity — "
                         "present/affected/reachable (NOT an exploitability claim).", ev, confidence="HIGH")
            continue
        if version == "AFFECTED":
            blk = [("NOT_REACHABLE", "no reachable path proven", "reachability evidence")] if reach == "NOT_REACHABLE" else None
            ctx.conclude(T.SUBJECT_CVE, ref, T.CVE_POSSIBLY_RELEVANT, T.SUPPORTED, "R-CVE-AFFECTED",
                         "affected version present; reachability not fully established.", ev, confidence="MEDIUM",
                         blockers=blk)
            continue
        if reach == "NOT_REACHABLE":
            ctx.conclude(T.SUBJECT_CVE, ref, T.CVE_NOT_REACHABLE, T.REQUIRES_REVIEW, "R-CVE-NOT-REACHABLE",
                         "no reachable path proven — NOT_REACHABLE does not mean not-affected/safe.", ev,
                         confidence="MEDIUM")
            continue
        if version in ("POSSIBLY_AFFECTED", "PRESENT_UNKNOWN_VERSION", "UNKNOWN"):
            state = T.CONDITIONALLY_SUPPORTED if identity in ("EXACT", "HIGH") else T.UNVERIFIED
            ctx.conclude(T.SUBJECT_CVE, ref, T.CVE_VERSION_UNVERIFIED, state, "R-CVE-VERSION-UNVERIFIED",
                         "dependency present but installed version is unverified — POSSIBLY_AFFECTED is not AFFECTED.",
                         ev, confidence="MEDIUM",
                         blockers=[("MISSING_VERSION", "installed version unknown", "reliable version evidence")],
                         requirements=[("reliable_version", False, "confirm installed version")])
            continue
        ctx.conclude(T.SUBJECT_CVE, ref, T.CVE_EVIDENCE_INSUFFICIENT, T.INCONCLUSIVE, "R-CVE-INSUFFICIENT",
                     "insufficient identity/version evidence to reach a CVE conclusion.", ev, confidence="LOW")


# ---------------------------------------------------------------------------
# Runtime conclusions
# ---------------------------------------------------------------------------


def _assess_runtime(analysis, ctx) -> None:
    runs = list(analysis.runtime_validation_runs)
    if not runs:
        ctx.subject(T.SUBJECT_RUNTIME, "runtime", "runtime validation")
        # OBSERVATION_UNAVAILABLE — distinct from NO_OBSERVATION; never "safe".
        ctx.conclude(T.SUBJECT_RUNTIME, "runtime", T.RUNTIME_UNAVAILABLE, T.INCONCLUSIVE, "R-RT-UNAVAILABLE",
                     "no runtime validation run recorded — runtime observation is UNAVAILABLE (not NOT_OBSERVED).",
                     [(T.LAYER_RUNTIME, "none", T.MODE_UNAVAILABLE, "RUNTIME", "no runtime run")], confidence="LOW")
        return
    run = max(runs, key=lambda r: r.created_at)
    ref = run.fingerprint
    ctx.subject(T.SUBJECT_RUNTIME, ref, f"runtime run ({run.mode})")
    mode = (run.mode or "UNAVAILABLE").upper()
    ev = [(T.LAYER_RUNTIME, ref, mode if mode in (T.MODE_LIVE, T.MODE_MOCKED) else T.MODE_UNAVAILABLE,
           "RUNTIME_ADB" if mode == T.MODE_LIVE else "RUNTIME",
           f"mode={mode} correlations={run.correlation_count} live_claims={run.live_claim_count}")]
    if mode == T.MODE_LIVE and run.live_claim_count > 0:
        ctx.conclude(T.SUBJECT_RUNTIME, ref, T.RUNTIME_CORROBORATED, T.SUPPORTED, "R-RT-LIVE-CORROBORATED",
                     "LIVE runtime evidence corroborated observed behavior.", ev, confidence="HIGH")
    elif mode == T.MODE_LIVE:
        ctx.conclude(T.SUBJECT_RUNTIME, ref, T.RUNTIME_NOT_OBSERVED, T.REQUIRES_REVIEW, "R-RT-LIVE-NOT-OBSERVED",
                     "ran LIVE but the target behavior was not observed — NOT_OBSERVED does not mean safe.", ev,
                     confidence="MEDIUM")
    elif mode == T.MODE_MOCKED:
        ctx.conclude(T.SUBJECT_RUNTIME, ref, T.RUNTIME_MOCKED_ONLY, T.UNVERIFIED, "R-RT-MOCKED",
                     "only MOCKED runtime evidence present — MOCKED never satisfies LIVE corroboration.", ev,
                     confidence="LOW",
                     blockers=[("NO_LIVE_OBSERVATION", "no LIVE device evidence", "a LIVE runtime session")])
    else:
        ctx.conclude(T.SUBJECT_RUNTIME, ref, T.RUNTIME_UNAVAILABLE, T.INCONCLUSIVE, "R-RT-UNAVAILABLE",
                     "runtime observation UNAVAILABLE.", ev, confidence="LOW")


# ---------------------------------------------------------------------------
# Native conclusions
# ---------------------------------------------------------------------------


def _assess_native(analysis, ctx) -> None:
    from app.native.deep_native import native_deep_view, API_REACHED, API_PRESENT
    if not analysis.native_analysis_runs:
        return
    view = native_deep_view(analysis)
    cap = view["capability"]
    ref = view["fingerprint"]
    ctx.subject(T.SUBJECT_NATIVE, ref, f"native ({cap['mode']})")
    apis = analysis.native_api_observations
    reached = [o for o in apis if o.state == API_REACHED]
    present = [o for o in apis if o.state == API_PRESENT]
    unknown_targets = any(j.state == "UNKNOWN" for j in analysis.native_deep_jni_bindings)
    ev = [(T.LAYER_NATIVE, ref, T.MODE_STATIC, "GHIDRA" if cap["ghidra"] == "GHIDRA_AVAILABLE" else "ELF",
           f"mode={cap['mode']} ghidra={cap['ghidra']} api_present={len(present)} api_reached={len(reached)}")]
    blk = [("UNKNOWN_NATIVE_TARGET", "a JNI target is unresolved", "resolved native target")] if unknown_targets else None

    # runtime-observed native invocation (LIVE) upgrades to NATIVE_API_CONFIRMED
    live_native = [c for c in analysis.runtime_correlations
                   if c.subject_type in ("NATIVE_API", "NATIVE_FUNCTION") and c.mode == "LIVE"]
    if live_native:
        ev.append((T.LAYER_RUNTIME, live_native[0].fingerprint, T.MODE_LIVE, "RUNTIME_FRIDA",
                   f"{len(live_native)} LIVE native runtime invocation(s)"))
        ctx.conclude(T.SUBJECT_NATIVE, ref, T.NATIVE_API_CONFIRMED, T.SUPPORTED, "R-NAT-LIVE-INVOKED",
                     "a native API/function was invoked at runtime (LIVE).", ev, confidence="HIGH", blockers=blk)
        return
    if reached:
        ctx.conclude(T.SUBJECT_NATIVE, ref, T.NATIVE_PATH_CORROBORATED, T.SUPPORTED, "R-NAT-REACHED",
                     "a Ghidra call chain reaches a native API (static reachability corroborated).", ev,
                     confidence="MEDIUM", blockers=blk)
        return
    if cap["mode"] == "ELF_ONLY":
        ctx.conclude(T.SUBJECT_NATIVE, ref, T.NATIVE_ANALYSIS_UNAVAILABLE, T.INCONCLUSIVE, "R-NAT-ELF-ONLY",
                     "ELF-only mode — native call-chain reachability is UNAVAILABLE (Ghidra not run).", ev,
                     confidence="LOW", blockers=blk)
        return
    if present:
        ctx.conclude(T.SUBJECT_NATIVE, ref, T.NATIVE_REACHABILITY_UNVERIFIED, T.UNVERIFIED, "R-NAT-PRESENT",
                     "native APIs present but reachability from Java is unverified (presence is not reachability).",
                     ev, confidence="LOW", blockers=blk)
        return
    ctx.conclude(T.SUBJECT_NATIVE, ref, T.NATIVE_REACHABILITY_UNVERIFIED, T.INCONCLUSIVE, "R-NAT-NONE",
                 "no security-relevant native API observations.", ev, confidence="LOW", blockers=blk)


# ---------------------------------------------------------------------------
# Remediation conclusions
# ---------------------------------------------------------------------------


def _assess_remediation(analysis, ctx) -> None:
    from app.analysis.remediation import build_items
    items = build_items(analysis)  # pure, deterministic, read-only projection
    state_map = {
        "RECOMMENDED": (T.REMEDIATION_RECOMMENDED, T.SUPPORTED, "R-REM-RECOMMENDED"),
        "CONDITIONALLY_RECOMMENDED": (T.REMEDIATION_CONDITIONAL, T.CONDITIONALLY_SUPPORTED, "R-REM-CONDITIONAL"),
        "REVIEW_REQUIRED": (T.REMEDIATION_REQUIRES_REVIEW, T.REQUIRES_REVIEW, "R-REM-REVIEW"),
        "REMEDIATED": (T.REMEDIATION_REMEDIATED, T.CONFIRMED, "R-REM-REMEDIATED"),
        "VERSION_UNVERIFIED": (T.REMEDIATION_STATUS_UNVERIFIED, T.UNVERIFIED, "R-REM-VERSION-UNVERIFIED"),
    }
    for it in items:
        ref = it.fingerprint
        ctx.subject(T.SUBJECT_REMEDIATION, ref, f"{it.action}: {it.target or ''}")
        ctype, state, rule = state_map.get(it.status, (T.REMEDIATION_REQUIRES_REVIEW, T.REQUIRES_REVIEW, "R-REM-DEFAULT"))
        ev = [(T.LAYER_REMEDIATION, ref, T.MODE_STATIC, "REMEDIATION",
               f"{it.action} status={it.status} priority={it.priority} fixability={it.fixability}")]
        rationale = f"remediation item {it.action} is {it.status} (priority {it.priority}; recommendation only)."
        ctx.conclude(T.SUBJECT_REMEDIATION, ref, ctype, state, rule, rationale, ev, confidence=it.confidence)


# ---------------------------------------------------------------------------
# Assessment-level conclusions
# ---------------------------------------------------------------------------

_SECURITY_RELEVANT = {
    T.FINDING_CONFIRMED, T.FINDING_SUPPORTED, T.CVE_CONFIRMED, T.CVE_POSSIBLY_RELEVANT,
    T.RUNTIME_CORROBORATED, T.NATIVE_PATH_CORROBORATED, T.NATIVE_API_CONFIRMED,
}


def _assess_overall(analysis, ctx) -> None:
    conclusions = list(ctx.a.conclusions)
    ctx.subject(T.SUBJECT_ASSESSMENT, "ASSESSMENT", "overall assessment")
    deps = [(c.fingerprint, "CONCLUSION", c.conclusion_type) for c in conclusions]

    relevant = [c for c in conclusions if c.conclusion_type in _SECURITY_RELEVANT]
    open_conc = [c for c in conclusions if c.decision_state in T.OPEN_STATES]
    validation_incomplete = any(c.decision_state in (T.BLOCKED, T.UNVERIFIED) for c in conclusions)

    ev_present = [(T.LAYER_FINDINGS, "aggregate", T.MODE_STATIC, "ASSESSMENT",
                   f"{len(relevant)} security-relevant conclusions")]

    if relevant:
        ctx.conclude(T.SUBJECT_ASSESSMENT, "ASSESSMENT", T.SECURITY_RELEVANT_EVIDENCE_PRESENT, T.SUPPORTED,
                     "R-ASSESS-RELEVANT", "security-relevant evidence is present across the analysis.",
                     ev_present, confidence="MEDIUM", dependencies=deps[:200])

    if open_conc:
        ctx.conclude(T.SUBJECT_ASSESSMENT, "ASSESSMENT", T.SECURITY_REVIEW_REQUIRED, T.REQUIRES_REVIEW,
                     "R-ASSESS-REVIEW", f"{len(open_conc)} conclusion(s) still require human review or more evidence.",
                     [(T.LAYER_VALIDATION, "aggregate", T.MODE_STATIC, "ASSESSMENT", f"{len(open_conc)} open")],
                     confidence="MEDIUM")
        ctx.conclude(T.SUBJECT_ASSESSMENT, "ASSESSMENT", T.EVIDENCE_INCOMPLETE, T.INCONCLUSIVE, "R-ASSESS-INCOMPLETE",
                     "some evidence is still missing to settle every conclusion.",
                     [(T.LAYER_VALIDATION, "aggregate", T.MODE_STATIC, "ASSESSMENT", "evidence incomplete")],
                     confidence="LOW")
    if validation_incomplete:
        ctx.conclude(T.SUBJECT_ASSESSMENT, "ASSESSMENT", T.VALIDATION_INCOMPLETE, T.INCONCLUSIVE,
                     "R-ASSESS-VALIDATION-INCOMPLETE", "validation is incomplete for one or more subjects.",
                     [(T.LAYER_VALIDATION, "aggregate", T.MODE_STATIC, "ASSESSMENT", "validation incomplete")],
                     confidence="LOW")

    if open_conc:
        ctx.conclude(T.SUBJECT_ASSESSMENT, "ASSESSMENT", T.ASSESSMENT_INCONCLUSIVE, T.INCONCLUSIVE,
                     "R-ASSESS-INCONCLUSIVE", "the overall assessment is inconclusive while open items remain.",
                     ev_present, confidence="MEDIUM")
        ctx.overall_status = T.ASSESSMENT_INCONCLUSIVE
    else:
        ctx.conclude(T.SUBJECT_ASSESSMENT, "ASSESSMENT", T.ASSESSMENT_CONCLUSIVE, T.CONFIRMED,
                     "R-ASSESS-CONCLUSIVE", "every conclusion is evidentiarily settled.", ev_present,
                     confidence="MEDIUM")
        ctx.overall_status = T.ASSESSMENT_CONCLUSIVE


# ---------------------------------------------------------------------------
# Views / explanation / diff
# ---------------------------------------------------------------------------


def _latest(analysis):
    runs = list(analysis.assessments)
    return max(runs, key=lambda x: x.created_at) if runs else None


def assessment_view(analysis) -> dict:
    a = _latest(analysis)
    if a is None:
        return {"status": T.ASSESSMENT_INCONCLUSIVE, "fingerprint": _fp("EMPTY", analysis.apk_sha256),
                "summary": {}, "conclusions": [], "note": _NOTE}
    return {
        "status": a.status, "fingerprint": a.fingerprint,
        "summary": {**(a.summary or {}), "truncated": a.truncated},
        "conclusions": [_conc_dict(c) for c in sorted(a.conclusions, key=_conc_sort)][:2000],
        "note": _NOTE,
    }


def _conc_sort(c):
    return (T.DECISION_ORDER.get(c.decision_state, 99), c.subject_type, c.subject_ref, c.conclusion_type)


def _conc_dict(c) -> dict:
    return {
        "id": c.fingerprint, "subject_type": c.subject_type, "subject_ref": c.subject_ref,
        "conclusion_type": c.conclusion_type, "decision_state": c.decision_state, "confidence": c.confidence,
        "rule_id": c.rule_id, "rationale": c.rationale,
        "evidence": [{"source_layer": e.source_layer, "evidence_ref": e.evidence_ref, "mode": e.mode,
                      "provenance": e.provenance, "detail": e.detail} for e in c.evidence],
        "blockers": [{"blocker": b.blocker, "reason": b.reason, "missing": b.missing} for b in c.blockers],
        "requirements": [{"requirement": r.requirement, "satisfied": r.satisfied} for r in c.requirements],
        "dependencies": [{"depends_on": d.depends_on, "type": d.dependency_type} for d in c.dependencies],
    }


def explain_conclusion(analysis, ref: str) -> dict:
    """Full decision chain for a conclusion (by fingerprint) or a subject_ref:
    conclusion → decision state → rule → evidence (with provenance/mode) →
    blockers → requirements → dependencies. Every step references existing evidence."""
    a = _latest(analysis)
    if a is None:
        return {"ref": ref, "chain": [], "note": _NOTE}
    match = next((c for c in a.conclusions if c.fingerprint == ref or c.subject_ref == ref), None)
    if match is None:
        return {"ref": ref, "chain": [{"step": "NOT_FOUND", "detail": "no conclusion for this reference"}],
                "note": _NOTE}
    chain = [
        {"step": "CONCLUSION", "detail": f"{match.conclusion_type}", "provenance": "ASSESSMENT"},
        {"step": "DECISION_STATE", "detail": match.decision_state, "provenance": "ASSESSMENT"},
        {"step": "RULE", "detail": f"{match.rule_id}: {match.rationale}", "provenance": "ASSESSMENT"},
    ]
    for e in match.evidence:
        chain.append({"step": "EVIDENCE", "detail": f"{e.source_layer} → {e.evidence_ref} :: {e.detail}",
                      "provenance": e.provenance, "mode": e.mode})
    for b in match.blockers:
        chain.append({"step": "BLOCKER", "detail": f"{b.blocker}: {b.reason}", "provenance": "ASSESSMENT"})
    for r in match.requirements:
        chain.append({"step": "REQUIREMENT", "detail": f"{r.requirement} ({'met' if r.satisfied else 'unmet'})",
                      "provenance": "ASSESSMENT"})
    chain.append({"step": "CURRENT_DECISION_STATE", "detail": match.decision_state, "provenance": "ASSESSMENT"})
    return {"ref": ref, "subject_type": match.subject_type, "subject_ref": match.subject_ref,
            "decision_state": match.decision_state, "chain": chain, "note": _NOTE}


def assessment_from_diff(comparison) -> dict:
    """Conservative A→B assessment diff by (subject_type, subject_ref). A removed
    conclusion is NO_LONGER_PRESENT — never FIXED / REMEDIATED / NOT_AFFECTED."""
    va = assessment_view(comparison.baseline)
    vb = assessment_view(comparison.candidate)
    a_idx = {(c["subject_type"], c["subject_ref"]): c for c in va["conclusions"]}
    b_idx = {(c["subject_type"], c["subject_ref"]): c for c in vb["conclusions"]}
    changes = []
    for k in sorted(set(a_idx) - set(b_idx)):
        changes.append({"transition": "NO_LONGER_PRESENT", "subject": list(k),
                        "from_state": a_idx[k]["decision_state"], "to_state": None,
                        "detail": "conclusion no longer present — not FIXED/REMEDIATED/NOT_AFFECTED"})
    for k in sorted(set(b_idx) - set(a_idx)):
        changes.append({"transition": "NEW_CONCLUSION", "subject": list(k), "from_state": None,
                        "to_state": b_idx[k]["decision_state"], "detail": b_idx[k]["conclusion_type"]})
    for k in sorted(set(a_idx) & set(b_idx)):
        if a_idx[k]["decision_state"] != b_idx[k]["decision_state"]:
            changes.append({"transition": "STATE_CHANGED", "subject": list(k),
                            "from_state": a_idx[k]["decision_state"], "to_state": b_idx[k]["decision_state"],
                            "detail": f"{a_idx[k]['conclusion_type']} → {b_idx[k]['conclusion_type']}"})
    return {"baseline_fingerprint": va["fingerprint"], "candidate_fingerprint": vb["fingerprint"],
            "changes": changes, "unchanged": len(set(a_idx) & set(b_idx)) - sum(
                1 for k in set(a_idx) & set(b_idx) if a_idx[k]["decision_state"] != b_idx[k]["decision_state"]),
            "note": "conservative decision-state diff; absence never implies remediation/fix/safety."}


_NOTE = ("Decision states express evidentiary strength, not exploitability, and are never a SAFE/UNSAFE verdict. "
         "Every conclusion references existing persisted evidence and never mutates it. POSSIBLY_AFFECTED ≠ AFFECTED, "
         "NOT_OBSERVED/NOT_REACHABLE ≠ safe, MOCKED ≠ LIVE, UNKNOWN_NATIVE_TARGET is preserved.")

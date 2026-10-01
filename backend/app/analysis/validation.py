"""Security verification & validation intelligence (prompt 18).

A deterministic, evidence-backed projection over already-persisted evidence that
answers: what security claim can currently be VERIFIED from static evidence,
CORROBORATED by runtime, or remains UNVERIFIED — and what evidence is still
required. It is NOT an exploitability engine: there is no `exploitable` state, no
score is mutated, and every uncertainty (UNKNOWN / NOT_REACHABLE / NOT_OBSERVED /
POSSIBLY_AFFECTED / NO_LONGER_DETECTED / UNKNOWN_NATIVE_TARGET) is preserved.

Validation confidence is a SEPARATE axis from risk / severity / remediation
priority. Independence matters: evidence from the same source family does not
count as independent corroboration; distinct families (e.g. STATIC_CODE +
STATIC_REACHABILITY, or STATIC + live RUNTIME) do. Mock runtime observations stay
MOCKED and never corroborate.

Complexity: each source (findings, matches, boundaries, ipc, remediation items,
runtime sessions) is scanned once with dictionary lookups — no N×M scans, and the
Java/native graph is never recomputed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.models.validation import (
    VS_BLOCKED, VS_INCONCLUSIVE, VS_MULTI_SOURCE, VS_NOT_APPLICABLE, VS_RUNTIME_CORROBORATED,
    VS_STATIC_SUPPORTED, VS_SUPERSEDED, VS_UNVERIFIED,
    ValidationBlocker, ValidationClaim, ValidationEvidence, ValidationRequirement, ValidationTransition,
)

# --- source families (deterministic classification) ------------------------
F_STATIC_CODE = "STATIC_CODE"
F_STATIC_MANIFEST = "STATIC_MANIFEST"
F_STATIC_REACHABILITY = "STATIC_REACHABILITY"
F_STATIC_SEMANTICS = "STATIC_SEMANTICS"
F_STATIC_NATIVE = "STATIC_NATIVE"
F_DEPENDENCY_METADATA = "DEPENDENCY_METADATA"
F_VULNERABILITY_DATABASE = "VULNERABILITY_DATABASE"
F_RUNTIME = "RUNTIME"
F_DIFF = "DIFF"
F_USER_INVESTIGATION = "USER_INVESTIGATION"

_SOURCE_FAMILY = {
    "manifest": F_STATIC_MANIFEST, "code": F_STATIC_CODE, "dex": F_STATIC_CODE, "jadx": F_STATIC_CODE,
    "reachability": F_STATIC_REACHABILITY, "semantic": F_STATIC_SEMANTICS, "semantics": F_STATIC_SEMANTICS,
    "native": F_STATIC_NATIVE, "elf": F_STATIC_NATIVE, "jni": F_STATIC_NATIVE,
    "cve": F_VULNERABILITY_DATABASE, "runtime": F_RUNTIME,
}

# --- documented confidence weights (separate from risk/severity/priority) --
VALIDATION_WEIGHTS = {
    "base_evidence": 40,          # at least one supporting evidence row
    "independent_family": 15,     # per distinct family beyond the first
    "direct_target": 10,          # evidence directly names the target
    "runtime_corroboration": 20,  # a live (non-mock) runtime observation
    "reachability_confirmed": 10, # a proven reachable path supports the claim
    "identity_confirmed": 10,     # CVE identity confidence EXACT/HIGH
    "version_confirmed": 10,      # reliable installed version
}
VALIDATION_PENALTIES = {
    "unknown_version": 15,
    "unknown_native_target": 10,
    "unresolved_ipc_target": 10,
    "not_reachable": 10,
    "possibly_affected": 10,
    "runtime_not_observed": 5,
    "missing_provider_record": 5,
    "ambiguous_identity": 10,
}

# --- claim types -----------------------------------------------------------
C_REACHABILITY = "REACHABILITY_CONFIRMED"
C_SOURCE_TO_SINK = "SOURCE_TO_SINK_SUPPORTED"
C_EXPORTED_COMPONENT = "EXPORTED_COMPONENT_CONFIRMED"
C_INTENT_INPUT = "INTENT_INPUT_CONFIRMED"
C_DEEP_LINK = "DEEP_LINK_INPUT_CONFIRMED"
C_IPC_BOUNDARY = "IPC_BOUNDARY_CONFIRMED"
C_WEBVIEW_BRIDGE = "WEBVIEW_BRIDGE_CONFIRMED"
C_REFLECTION = "REFLECTION_PATH_CONFIRMED"
C_DYNAMIC_LOAD = "DYNAMIC_LOAD_PATH_CONFIRMED"
C_JNI_BOUNDARY = "JNI_BOUNDARY_CONFIRMED"
C_NATIVE_USAGE = "NATIVE_USAGE_CONFIRMED"
C_DEPENDENCY_PRESENT = "DEPENDENCY_PRESENT"
C_DEPENDENCY_VERSION = "DEPENDENCY_VERSION_CONFIRMED"
C_CVE_MATCH = "CVE_MATCH_SUPPORTED"
C_CVE_AFFECTED = "CVE_VERSION_AFFECTED"
C_CVE_UNVERIFIED = "CVE_VERSION_UNVERIFIED"
C_RUNTIME_OBSERVED = "RUNTIME_BEHAVIOR_OBSERVED"
C_REMEDIATION = "REMEDIATION_STATE_SUPPORTED"
C_APK_CHANGE = "APK_CHANGE_CONFIRMED"
C_STATIC_FINDING = "STATIC_FINDING_SUPPORTED"  # extension for unmapped finding categories
# deep native / Ghidra correlation claims (prompt 20). Ghidra is one source family
# (F_STATIC_NATIVE); UNKNOWN_NATIVE_TARGET is preserved, never inferred.
C_NATIVE_TARGET_RESOLVED = "NATIVE_TARGET_RESOLVED"
C_NATIVE_JNI_CONFIRMED = "JNI_BINDING_CONFIRMED"
C_NATIVE_CALL_PATH = "NATIVE_CALL_PATH_CONFIRMED"
C_NATIVE_API_REACHABILITY = "NATIVE_API_REACHABILITY_SUPPORTED"
C_NATIVE_TARGET_UNRESOLVED = "NATIVE_TARGET_UNRESOLVED"
# Live runtime-backed claims (prompt 21). Only genuinely LIVE evidence corroborates;
# MOCKED runtime never counts as live and leaves the claim BLOCKED (needs a device).
C_RT_COMPONENT_DISPATCH = "COMPONENT_DISPATCH_OBSERVED"
C_RT_REFLECTION = "REFLECTION_RESOLUTION_OBSERVED"
C_RT_DYNAMIC_LOAD = "DYNAMIC_LOAD_OBSERVED"
C_RT_JNI_INVOCATION = "JNI_INVOCATION_OBSERVED"
C_RT_NATIVE_API_INVOCATION = "NATIVE_API_INVOCATION_OBSERVED"
C_RT_WEBVIEW = "WEBVIEW_BEHAVIOR_OBSERVED"
C_RT_IPC = "IPC_BEHAVIOR_OBSERVED"
C_RT_NETWORK = "NETWORK_SECURITY_BEHAVIOR_OBSERVED"

# --- blockers --------------------------------------------------------------
B_NO_RUNTIME_DEVICE = "NO_RUNTIME_DEVICE"
B_NO_FRIDA = "NO_FRIDA"
B_MISSING_VERSION = "MISSING_VERSION"
B_MISSING_JNI_TARGET = "MISSING_JNI_TARGET"
B_UNKNOWN_NATIVE_TARGET = "UNKNOWN_NATIVE_TARGET"
B_MISSING_PROVIDER_RECORD = "MISSING_PROVIDER_RECORD"
B_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
B_AMBIGUOUS_IDENTITY = "AMBIGUOUS_IDENTITY"
B_NO_COMPILED_TEST_ARTIFACT = "NO_COMPILED_TEST_ARTIFACT"
B_NO_LIVE_OBSERVATION = "NO_LIVE_OBSERVATION"
B_UNRESOLVED_IPC_TARGET = "UNRESOLVED_IPC_TARGET"

# Blockers that prevent validation (vs. UNKNOWN_NATIVE_TARGET which is preserved
# as an uncertainty and does not block).
_HARD_BLOCKERS = {B_MISSING_VERSION, B_NO_LIVE_OBSERVATION, B_UNRESOLVED_IPC_TARGET, B_MISSING_JNI_TARGET}


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class VEv:
    family: str
    source_type: str
    source_id: str | None
    confidence: str
    live: bool
    detail: str
    evidence_json: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        raw = f"{self.family}|{self.source_type}|{self.source_id}|{self.detail}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]


@dataclass
class VClaim:
    claim_type: str
    target_type: str
    target: str | None
    current_state: str | None = None
    finding_id: object | None = None
    remediation_ref: str | None = None
    evidence: list[VEv] = field(default_factory=list)
    requirements: list[dict] = field(default_factory=list)  # {requirement, satisfied, detail, hard}
    blockers: list[dict] = field(default_factory=list)      # {blocker, reason, missing}
    uncertainty: list[str] = field(default_factory=list)
    state: str = VS_UNVERIFIED
    confidence: int = 0
    independent_source_count: int = 0
    provenance: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        raw = f"{self.claim_type}|{self.target_type}|{(self.target or '').lower()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    @property
    def families(self) -> set[str]:
        # a same-family group counts once; non-live runtime is not corroborating
        return {e.family for e in self.evidence if not (e.family == F_RUNTIME and not e.live)}


# ---------------------------------------------------------------------------
# Requirement templates (deterministic, inspectable)
# ---------------------------------------------------------------------------

# requirement -> (hard, blocker-when-unmet)
_REQUIREMENTS: dict[str, list[tuple[str, bool, str | None]]] = {
    C_REACHABILITY: [("reachable_path", True, B_INSUFFICIENT_EVIDENCE)],
    C_SOURCE_TO_SINK: [("source", False, None), ("sink", False, None), ("reachable_path", True, B_INSUFFICIENT_EVIDENCE)],
    C_EXPORTED_COMPONENT: [("manifest_export", True, B_INSUFFICIENT_EVIDENCE), ("semantic_dispatch", False, None)],
    C_INTENT_INPUT: [("exported_component", True, B_INSUFFICIENT_EVIDENCE), ("intent_evidence", False, None)],
    C_DEEP_LINK: [("deep_link_evidence", True, B_INSUFFICIENT_EVIDENCE)],
    C_IPC_BOUNDARY: [("ipc_transaction", True, B_INSUFFICIENT_EVIDENCE), ("resolved_target", True, B_UNRESOLVED_IPC_TARGET)],
    C_WEBVIEW_BRIDGE: [("webview_bridge_evidence", True, B_INSUFFICIENT_EVIDENCE)],
    C_REFLECTION: [("reflection_evidence", True, B_INSUFFICIENT_EVIDENCE), ("resolved_target", False, B_UNKNOWN_NATIVE_TARGET)],
    C_DYNAMIC_LOAD: [("dynamic_load_evidence", True, B_INSUFFICIENT_EVIDENCE), ("resolved_target", False, B_UNKNOWN_NATIVE_TARGET)],
    C_JNI_BOUNDARY: [("java_native_decl_or_call", True, B_INSUFFICIENT_EVIDENCE),
                     ("jni_binding", False, None), ("resolved_native_target", False, B_UNKNOWN_NATIVE_TARGET)],
    C_NATIVE_USAGE: [("native_symbol", True, B_INSUFFICIENT_EVIDENCE), ("native_artifact", True, B_INSUFFICIENT_EVIDENCE)],
    C_DEPENDENCY_PRESENT: [("dependency_identity", True, B_INSUFFICIENT_EVIDENCE)],
    C_DEPENDENCY_VERSION: [("dependency_identity", True, B_INSUFFICIENT_EVIDENCE), ("reliable_version", True, B_MISSING_VERSION)],
    C_CVE_MATCH: [("identity_match", True, B_AMBIGUOUS_IDENTITY), ("vulnerability_record", True, B_MISSING_PROVIDER_RECORD)],
    C_CVE_AFFECTED: [("identity_match", True, B_AMBIGUOUS_IDENTITY), ("reliable_version", True, B_MISSING_VERSION),
                     ("affected_range", True, B_INSUFFICIENT_EVIDENCE), ("vulnerability_record", True, B_MISSING_PROVIDER_RECORD)],
    C_CVE_UNVERIFIED: [("identity_match", True, B_AMBIGUOUS_IDENTITY), ("vulnerability_record", True, B_MISSING_PROVIDER_RECORD)],
    C_RUNTIME_OBSERVED: [("runtime_observation", True, B_NO_LIVE_OBSERVATION), ("observation_source", True, B_NO_LIVE_OBSERVATION),
                         ("matching_target", True, B_NO_LIVE_OBSERVATION)],
    C_REMEDIATION: [("remediation_action", True, B_INSUFFICIENT_EVIDENCE), ("supporting_evidence", True, B_INSUFFICIENT_EVIDENCE)],
    C_STATIC_FINDING: [("static_finding_evidence", True, B_INSUFFICIENT_EVIDENCE)],
    C_APK_CHANGE: [("diff_change", True, B_INSUFFICIENT_EVIDENCE)],
    # UNKNOWN_NATIVE_TARGET is a soft blocker (preserved, does not block).
    C_NATIVE_TARGET_RESOLVED: [("native_symbol", True, B_INSUFFICIENT_EVIDENCE),
                              ("resolved_native_target", False, B_UNKNOWN_NATIVE_TARGET)],
    C_NATIVE_JNI_CONFIRMED: [("jni_binding", True, B_INSUFFICIENT_EVIDENCE),
                             ("resolved_native_target", False, B_UNKNOWN_NATIVE_TARGET)],
    C_NATIVE_CALL_PATH: [("native_call_edge", True, B_INSUFFICIENT_EVIDENCE)],
    C_NATIVE_API_REACHABILITY: [("native_call_edge", True, B_INSUFFICIENT_EVIDENCE),
                                ("reached_api", True, B_INSUFFICIENT_EVIDENCE)],
    C_NATIVE_TARGET_UNRESOLVED: [("jni_binding", True, B_INSUFFICIENT_EVIDENCE)],
    # Runtime-backed claims require a LIVE observation (MOCKED never satisfies).
    C_RT_COMPONENT_DISPATCH: [("runtime_observation", True, B_NO_LIVE_OBSERVATION)],
    C_RT_REFLECTION: [("runtime_observation", True, B_NO_LIVE_OBSERVATION)],
    C_RT_DYNAMIC_LOAD: [("runtime_observation", True, B_NO_LIVE_OBSERVATION)],
    C_RT_JNI_INVOCATION: [("runtime_observation", True, B_NO_LIVE_OBSERVATION)],
    C_RT_NATIVE_API_INVOCATION: [("runtime_observation", True, B_NO_LIVE_OBSERVATION)],
    C_RT_WEBVIEW: [("runtime_observation", True, B_NO_LIVE_OBSERVATION)],
    C_RT_IPC: [("runtime_observation", True, B_NO_LIVE_OBSERVATION)],
    C_RT_NETWORK: [("runtime_observation", True, B_NO_LIVE_OBSERVATION)],
}


def requirements_for(claim_type: str) -> list[str]:
    return [r[0] for r in _REQUIREMENTS.get(claim_type, [])]


# ---------------------------------------------------------------------------
# Finding claims
# ---------------------------------------------------------------------------


def _finding_claim_type(finding) -> tuple[str, str]:
    rid, cat = finding.rule_id, finding.category
    text = " ".join([finding.title or ""] + [e.detail or "" for e in finding.evidence]).lower()
    if cat == "reachability" or rid.startswith("ANDROID-REACH"):
        if "reflect" in text or "class.forname" in text:
            return C_REFLECTION, "CODE_PATH"
        if "source" in text and "sink" in text:
            return C_SOURCE_TO_SINK, "CODE_PATH"
        return C_REACHABILITY, "CODE_PATH"
    if cat == "webview" or "webview" in text:
        return (C_WEBVIEW_BRIDGE if "bridge" in text or "interface" in text else C_WEBVIEW_BRIDGE), "WEBVIEW"
    if cat == "native" or rid.startswith("ASF-NATIVE"):
        return C_NATIVE_USAGE, "NATIVE_LIBRARY"
    mapping = {
        "ANDROID-SEMANTIC-001": (C_INTENT_INPUT, "COMPONENT"),
        "ANDROID-SEMANTIC-002": (C_DEEP_LINK, "DEEP_LINK"),
        "ANDROID-SEMANTIC-003": (C_IPC_BOUNDARY, "IPC"),
        "ANDROID-SEMANTIC-004": (C_WEBVIEW_BRIDGE, "WEBVIEW"),
        "ANDROID-SEMANTIC-005": (C_REFLECTION, "CODE_PATH"),
        "ANDROID-COMPONENT-001": (C_EXPORTED_COMPONENT, "COMPONENT"),
    }
    if rid in mapping:
        return mapping[rid]
    return C_STATIC_FINDING, "FINDING"


def _finding_claims(analysis, ctx) -> list[VClaim]:
    out: list[VClaim] = []
    for f in analysis.findings:
        if f.is_duplicate or f.category == "cve":
            continue
        claim_type, target_type = _finding_claim_type(f)
        target = f.component or f.primary_target or f.rule_id
        claim = VClaim(claim_type=claim_type, target_type=target_type, target=target, finding_id=f.id,
                       current_state=f"finding {f.rule_id} [{f.severity}/{f.confidence}] status={f.status}")
        # static evidence from the finding's own evidence rows (family-classified)
        for e in f.evidence:
            fam = _SOURCE_FAMILY.get((e.source or "").lower(), F_STATIC_CODE)
            claim.evidence.append(VEv(fam, e.source, e.location, (f.confidence or "medium").upper(), False,
                                      e.detail or "", {"class": e.class_name, "method": e.method_name, "line": e.line}))
        # independent reachability corroboration
        if ctx["reach_by_rule"].get(f.rule_id):
            p = ctx["reach_by_rule"][f.rule_id]
            claim.evidence.append(VEv(F_STATIC_REACHABILITY, "reachability", f"{p.from_key}->{p.to_key}",
                                      p.confidence, False, f"reachable path {p.status} {p.from_label}->{p.to_label}",
                                      {"status": p.status}))
        # runtime corroboration (live vs mock)
        for ev in _runtime_evidence(analysis, f):
            claim.evidence.append(ev)
        _finalize_claim(claim, analysis, ctx, finding=f)
        out.append(claim)
    return out


def _runtime_evidence(analysis, finding) -> list[VEv]:
    out: list[VEv] = []
    text = " ".join([finding.title or ""] + [e.detail or "" for e in finding.evidence])
    for s in analysis.runtime_sessions:
        live = (s.metadata_ or {}).get("adapter") != "mock"
        for o in s.observations:
            token = (f"{o.class_name.rsplit('.', 1)[-1]}.{o.method_name}" if o.class_name and o.method_name
                     else (o.symbol or None))
            if token and token in text:
                out.append(VEv(F_RUNTIME, "runtime", str(o.id), o.confidence, live,
                               f"observed {token} ({'LIVE' if live else 'MOCKED'}) via {o.source}",
                               {"live": live, "session": str(s.id)}))
    return out


# ---------------------------------------------------------------------------
# CVE / dependency claims
# ---------------------------------------------------------------------------


def _cve_claims(analysis) -> list[VClaim]:
    out: list[VClaim] = []
    for m in analysis.vulnerability_matches:
        dep = m.dependency
        if m.version_state == "NOT_AFFECTED":
            claim = VClaim(C_DEPENDENCY_PRESENT, "DEPENDENCY", dep.name,
                           current_state=f"{m.cve_id} NOT_AFFECTED")
            _dep_evidence(claim, m, dep)
            claim.state = VS_NOT_APPLICABLE
            claim.confidence = 0
            out.append(claim)
            continue
        if m.version_state == "AFFECTED":
            ctype = C_CVE_AFFECTED
        elif m.version_state == "POSSIBLY_AFFECTED":
            ctype = C_CVE_UNVERIFIED
        else:
            ctype = C_CVE_MATCH
        claim = VClaim(ctype, "DEPENDENCY", dep.name,
                       current_state=f"{m.cve_id} version_state={m.version_state} identity={m.identity_confidence}",
                       finding_id=None)
        _dep_evidence(claim, m, dep)
        _finalize_claim(claim, analysis, None, match=m)
        out.append(claim)
    return out


def _dep_evidence(claim: VClaim, m, dep) -> None:
    claim.evidence.append(VEv(F_DEPENDENCY_METADATA, "dependency", dep.name, dep.identity_confidence, False,
                              f"{dep.name} ({dep.ecosystem}/{dep.kind}) version={dep.version or 'UNKNOWN'} "
                              f"version_source={dep.version_source or 'UNKNOWN'}",
                              {"version": dep.version, "version_source": dep.version_source}))
    claim.evidence.append(VEv(F_VULNERABILITY_DATABASE, "cve", m.cve_id, m.match_confidence, False,
                              f"{m.cve_id} state={m.version_state}/{m.correlation_state} identity={m.identity_confidence}",
                              {"correlation_state": m.correlation_state, "reachability_state": m.reachability_state}))


# ---------------------------------------------------------------------------
# Structural claims: IPC + JNI boundaries (so they validate even without a finding)
# ---------------------------------------------------------------------------


def _ipc_claims(analysis) -> list[VClaim]:
    out: list[VClaim] = []
    for t in analysis.ipc_transactions:
        target = t.class_name or t.interface_name or "IPC"
        claim = VClaim(C_IPC_BOUNDARY, "IPC", target,
                       current_state=f"kind={t.kind} code={t.transaction_code} target=UNKNOWN")
        claim.evidence.append(VEv(F_STATIC_SEMANTICS, "semantic", target, t.confidence, False,
                                  f"{t.kind} {target}.{t.method_name or ''} code={t.transaction_code} target=UNKNOWN",
                                  {"target_status": "UNKNOWN"}))
        _finalize_claim(claim, analysis, None)
        out.append(claim)
    return out


def _jni_claims(analysis) -> list[VClaim]:
    out: list[VClaim] = []
    for b in analysis.security_boundaries:
        if (b.boundary_type or "").upper() != "JNI":
            continue
        target = b.component or b.node_key
        claim = VClaim(C_JNI_BOUNDARY, "JNI_BINDING", target,
                       current_state="JNI boundary present; native target UNKNOWN_NATIVE_TARGET")
        claim.evidence.append(VEv(F_STATIC_SEMANTICS, "semantic", b.node_key, b.confidence, False,
                                  f"JNI boundary at {target}; native target UNKNOWN_NATIVE_TARGET",
                                  {"native_target": "UNKNOWN_NATIVE_TARGET"}))
        # a JNI binding, if present, is an independent (native) family
        if analysis.jni_bindings:
            jb = analysis.jni_bindings[0]
            claim.evidence.append(VEv(F_STATIC_NATIVE, "jni", jb.native_function or jb.library_name,
                                      jb.confidence, False, f"JNI binding {jb.java_class}.{jb.java_method}", {}))
        _finalize_claim(claim, analysis, None)
        out.append(claim)
    return out


# ---------------------------------------------------------------------------
# Live runtime-backed claims (prompt 21)
# ---------------------------------------------------------------------------

_RT_TAXONOMY_CLAIM = {
    "COMPONENT_DISPATCH": C_RT_COMPONENT_DISPATCH, "ACTIVITY_LAUNCH": C_RT_COMPONENT_DISPATCH,
    "SERVICE_START": C_RT_COMPONENT_DISPATCH, "BROADCAST_DISPATCH": C_RT_COMPONENT_DISPATCH,
    "CONTENT_PROVIDER_ACCESS": C_RT_COMPONENT_DISPATCH,
    "REFLECTION_RESOLUTION": C_RT_REFLECTION, "DYNAMIC_CLASS_LOADING": C_RT_DYNAMIC_LOAD,
    "JNI_INVOCATION": C_RT_JNI_INVOCATION, "NATIVE_API_INVOCATION": C_RT_NATIVE_API_INVOCATION,
    "WEBVIEW_NAVIGATION": C_RT_WEBVIEW, "BINDER_TRANSACTION": C_RT_IPC, "TLS_NETWORK": C_RT_NETWORK,
}


def _runtime_validation_claims(analysis) -> list[VClaim]:
    """Validation claims from persisted runtime correlations (prompt 21). Guarded:
    only when a runtime-validation run exists. All correlations for one
    (claim_type, target) are aggregated into a single claim BEFORE finalizing, so
    LIVE and MOCKED evidence are weighed together — only genuinely LIVE evidence
    corroborates; MOCKED never satisfies the live requirement. Runtime never
    overwrites static truth or asserts exploitability."""
    if not analysis.runtime_validation_runs:
        return []
    grouped: dict[tuple[str, str, str], VClaim] = {}
    for c in analysis.runtime_correlations:
        claim_type = _RT_TAXONOMY_CLAIM.get(c.taxonomy or "", C_RUNTIME_OBSERVED)
        target = c.subject_ref[:200]
        key = (claim_type, c.subject_type, target)
        claim = grouped.get(key)
        if claim is None:
            claim = VClaim(claim_type, c.subject_type, target,
                           current_state=f"runtime {c.correlation_type} [{c.mode}] {c.detail[:120]}")
            grouped[key] = claim
        claim.evidence.append(VEv(F_RUNTIME, "runtime", c.subject_ref, c.confidence, c.mode == "LIVE",
                                  f"{c.correlation_type} {c.taxonomy or ''} [{c.mode}] {c.detail}",
                                  {"mode": c.mode, "provenance": c.provenance}))
    out = list(grouped.values())
    for claim in out:
        _finalize_claim(claim, analysis, None)
    return out


# ---------------------------------------------------------------------------
# Deep native / Ghidra correlation claims (prompt 20)
# ---------------------------------------------------------------------------


def _native_deep_claims(analysis) -> list[VClaim]:
    """Validation claims from persisted deep-native evidence. Guarded: only when a
    native-deep run exists. Ghidra is one source family (F_STATIC_NATIVE); never
    infers reachability, never converts UNKNOWN_NATIVE_TARGET to a resolved target,
    never asserts exploitability."""
    if not analysis.native_analysis_runs:
        return []
    from app.core.config import settings
    out: list[VClaim] = []
    fn_by_fp = {f.fingerprint: f for f in analysis.native_deep_functions}

    for j in list(analysis.native_deep_jni_bindings)[: settings.native_max_jni_bindings]:
        target = f"{j.java_class}.{j.java_method}"
        src = "ghidra" if j.source == "GHIDRA" else "jni"
        if j.state == "RESOLVED" and j.native_symbol:
            claim = VClaim(C_NATIVE_JNI_CONFIRMED, "JNI_BINDING", target,
                           current_state=f"JNI {target} → {j.native_symbol} [{j.registration_type}]")
            claim.evidence.append(VEv(F_STATIC_NATIVE, src, j.native_symbol, j.confidence, False,
                                      f"JNI {target} resolved to native symbol {j.native_symbol} "
                                      f"({j.registration_type})", {"registration_type": j.registration_type}))
            _finalize_claim(claim, analysis, None)
            out.append(claim)
            # NATIVE_TARGET_RESOLVED: the native function target itself is resolved.
            rclaim = VClaim(C_NATIVE_TARGET_RESOLVED, "NATIVE_FUNCTION", j.native_symbol,
                            current_state=f"native target {j.native_symbol} resolved from JNI {target}")
            rclaim.evidence.append(VEv(F_STATIC_NATIVE, src, j.native_symbol, j.confidence, False,
                                       f"native symbol {j.native_symbol} present and bound from {target}", {}))
            _finalize_claim(rclaim, analysis, None)
            out.append(rclaim)
        else:
            claim = VClaim(C_NATIVE_TARGET_UNRESOLVED, "JNI_BINDING", target,
                           current_state=f"JNI {target} → UNKNOWN_NATIVE_TARGET ({j.registration_type})")
            claim.evidence.append(VEv(F_STATIC_NATIVE, src, j.native_symbol or target, j.confidence, False,
                                      f"JNI {target} present; native target UNKNOWN_NATIVE_TARGET "
                                      f"({j.registration_type})", {"native_target": "UNKNOWN_NATIVE_TARGET"}))
            _finalize_claim(claim, analysis, None)
            out.append(claim)

    # NATIVE_API_REACHABILITY_SUPPORTED — only where a Ghidra call chain reaches an API.
    from app.native.deep_native import API_REACHED
    for o in list(analysis.native_api_observations)[: settings.native_max_path_results]:
        if o.state != API_REACHED:
            continue
        fn = fn_by_fp.get(o.function_fp) if o.function_fp else None
        target = f"{o.api}@{fn.name if fn else '?'}"
        claim = VClaim(C_NATIVE_API_REACHABILITY, "NATIVE_API", target,
                       current_state=f"native API {o.api} NATIVE_CALL_CHAIN_REACHES_API")
        claim.evidence.append(VEv(F_STATIC_NATIVE, "native_call", o.api, o.confidence, False,
                                  f"native_call_edge chain reaches API {o.api}; "
                                  f"state=NATIVE_CALL_CHAIN_REACHES_API", {"category": o.category}))
        _finalize_claim(claim, analysis, None)
        out.append(claim)

    return out


# ---------------------------------------------------------------------------
# Remediation claims
# ---------------------------------------------------------------------------


def _remediation_claims(analysis) -> list[VClaim]:
    from app.analysis.remediation import build_items
    from app.models.remediation import STATUS_VERSION_UNVERIFIED

    out: list[VClaim] = []
    for it in build_items(analysis):
        claim = VClaim(C_REMEDIATION, it.target_type, it.target, remediation_ref=it.fingerprint,
                       current_state=f"{it.action} [{it.status}] priority={it.priority}")
        # remediation carries its own evidence families
        for e in it.evidence:
            fam = {"FINDING": F_STATIC_CODE, "CVE": F_VULNERABILITY_DATABASE, "DEPENDENCY": F_DEPENDENCY_METADATA,
                   "ROOT_CAUSE": F_STATIC_SEMANTICS, "ATTACK_SURFACE": F_STATIC_MANIFEST, "IPC": F_STATIC_SEMANTICS,
                   "SECURITY_BOUNDARY": F_STATIC_SEMANTICS, "CODE": F_STATIC_CODE,
                   "RUNTIME": F_RUNTIME}.get(e.get("source_type"), F_STATIC_CODE)
            live = e.get("source_type") == "RUNTIME" and e.get("detail") == "RUNTIME_CORROBORATED"
            claim.evidence.append(VEv(fam, e.get("source_type", "STATIC"), e.get("source_id"),
                                      e.get("confidence", "MEDIUM"), live, e.get("detail", ""), {}))
        if it.status == STATUS_VERSION_UNVERIFIED:
            claim.blockers.append({"blocker": B_MISSING_VERSION, "reason": "installed version not recovered",
                                   "missing": "reliable_version"})
        _finalize_claim(claim, analysis, None)
        out.append(claim)
    return out


# ---------------------------------------------------------------------------
# Requirement checking + state + confidence
# ---------------------------------------------------------------------------


def _requirement_satisfied(req: str, claim: VClaim, analysis, finding, match) -> bool:
    fams = claim.families
    text = " ".join(e.detail.lower() for e in claim.evidence)
    if req == "reachable_path":
        return any(e.family == F_STATIC_REACHABILITY and "reachable" in e.detail.lower() and "reachable" in e.detail.lower()
                   for e in claim.evidence) or (finding is not None and finding.category == "reachability")
    if req in ("source", "sink"):
        return req in text
    if req == "manifest_export" or req == "exported_component":
        return any(c.effective_exported and c.name == claim.target for c in analysis.components) or \
            F_STATIC_MANIFEST in fams or (finding is not None and (finding.component in
            {c.name for c in analysis.components if c.effective_exported}))
    if req == "semantic_dispatch":
        return F_STATIC_SEMANTICS in fams
    if req in ("intent_evidence", "deep_link_evidence", "webview_bridge_evidence", "reflection_evidence",
               "dynamic_load_evidence", "static_finding_evidence", "java_native_decl_or_call", "diff_change"):
        return bool(claim.evidence)
    if req == "ipc_transaction":
        return any(e.family == F_STATIC_SEMANTICS for e in claim.evidence)
    if req == "resolved_target":
        return "unknown" not in text and "target=unknown" not in text
    if req == "resolved_native_target":
        return "unknown_native_target" not in text and "unknown" not in text
    if req == "jni_binding":
        return F_STATIC_NATIVE in fams
    if req == "native_call_edge":
        return any("native_call" in (e.source_type or "").lower() or "call_edge" in e.detail.lower()
                   for e in claim.evidence)
    if req == "reached_api":
        return any("reach" in e.detail.lower() or "NATIVE_CALL_CHAIN_REACHES_API" in e.detail
                   for e in claim.evidence)
    if req == "native_symbol":
        return F_STATIC_NATIVE in fams or (finding is not None and finding.category == "native")
    if req == "native_artifact":
        return bool(analysis.native_libraries)
    if req == "dependency_identity":
        return match is not None and match.identity_confidence in ("EXACT", "HIGH", "MEDIUM")
    if req == "reliable_version":
        return match is not None and match.dependency.version is not None and \
            match.dependency.version_confidence not in ("UNKNOWN", None)
    if req == "identity_match":
        return match is not None and match.identity_confidence in ("EXACT", "HIGH")
    if req == "affected_range":
        return match is not None
    if req == "vulnerability_record":
        return match is not None
    if req in ("runtime_observation", "observation_source", "matching_target"):
        return any(e.family == F_RUNTIME and e.live for e in claim.evidence)
    if req in ("remediation_action", "supporting_evidence"):
        return bool(claim.evidence)
    return bool(claim.evidence)


def _runtime_capability_blockers(analysis) -> list[dict]:
    """Static-only environments cannot corroborate at runtime — report why."""
    blockers = []
    if not analysis.runtime_sessions:
        blockers.append({"blocker": B_NO_LIVE_OBSERVATION, "reason": "no runtime session recorded",
                         "missing": "live runtime observation"})
    elif not any((s.metadata_ or {}).get("adapter") != "mock" for s in analysis.runtime_sessions):
        blockers.append({"blocker": B_NO_LIVE_OBSERVATION, "reason": "only MOCKED runtime sessions present",
                         "missing": "a LIVE (non-mock) runtime observation"})
    return blockers


def _finalize_claim(claim: VClaim, analysis, ctx, finding=None, match=None) -> None:
    # requirements
    hard_unmet = False
    for req, hard, blocker in _REQUIREMENTS.get(claim.claim_type, []):
        satisfied = _requirement_satisfied(req, claim, analysis, finding, match)
        claim.requirements.append({"requirement": req, "satisfied": satisfied, "hard": hard})
        if not satisfied and blocker is not None:
            if not any(b["blocker"] == blocker for b in claim.blockers):
                claim.blockers.append({"blocker": blocker, "reason": f"requirement '{req}' not satisfied",
                                       "missing": req})
            if hard:
                hard_unmet = True

    fams = claim.families
    claim.independent_source_count = len(fams)
    has_live_runtime = any(e.family == F_RUNTIME and e.live for e in claim.evidence)
    has_mock_runtime = any(e.family == F_RUNTIME and not e.live for e in claim.evidence)

    # uncertainties (preserve source states verbatim)
    if match is not None and match.version_state == "POSSIBLY_AFFECTED":
        claim.uncertainty.append("version unverified — POSSIBLY_AFFECTED is not AFFECTED")
    if any("target=unknown" in e.detail.lower() or "unknown_native_target" in e.detail.lower()
           for e in claim.evidence):
        claim.uncertainty.append("target is UNKNOWN and is never inferred")
    if has_mock_runtime and not has_live_runtime:
        claim.uncertainty.append("runtime evidence is MOCKED, never treated as LIVE")

    # A hard capability/evidence blocker (missing version, no live observation,
    # unresolved IPC/JNI target) blocks the claim; UNKNOWN_NATIVE_TARGET does NOT
    # block (it is preserved as an uncertainty).
    hard_blocker = any(b["blocker"] in _HARD_BLOCKERS for b in claim.blockers)
    blocked = (hard_unmet or hard_blocker) and claim.claim_type != C_CVE_UNVERIFIED

    # state — UNVERIFIED (no supporting evidence) is distinct from BLOCKED
    # (evidence present but a required capability/evidence is absent).
    if claim.state == VS_NOT_APPLICABLE:
        pass
    elif claim.independent_source_count == 0 and not has_live_runtime:
        claim.state = VS_UNVERIFIED
        if not claim.blockers:
            claim.blockers.append({"blocker": B_INSUFFICIENT_EVIDENCE,
                                   "reason": "no independent supporting evidence", "missing": "supporting_evidence"})
    elif blocked:
        claim.state = VS_BLOCKED
    elif has_live_runtime and claim.independent_source_count >= 2:
        claim.state = VS_MULTI_SOURCE
    elif has_live_runtime:
        claim.state = VS_RUNTIME_CORROBORATED
    elif claim.independent_source_count >= 2:
        claim.state = VS_MULTI_SOURCE
    elif claim.independent_source_count == 1:
        claim.state = VS_STATIC_SUPPORTED
    else:
        claim.state = VS_UNVERIFIED

    claim.confidence = _confidence(claim, match, has_live_runtime)
    claim.provenance = {"families": sorted(fams), "evidence": len(claim.evidence),
                        "blockers": [b["blocker"] for b in claim.blockers]}
    # required capabilities / missing evidence
    if claim.claim_type == C_RUNTIME_OBSERVED or any(b["blocker"] == B_NO_LIVE_OBSERVATION for b in claim.blockers):
        pass
    claim.provenance["required_capabilities"] = _required_capabilities(claim.claim_type)


def _confidence(claim: VClaim, match, has_live_runtime: bool) -> int:
    if not claim.evidence or claim.state in (VS_NOT_APPLICABLE,):
        return 0
    score = VALIDATION_WEIGHTS["base_evidence"]
    if claim.independent_source_count >= 1:
        score += VALIDATION_WEIGHTS["independent_family"] * (claim.independent_source_count - 1)
    if claim.target and any(claim.target.rsplit(".", 1)[-1].lower() in (e.source_id or "").lower()
                            for e in claim.evidence):
        score += VALIDATION_WEIGHTS["direct_target"]
    if has_live_runtime:
        score += VALIDATION_WEIGHTS["runtime_corroboration"]
    if any(e.family == F_STATIC_REACHABILITY for e in claim.evidence):
        score += VALIDATION_WEIGHTS["reachability_confirmed"]
    if match is not None and match.identity_confidence in ("EXACT", "HIGH"):
        score += VALIDATION_WEIGHTS["identity_confirmed"]
    if match is not None and match.dependency.version and match.dependency.version_confidence not in ("UNKNOWN", None):
        score += VALIDATION_WEIGHTS["version_confirmed"]
    # penalties
    blockers = {b["blocker"] for b in claim.blockers}
    if B_MISSING_VERSION in blockers:
        score -= VALIDATION_PENALTIES["unknown_version"]
    if B_UNKNOWN_NATIVE_TARGET in blockers:
        score -= VALIDATION_PENALTIES["unknown_native_target"]
    if B_UNRESOLVED_IPC_TARGET in blockers:
        score -= VALIDATION_PENALTIES["unresolved_ipc_target"]
    if B_MISSING_PROVIDER_RECORD in blockers:
        score -= VALIDATION_PENALTIES["missing_provider_record"]
    if B_AMBIGUOUS_IDENTITY in blockers:
        score -= VALIDATION_PENALTIES["ambiguous_identity"]
    if match is not None and match.reachability_state == "NOT_REACHABLE":
        score -= VALIDATION_PENALTIES["not_reachable"]
    if match is not None and match.version_state == "POSSIBLY_AFFECTED":
        score -= VALIDATION_PENALTIES["possibly_affected"]
    return max(0, min(100, score))


_RUNTIME_CLAIM_TYPES = {C_RUNTIME_OBSERVED, C_RT_COMPONENT_DISPATCH, C_RT_REFLECTION, C_RT_DYNAMIC_LOAD,
                        C_RT_JNI_INVOCATION, C_RT_NATIVE_API_INVOCATION, C_RT_WEBVIEW, C_RT_IPC, C_RT_NETWORK}


def _required_capabilities(claim_type: str) -> list[str]:
    if claim_type in _RUNTIME_CLAIM_TYPES:
        return ["runtime_device", "frida_or_adb_observation"]
    if claim_type in (C_NATIVE_CALL_PATH, C_NATIVE_API_REACHABILITY):
        return ["static_analysis", "ghidra_call_graph"]
    return ["static_analysis"]


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def build_claims(analysis) -> list[VClaim]:
    """Deterministic list of validation claims (pure — no persistence)."""
    ctx = {"reach_by_rule": {p.rule_id: p for p in sorted(analysis.reachability_paths, key=lambda p: p.length)
                             if p.status == "REACHABLE" and p.rule_id}}
    claims = _finding_claims(analysis, ctx) + _cve_claims(analysis) + _ipc_claims(analysis) + \
        _jni_claims(analysis) + _native_deep_claims(analysis) + _runtime_validation_claims(analysis) + \
        _remediation_claims(analysis)
    # deterministic dedup by fingerprint
    merged: dict[str, VClaim] = {}
    for c in claims:
        if c.fingerprint not in merged:
            merged[c.fingerprint] = c
        else:
            _merge_claim(merged[c.fingerprint], c)
    out = list(merged.values())
    order = {VS_MULTI_SOURCE: 0, VS_RUNTIME_CORROBORATED: 1, VS_STATIC_SUPPORTED: 2, VS_INCONCLUSIVE: 3,
             VS_BLOCKED: 4, VS_UNVERIFIED: 5, VS_NOT_APPLICABLE: 6, VS_SUPERSEDED: 7}
    out.sort(key=lambda c: (order.get(c.state, 9), -c.confidence, c.fingerprint))
    return out


def _merge_claim(base: VClaim, other: VClaim) -> None:
    seen = {e.fingerprint for e in base.evidence}
    for e in other.evidence:
        if e.fingerprint not in seen:
            base.evidence.append(e)
            seen.add(e.fingerprint)
    for b in other.blockers:
        if b["blocker"] not in {x["blocker"] for x in base.blockers}:
            base.blockers.append(b)
    base.uncertainty.extend(u for u in other.uncertainty if u not in base.uncertainty)


def _summary(claims: list[VClaim]) -> dict:
    from collections import Counter
    return {
        "total": len(claims),
        "by_state": dict(Counter(c.state for c in claims)),
        "by_claim_type": dict(Counter(c.claim_type for c in claims)),
        "blockers": dict(Counter(b["blocker"] for c in claims for b in c.blockers)),
        "static_supported": sum(1 for c in claims if c.state == VS_STATIC_SUPPORTED),
        "multi_source": sum(1 for c in claims if c.state == VS_MULTI_SOURCE),
        "runtime_corroborated": sum(1 for c in claims if c.state == VS_RUNTIME_CORROBORATED),
        "unverified": sum(1 for c in claims if c.state == VS_UNVERIFIED),
        "blocked": sum(1 for c in claims if c.state == VS_BLOCKED),
        "uncertainties": sorted({u for c in claims for u in c.uncertainty}),
        "live_runtime_validation": "AVAILABLE" if any(
            e.family == F_RUNTIME and e.live for c in claims for e in c.evidence) else "UNAVAILABLE",
    }


def claim_to_dict(c: VClaim) -> dict:
    return {
        "id": c.fingerprint, "fingerprint": c.fingerprint, "claim_type": c.claim_type,
        "target_type": c.target_type, "target": c.target, "current_state": c.current_state,
        "validation_state": c.state, "confidence": c.confidence, "evidence_count": len(c.evidence),
        "independent_source_count": c.independent_source_count, "source_families": sorted(c.families),
        "finding_id": str(c.finding_id) if c.finding_id else None, "remediation_ref": c.remediation_ref,
        "required_capabilities": c.provenance.get("required_capabilities", []),
        "missing_evidence": [b["missing"] for b in c.blockers],
        "blockers": c.blockers, "requirements": c.requirements, "uncertainty": c.uncertainty,
        "evidence": [{"source_family": e.family, "source_type": e.source_type, "source_id": e.source_id,
                      "confidence": e.confidence, "live": e.live, "detail": e.detail} for e in c.evidence],
        "provenance": c.provenance,
    }


def validation_view(analysis) -> dict:
    claims = build_claims(analysis)
    plan_fp = hashlib.sha256("|".join(sorted(c.fingerprint for c in claims)).encode()).hexdigest()[:32]
    return {
        "fingerprint": plan_fp, "summary": _summary(claims),
        "claims": [claim_to_dict(c) for c in claims],
        "blockers": [{"claim": c.fingerprint, **b} for c in claims for b in c.blockers],
        "requirements": [{"claim": c.fingerprint, **r} for c in claims for r in c.requirements],
        "uncertainties": _summary(claims)["uncertainties"],
        "note": "Validation is evidence quality/verification state only — never exploitability. UNKNOWN / "
                "NOT_REACHABLE / NOT_OBSERVED / POSSIBLY_AFFECTED are preserved.",
    }


# ---------------------------------------------------------------------------
# Persistence (idempotent — no duplicate records on repeated runs)
# ---------------------------------------------------------------------------


def build_validation(db, analysis, requested_by: str = "orchestrator") -> list[ValidationClaim]:
    """Build + persist validation claims; update additive finding columns.
    Idempotent: existing claims for the analysis are replaced. Never mutates
    finding severity/confidence/runtime_status or any score."""
    # Clear via the delete-orphan collection so the in-memory list stays
    # consistent (db.delete leaves stale entries and duplicates on rebuild).
    analysis.validation_claims.clear()
    db.flush()

    claims = build_claims(analysis)
    finding_agg: dict = {}
    for c in claims:
        row = ValidationClaim(
            analysis_id=analysis.id, finding_id=c.finding_id, remediation_ref=c.remediation_ref,
            fingerprint=c.fingerprint, claim_type=c.claim_type, target_type=c.target_type, target=c.target,
            current_state=c.current_state, validation_state=c.state, confidence=c.confidence,
            evidence_count=len(c.evidence), independent_source_count=c.independent_source_count,
            source_families=sorted(c.families), required_capabilities=c.provenance.get("required_capabilities", []),
            missing_evidence=[b["missing"] for b in c.blockers], uncertainty=c.uncertainty, provenance=c.provenance,
            created_at=_now())
        analysis.validation_claims.append(row)
        for e in c.evidence:
            row.evidence.append(ValidationEvidence(
                source_family=e.family, source_type=e.source_type, source_id=e.source_id, confidence=e.confidence,
                live=e.live, detail=e.detail, evidence_json=e.evidence_json, fingerprint=e.fingerprint))
        for b in c.blockers:
            row.blockers.append(ValidationBlocker(blocker=b["blocker"], reason=b["reason"], missing=b["missing"]))
        for r in c.requirements:
            row.requirements.append(ValidationRequirement(
                requirement=r["requirement"], satisfied=r["satisfied"],
                detail=("hard" if r.get("hard") else "soft")))
        if c.finding_id is not None:
            agg = finding_agg.setdefault(c.finding_id, {"claims": 0, "evidence": 0, "blockers": 0,
                                                        "state": VS_UNVERIFIED, "confidence": 0})
            agg["claims"] += 1
            agg["evidence"] += len(c.evidence)
            agg["blockers"] += len(c.blockers)
            if _state_rank(c.state) > _state_rank(agg["state"]):
                agg["state"] = c.state
            agg["confidence"] = max(agg["confidence"], c.confidence)
    db.flush()

    # additive finding validation columns (existing values untouched)
    for f in analysis.findings:
        agg = finding_agg.get(f.id)
        if agg is None:
            continue
        f.security_validation_state = agg["state"]
        f.validation_confidence = agg["confidence"]
        f.validation_claim_count = agg["claims"]
        f.validation_evidence_count = agg["evidence"]
        f.validation_blocker_count = agg["blockers"]
        f.validation_summary = f"{agg['state']} (confidence {agg['confidence']}, {agg['claims']} claim(s))"
    db.flush()
    return list(analysis.validation_claims)


_STATE_ORDER = {VS_UNVERIFIED: 0, VS_NOT_APPLICABLE: 0, VS_BLOCKED: 1, VS_INCONCLUSIVE: 1,
                VS_STATIC_SUPPORTED: 2, VS_RUNTIME_CORROBORATED: 3, VS_MULTI_SOURCE: 4}


def _state_rank(state: str) -> int:
    return _STATE_ORDER.get(state, 0)


# ---------------------------------------------------------------------------
# Explanation engine
# ---------------------------------------------------------------------------


def explain_claim(analysis, claim) -> dict:
    d = claim_to_dict(claim) if hasattr(claim, "fingerprint") else claim
    supported = d["validation_state"] in (VS_STATIC_SUPPORTED, VS_RUNTIME_CORROBORATED, VS_MULTI_SOURCE)
    header = "WHY_IS_THIS_CLAIM_SUPPORTED" if supported else "WHY_IS_THIS_CLAIM_UNVERIFIED"
    reasons: list[str] = []
    fams = d["source_families"]
    reasons.append(f"Claim {d['claim_type']} for {d['target']} is {d['validation_state']} "
                   f"(confidence {d['confidence']}/100).")
    reasons.append(f"Supporting evidence families: {', '.join(fams) or 'none'} "
                   f"({d['independent_source_count']} independent).")
    if any(e["live"] for e in d["evidence"]):
        reasons.append("A LIVE runtime observation corroborates the static evidence (not exploitability).")
    elif any(e["source_family"] == 'RUNTIME' for e in d["evidence"]):
        reasons.append("Runtime evidence is present but MOCKED, so it does not corroborate.")
    if d["blockers"]:
        reasons.append("Blocked by: " + ", ".join(b["blocker"] for b in d["blockers"]) + ".")
    return {
        header: reasons,
        "claim": d["claim_type"], "target": d["target"], "validation_state": d["validation_state"],
        "confidence": d["confidence"], "supporting_evidence": d["evidence"],
        "independent_evidence_families": fams, "blockers": d["blockers"], "requirements": d["requirements"],
        "uncertainties": d["uncertainty"], "provenance": d["provenance"],
        "note": "Validation reflects evidence quality and verification state only — never exploitability.",
    }


# ---------------------------------------------------------------------------
# APK-diff validation transitions
# ---------------------------------------------------------------------------


def validate_comparison(comparison) -> dict:
    """Baseline→candidate validation transitions from an APK comparison.
    A disappeared finding stays NO_LONGER_DETECTED; nothing is inferred 'fixed'
    or 'exploitable' from appearance/disappearance alone."""
    transitions: list[dict] = []
    for f in comparison.finding_changes:
        target = f"{f.rule_id}@{f.component or '-'}"
        if f.change_type == "ADDED":
            transitions.append({"target": target, "baseline_state": "ABSENT", "candidate_state": "CANDIDATE_SUPPORTED",
                                "transition": "NEW_CLAIM", "detail": "new finding in candidate"})
        elif f.change_type == "REMOVED":
            transitions.append({"target": target, "baseline_state": "BASELINE_SUPPORTED",
                                "candidate_state": "NO_LONGER_DETECTED", "transition": "NO_LONGER_DETECTED",
                                "detail": "finding no longer detected — not proven remediated/fixed"})
        else:
            transitions.append({"target": target, "baseline_state": "BASELINE_SUPPORTED",
                                "candidate_state": "CANDIDATE_SUPPORTED", "transition": "CHANGED",
                                "detail": f"dimensions changed: {f.changed_dimensions}"})
    for ch in comparison.changes:
        if ch.category != "cve":
            continue
        if ch.change_type == "ADDED":
            transitions.append({"target": ch.entity_identity, "baseline_state": "ABSENT",
                                "candidate_state": "CANDIDATE_UNVERIFIED", "transition": "NEW_CVE_CLAIM",
                                "detail": "new CVE match in candidate"})
        elif ch.change_type == "REMOVED":
            transitions.append({"target": ch.entity_identity, "baseline_state": "BASELINE_UNVERIFIED",
                                "candidate_state": "NO_LONGER_DETECTED", "transition": "NO_LONGER_DETECTED",
                                "detail": "CVE match no longer present — not inferred fixed"})
    from collections import Counter
    return {"transitions": transitions, "summary": dict(Counter(t["transition"] for t in transitions)),
            "note": "A disappeared finding/CVE is NO_LONGER_DETECTED, not 'fixed'; nothing is 'exploitable'."}

"""Live runtime validation & behavioral corroboration engine (prompt 21).

Correlates persisted runtime observations (LIVE or MOCKED) against the existing
static model — findings, code methods, components, entry points, and the deep
native/JNI graph — and records provenance-backed RuntimeCorrelation evidence plus
a RuntimeValidationRun summary.

Strict rules: runtime evidence NEVER overwrites static truth (severity, score,
static confidence, risk, CVE state, remediation priority are untouched); LIVE and
MOCKED are kept distinct and only genuinely LIVE evidence corroborates; absence of
an observation is NOT proof of safety (NOT_OBSERVED != SAFE); UNKNOWN /
UNKNOWN_NATIVE_TARGET / NOT_REACHABLE / POSSIBLY_AFFECTED are preserved; no native
reachability is fabricated because a native function merely exists; and no
`exploitable` conclusion is ever produced. Deterministic + idempotent.
"""

from __future__ import annotations

import hashlib

from app.core.config import settings
from app.models.runtime_validation import (
    CORR_CONFIRMS, CORR_CORROBORATES, CORR_INVOCATION, CORR_REACHES,
    MODE_LIVE, MODE_MOCKED, MODE_UNAVAILABLE,
    RVS_CONFIRMED, RVS_CORROBORATED, RVS_INCONCLUSIVE, RVS_LIVE_UNAVAILABLE, RVS_NOT_OBSERVED,
    RuntimeCorrelation, RuntimeValidationRun,
)

# --- runtime observation taxonomy (prompt 21 §2) ---------------------------
T_PROCESS = "PROCESS_LIFECYCLE"
T_COMPONENT = "COMPONENT_DISPATCH"
T_ACTIVITY = "ACTIVITY_LAUNCH"
T_SERVICE = "SERVICE_START"
T_BROADCAST = "BROADCAST_DISPATCH"
T_PROVIDER = "CONTENT_PROVIDER_ACCESS"
T_BINDER = "BINDER_TRANSACTION"
T_INTENT = "INTENT_METADATA"
T_DEEPLINK = "DEEP_LINK_DISPATCH"
T_WEBVIEW = "WEBVIEW_NAVIGATION"
T_REFLECTION = "REFLECTION_RESOLUTION"
T_DYNLOAD = "DYNAMIC_CLASS_LOADING"
T_JNI = "JNI_INVOCATION"
T_NATIVE_API = "NATIVE_API_INVOCATION"
T_TLS = "TLS_NETWORK"
T_FILE = "FILESYSTEM_ACCESS"
T_SECURITY_CONFIG = "SECURITY_SENSITIVE_CONFIG"
T_UNKNOWN = "RUNTIME_BEHAVIOR"

# Finding categories runtime instrumentation can plausibly observe.
_OBSERVABLE_CATEGORIES = {"webview", "reflection", "crypto", "native", "reachability", "semantic"}


def _fp(*parts) -> str:
    return hashlib.sha256("|".join("" if p is None else str(p) for p in parts).encode()).hexdigest()[:32]


def classify_observation(obs) -> str:
    """Map a runtime observation to the higher-level taxonomy. Deterministic;
    based on observation type + class/method/symbol names only (never on argument
    values)."""
    otype = (obs.observation_type or "").upper()
    if otype == "PROCESS":
        return T_PROCESS
    if obs.observation_type == "NATIVE" or obs.symbol:
        sym = (obs.symbol or "").lower()
        if sym in ("jni_onload", "jni_onunload", "registernatives") or sym.startswith("java_"):
            return T_JNI
        return T_NATIVE_API
    cls = (obs.class_name or "")
    method = (obs.method_name or "")
    key = f"{cls}.{method}".lower()
    if "webview" in key:
        return T_WEBVIEW
    if "class.forname" in key or "method.invoke" in key or "reflect" in key:
        return T_REFLECTION
    if "classloader" in key or "loadlibrary" in key or "loadclass" in key:
        return T_DYNLOAD
    if "sslcontext" in key or "ssl" in key or "trustmanager" in key or "x509" in key:
        return T_TLS
    if "messagedigest" in key or "cipher" in key or "mac.getinstance" in key or "keystore" in key:
        return T_SECURITY_CONFIG
    if "onbind" in method.lower() or "ontransact" in method.lower() or "binder" in key:
        return T_BINDER
    if "getdata" in key or "getqueryparameter" in key or "uri" in cls.lower():
        return T_DEEPLINK
    if "getaction" in key or "getextra" in key or "getstringextra" in key or "intent" in cls.lower():
        return T_INTENT
    if "contentprovider" in key or ".query" in key or ".insert" in key:
        return T_PROVIDER
    if method in ("onCreate", "onResume", "onNewIntent", "onStart", "onPause"):
        return T_ACTIVITY if "activity" in cls.lower() else T_COMPONENT
    if "service" in cls.lower():
        return T_SERVICE
    if "broadcast" in cls.lower() or "onreceive" in method.lower():
        return T_BROADCAST
    if "fileinputstream" in key or "fileoutputstream" in key or "file" in cls.lower():
        return T_FILE
    return T_UNKNOWN


def _observation_mode(session) -> str:
    """LIVE when the session used a real (non-mock) adapter; MOCKED otherwise.
    LIVE and MOCKED must never be conflated."""
    adapter = (session.metadata_ or {}).get("adapter", "unknown")
    return MODE_LIVE if adapter == "adb" else MODE_MOCKED


def _obs_provenance(obs) -> str:
    return "RUNTIME_FRIDA" if (obs.source or "").upper() == "FRIDA" else "RUNTIME_ADB"


def _clear(analysis) -> None:
    analysis.runtime_correlations.clear()
    analysis.runtime_validation_runs.clear()


def build_runtime_validation(db, analysis, requested_by: str = "cli") -> RuntimeValidationRun:
    """Correlate persisted runtime observations against static entities and persist
    the run + correlations. Idempotent (collections cleared and rebuilt); pure
    supplement — sets only the additive finding ``runtime_validation_state``."""
    _clear(analysis)
    db.flush()

    sessions = list(analysis.runtime_sessions)
    observations = [(s, o) for s in sessions for o in s.observations]
    live_present = any(_observation_mode(s) == MODE_LIVE and s.observations for s in sessions)
    mocked_present = any(_observation_mode(s) == MODE_MOCKED and s.observations for s in sessions)
    mode = MODE_LIVE if live_present else (MODE_MOCKED if mocked_present else MODE_UNAVAILABLE)

    # taxonomy on each observation (additive, deterministic)
    for _s, o in observations:
        o.taxonomy = classify_observation(o)

    correlations: list[RuntimeCorrelation] = []
    truncated: dict = {}
    max_paths = settings.runtime_max_correlation_paths

    # static indexes (built once — no N×M scans)
    method_nodes = {}
    for n in analysis.code_nodes:
        if n.node_type == "JAVA_METHOD" and n.class_name and n.method_name:
            method_nodes[(n.class_name.rsplit(".", 1)[-1].lower(), n.method_name.lower())] = n
    jni_index = {}
    for j in analysis.native_deep_jni_bindings:
        if j.java_class and j.java_method:
            jni_index[(j.java_class.rsplit(".", 1)[-1].lower(), j.java_method.lower())] = j
    nat_fn_index = {f.normalized_name.lower(): f for f in analysis.native_deep_functions}
    nat_api_index = {}
    for o in analysis.native_api_observations:
        nat_api_index.setdefault(o.api.lower(), o)

    # LIVE and MOCKED observation sets are kept apart — MOCKED never confirms LIVE.
    live_java: set[str] = set()
    mock_java: set[str] = set()
    live_native: set[str] = set()
    mock_native: set[str] = set()

    def _add(subject_type, subject_ref, corr_type, obs, session, detail, subject_key=None, confidence="MEDIUM"):
        if len(correlations) >= max_paths:
            truncated["correlations"] = truncated.get("correlations", 0) + 1
            return False
        obs_mode = _observation_mode(session)
        row = RuntimeCorrelation(
            analysis_id=analysis.id, observation_id=obs.id if obs else None,
            session_id=session.id if session else None,
            fingerprint=_fp(subject_type, subject_key if subject_key is not None else subject_ref, corr_type,
                            obs.taxonomy if obs else None,
                            obs.observation_type if obs else None,
                            obs.class_name if obs else None, obs.method_name if obs else None,
                            obs.symbol if obs else None, obs_mode),
            subject_type=subject_type, subject_ref=subject_ref,
            taxonomy=obs.taxonomy if obs else None, correlation_type=corr_type, mode=obs_mode,
            confidence=confidence, provenance=_obs_provenance(obs) if obs else "RUNTIME_ADB",
            detail=detail, evidence_json={"mode": obs_mode})
        analysis.runtime_correlations.append(row)
        correlations.append(row)
        return True

    for session, obs in observations:
        obs_mode = _observation_mode(session)
        matched = False
        if obs.observation_type == "JAVA" and obs.class_name and obs.method_name:
            simple = obs.class_name.rsplit(".", 1)[-1]
            api = f"{simple}.{obs.method_name}"
            (live_java if obs_mode == MODE_LIVE else mock_java).add(api)
            node = method_nodes.get((simple.lower(), obs.method_name.lower()))
            if node is not None:
                matched |= _add("CODE_METHOD", node.node_key, CORR_CONFIRMS, obs, session,
                                f"runtime dispatch observed for {simple}.{obs.method_name}")
            jni = jni_index.get((simple.lower(), obs.method_name.lower()))
            if jni is not None:
                # Java→JNI→native invocation observed. Only relate when identifiers
                # match persisted deep-native evidence; UNKNOWN targets stay UNKNOWN.
                matched |= _add("JNI_BINDING", jni.fingerprint, CORR_INVOCATION, obs, session,
                                f"runtime invocation observed across JNI {jni.java_class}.{jni.java_method} "
                                f"→ {jni.native_symbol or 'UNKNOWN_NATIVE_TARGET'}")
        elif obs.symbol:
            (live_native if obs_mode == MODE_LIVE else mock_native).add(obs.symbol)
            fn = nat_fn_index.get(obs.symbol.lower())
            if fn is not None:
                matched |= _add("NATIVE_FUNCTION", fn.fingerprint, CORR_INVOCATION, obs, session,
                                f"native function {fn.name} invoked at runtime")
            api = nat_api_index.get(obs.symbol.lower())
            if api is not None:
                matched |= _add("NATIVE_API", api.fingerprint, CORR_REACHES, obs, session,
                                f"native API {api.api} reached at runtime")
        # Fallback: every observed behavior is corroboration evidence even when it
        # matches no persisted static entity (so runtime claims still form). This
        # never fabricates native reachability — subject_type stays RUNTIME_BEHAVIOR.
        if not matched:
            label = (f"{obs.class_name}.{obs.method_name}" if obs.class_name else (obs.symbol or "behavior"))
            _add("RUNTIME_BEHAVIOR", label, CORR_CONFIRMS, obs, session,
                 f"runtime behavior observed: {label} [{obs.taxonomy}]", subject_key=label)

    # Finding correlation (sets only the additive runtime_validation_state).
    corroborated = 0
    instrumented_live = live_present and any(s.instrumentation_enabled for s in sessions)
    for f in analysis.findings:
        state = _finding_runtime_state(f, live_java, live_native, mock_java, mock_native, mode, instrumented_live)
        f.runtime_validation_state = state
        if state in (RVS_CONFIRMED, RVS_CORROBORATED):
            corroborated += 1
            # record the finding-level corroboration (LIVE only reaches here)
            text = " ".join([f.title or ""] + [e.detail or "" for e in f.evidence])
            matched_api = next((a for a in live_java if a in text), None) or \
                next((s for s in live_native if f.category == "native" and s in text), None)
            obs_match = _match_observation(observations, matched_api)
            if obs_match is not None:
                s_obj, o_obj = obs_match
                _add("FINDING", str(f.id),
                     CORR_CONFIRMS if state == RVS_CONFIRMED else CORR_CORROBORATES,
                     o_obj, s_obj, f"finding {f.rule_id} corroborated by runtime {matched_api}",
                     subject_key=f.fingerprint or f.rule_id)

    live_claims = sum(1 for c in correlations if c.mode == MODE_LIVE)
    run_fp = _fp(mode, *sorted(c.fingerprint for c in correlations))
    run = RuntimeValidationRun(
        analysis_id=analysis.id, session_id=sessions[-1].id if sessions else None,
        fingerprint=run_fp, mode=mode,
        device_serial=next((s.device_serial for s in sessions if s.device_serial), None),
        apk_sha256=analysis.apk_sha256,
        observation_count=len(observations),
        event_count=sum(len(s.events) for s in sessions),
        process_count=sum(len(s.processes) for s in sessions),
        artifact_count=sum(len(s.artifacts) for s in sessions),
        correlation_count=len(correlations), live_claim_count=live_claims,
        corroborated_finding_count=corroborated, truncated=truncated,
        blockers=_blockers(mode, sessions),
        summary={"mode": mode, "sessions": len(sessions),
                 "by_taxonomy": _count(o.taxonomy for _s, o in observations),
                 "by_correlation_type": _count(c.correlation_type for c in correlations),
                 "live_claims": live_claims})
    analysis.runtime_validation_runs.append(run)
    db.flush()
    return run


def _finding_runtime_state(finding, live_java, live_native, mock_java, mock_native,
                           mode, instrumented_live) -> str:
    text = " ".join([finding.title or ""] + [e.detail or "" for e in finding.evidence])
    live_confirm_java = any(api in text for api in live_java)
    live_confirm_native = finding.category == "native" and any(s in text for s in live_native)
    mock_confirm = any(api in text for api in mock_java) or \
        (finding.category == "native" and any(s in text for s in mock_native))
    # LIVE evidence takes precedence; MOCKED never confirms.
    if mode == MODE_LIVE and live_confirm_java:
        return RVS_CONFIRMED
    if mode == MODE_LIVE and live_confirm_native:
        return RVS_CORROBORATED
    if mode == MODE_LIVE and instrumented_live and finding.category in _OBSERVABLE_CATEGORIES:
        return RVS_NOT_OBSERVED  # ran live but did not observe this behavior — NOT_OBSERVED != SAFE
    if mock_confirm:
        return RVS_INCONCLUSIVE  # only MOCKED matched — inconclusive, never confirmed
    if mode == MODE_MOCKED:
        return RVS_INCONCLUSIVE
    return RVS_LIVE_UNAVAILABLE


def _match_observation(observations, api_or_symbol):
    if not api_or_symbol:
        return None
    for s, o in observations:
        if o.class_name and o.method_name and f"{o.class_name.rsplit('.', 1)[-1]}.{o.method_name}" == api_or_symbol:
            return (s, o)
        if o.symbol == api_or_symbol:
            return (s, o)
    return None


def _blockers(mode, sessions) -> list:
    out = []
    if mode == MODE_UNAVAILABLE:
        out.append({"blocker": "LIVE_RUNTIME_UNAVAILABLE", "reason": "no runtime observations recorded"})
    elif mode == MODE_MOCKED:
        out.append({"blocker": "NO_LIVE_OBSERVATION",
                    "reason": "only MOCKED runtime evidence present; MOCKED never corroborates LIVE behavior"})
    return out


def _count(values) -> dict:
    from collections import Counter
    return dict(Counter(v for v in values if v))


# ---------------------------------------------------------------------------
# Views / explanation / diff
# ---------------------------------------------------------------------------


def _latest_run(analysis):
    runs = list(analysis.runtime_validation_runs)
    return max(runs, key=lambda r: r.created_at) if runs else None


def runtime_validation_view(analysis) -> dict:
    run = _latest_run(analysis)
    correlations = list(analysis.runtime_correlations)
    from collections import Counter
    findings_by_state = Counter(f.runtime_validation_state for f in analysis.findings)
    return {
        "mode": run.mode if run else MODE_UNAVAILABLE,
        "fingerprint": run.fingerprint if run else _fp("EMPTY", analysis.apk_sha256),
        "device_serial": run.device_serial if run else None,
        "apk_sha256": analysis.apk_sha256,
        "summary": {
            "sessions": len(analysis.runtime_sessions),
            "observations": run.observation_count if run else 0,
            "events": run.event_count if run else 0,
            "processes": run.process_count if run else 0,
            "artifacts": run.artifact_count if run else 0,
            "correlations": len(correlations),
            "live_claims": run.live_claim_count if run else 0,
            "corroborated_findings": run.corroborated_finding_count if run else 0,
            "by_taxonomy": (run.summary or {}).get("by_taxonomy", {}) if run else {},
            "by_correlation_type": _count(c.correlation_type for c in correlations),
            "finding_states": dict(findings_by_state),
        },
        "correlations": [_corr_dict(c) for c in correlations][:1000],
        "blockers": run.blockers if run else [{"blocker": "LIVE_RUNTIME_UNAVAILABLE",
                                               "reason": "no runtime validation run"}],
        "truncated": run.truncated if run else {},
        "uncertainties": _uncertainties(run, correlations),
        "provenance": sorted({c.provenance for c in correlations}) or ["RUNTIME_ADB"],
        "note": "Runtime evidence supplements static analysis; NOT_OBSERVED does not mean safe, MOCKED never "
                "corroborates LIVE behavior, UNKNOWN_NATIVE_TARGET is preserved, and no exploitability is asserted.",
    }


def _corr_dict(c) -> dict:
    return {"id": c.fingerprint, "subject_type": c.subject_type, "subject_ref": c.subject_ref,
            "correlation_type": c.correlation_type, "taxonomy": c.taxonomy, "mode": c.mode,
            "confidence": c.confidence, "provenance": c.provenance, "detail": c.detail}


def _uncertainties(run, correlations) -> list[str]:
    out = []
    if run is None or run.mode == MODE_UNAVAILABLE:
        out.append("no LIVE runtime evidence; runtime states are LIVE_UNAVAILABLE (not safe)")
    elif run.mode == MODE_MOCKED:
        out.append("runtime evidence is MOCKED; it never counts as LIVE corroboration")
    if any(c.subject_type == "JNI_BINDING" and "UNKNOWN_NATIVE_TARGET" in c.detail for c in correlations):
        out.append("a JNI target remains UNKNOWN_NATIVE_TARGET despite runtime invocation")
    if run and run.truncated:
        out.append(f"evidence TRUNCATED: {run.truncated}")
    return out


def runtime_explain(analysis, subject: str) -> dict:
    """Full evidence chain for a finding (by rule id / id) or a subject ref:
    Finding → static evidence → attack surface → reachability → runtime session →
    LIVE observation → correlated target → validation claim → requirements →
    blockers → current validation state. Every step retains provenance."""
    finding = next((f for f in analysis.findings
                    if str(f.id) == subject or f.rule_id == subject or (f.component or "") == subject), None)
    chain: list[dict] = []
    run = _latest_run(analysis)
    mode = run.mode if run else MODE_UNAVAILABLE

    if finding is not None:
        chain.append({"step": "FINDING", "detail": f"{finding.rule_id} [{finding.severity}/{finding.confidence}] "
                      f"status={finding.status}", "provenance": "STATIC"})
        for e in finding.evidence[:6]:
            chain.append({"step": "STATIC_EVIDENCE", "detail": f"{e.source}: {e.detail}",
                          "provenance": (e.source or "STATIC").upper()})
        for n in analysis.attack_surface_nodes:
            if n.component and finding.component and n.component == finding.component:
                chain.append({"step": "ATTACK_SURFACE", "detail": f"{n.name} exposure={n.exposure}",
                              "provenance": "STATIC"})
                break
        for p in analysis.reachability_paths:
            if p.rule_id == finding.rule_id and p.status == "REACHABLE":
                chain.append({"step": "REACHABILITY", "detail": f"REACHABLE ({p.length} nodes)",
                              "provenance": "STATIC_REACHABILITY"})
                break

    corrs = [c for c in analysis.runtime_correlations
             if (finding and c.subject_ref == str(finding.id)) or c.subject_ref == subject]
    for s in analysis.runtime_sessions:
        if s.observations:
            chain.append({"step": "RUNTIME_SESSION", "detail": f"session {str(s.id)[:8]} state={s.session_state} "
                          f"adapter={(s.metadata_ or {}).get('adapter')}",
                          "provenance": "RUNTIME_ADB", "mode": _observation_mode(s)})
            break
    for c in corrs[:10]:
        chain.append({"step": "LIVE_OBSERVATION" if c.mode == MODE_LIVE else "MOCKED_OBSERVATION",
                      "detail": c.detail, "provenance": c.provenance, "mode": c.mode})
        chain.append({"step": "CORRELATED_TARGET",
                      "detail": f"{c.correlation_type} → {c.subject_type} {c.subject_ref[:40]}",
                      "provenance": c.provenance, "mode": c.mode})

    # validation claim tie-in
    claim_state = None
    try:
        from app.analysis.validation import build_claims
        claims = build_claims(analysis)
        if finding is not None:
            claim = next((cl for cl in claims if cl.finding_id == finding.id), None)
            if claim is not None:
                claim_state = claim.state
                chain.append({"step": "VALIDATION_CLAIM", "detail": f"{claim.claim_type} → {claim.state}",
                              "provenance": "VALIDATION"})
                chain.append({"step": "REQUIREMENTS",
                              "detail": ", ".join(r["requirement"] for r in claim.requirements) or "none",
                              "provenance": "VALIDATION"})
                chain.append({"step": "BLOCKERS", "detail": ", ".join(b["blocker"] for b in claim.blockers) or "none",
                              "provenance": "VALIDATION"})
    except Exception:  # validation is optional in the chain
        pass

    chain.append({"step": "CURRENT_VALIDATION_STATE",
                  "detail": (finding.runtime_validation_state if finding else RVS_LIVE_UNAVAILABLE)
                  + (f" / static:{claim_state}" if claim_state else ""),
                  "provenance": "RUNTIME"})
    return {"subject": subject, "mode": mode, "chain": chain,
            "note": "Every step retains provenance; runtime never overwrites static truth and asserts no "
                    "exploitability. NOT_OBSERVED does not mean safe."}


def runtime_validation_from_diff(comparison) -> dict:
    """Runtime-behavior diff between baseline and candidate. Only compares when
    both analyses carry LIVE runtime evidence. Removed behavior is NO_LONGER_OBSERVED
    (never FIXED); security impact stays conservative."""
    a, b = comparison.baseline, comparison.candidate
    va, vb = runtime_validation_view(a), runtime_validation_view(b)
    if va["mode"] != MODE_LIVE or vb["mode"] != MODE_LIVE:
        return {"status": "RUNTIME_OBSERVATION_UNAVAILABLE", "baseline_mode": va["mode"],
                "candidate_mode": vb["mode"],
                "note": "runtime behavior diff requires LIVE runtime evidence in both analyses"}
    a_idx = {c["id"]: c for c in va["correlations"]}
    b_idx = {c["id"]: c for c in vb["correlations"]}
    changes = []
    for fp in sorted(set(a_idx) - set(b_idx)):
        changes.append({"category": "RUNTIME_BEHAVIOR_REMOVED", "transition": "NO_LONGER_OBSERVED",
                        "detail": a_idx[fp]["detail"], "security_relevant": False})
    for fp in sorted(set(b_idx) - set(a_idx)):
        changes.append({"category": "RUNTIME_BEHAVIOR_ADDED", "transition": "NEWLY_OBSERVED",
                        "detail": b_idx[fp]["detail"],
                        "security_relevant": b_idx[fp]["correlation_type"] in (CORR_REACHES, CORR_INVOCATION)})
    unchanged = len(set(a_idx) & set(b_idx))
    return {"status": "OK", "baseline_fingerprint": va["fingerprint"], "candidate_fingerprint": vb["fingerprint"],
            "changes": changes, "unchanged": unchanged,
            "note": "removed runtime behavior is NO_LONGER_OBSERVED, never FIXED; conservative security impact"}

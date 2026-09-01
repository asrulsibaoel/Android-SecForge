"""Deterministic CVE evidence chain (prompt 16).

Builds the auditable chain behind one CVE match without re-running analysis:

    APK → dependency → extracted version → normalized identity → CVE
        → affected range → fixed versions → vulnerable class/method
        → code node → reachability

Every step records source, confidence, provider, and a reason. UNKNOWN /
POSSIBLY_AFFECTED states are preserved verbatim; nothing is called "exploitable".
"""

from __future__ import annotations


def _ev(payload, kind):
    for item in payload or []:
        if item.get("kind") == kind:
            return item.get("detail")
    return None


def explain_match(analysis, match) -> dict:
    dep = match.dependency
    vuln = match.vulnerability
    payload = match.evidence or []
    apk = analysis.apk_sha256
    provider = vuln.source if vuln else _provider_from_evidence(payload)

    steps: list[dict] = []

    def step(name, source, confidence, detail, reason, **extra):
        steps.append({"step": name, "source": source, "confidence": confidence, "detail": detail,
                      "reason": reason, "provider": provider, **extra})

    step("apk", "DEX", "HIGH", f"APK sha256={apk}", "the analyzed artifact")
    step("dependency", "STATIC_RULE", dep.identity_confidence,
         f"{dep.name} ({dep.ecosystem}/{dep.kind})", "dependency inventory identified this component",
         artifact=dep.artifact)
    step("version", dep.version_source or "UNKNOWN", dep.version_confidence,
         f"version={dep.version or 'UNKNOWN'}",
         "version recovered from embedded metadata" if dep.version else
         "no trustworthy version evidence — treated as POSSIBLY_AFFECTED if a range applies")
    step("identity", "CVE_DATABASE", match.identity_confidence, _ev(payload, "identity") or "identity match",
         "normalized identity match between dependency and CVE affected product")
    step("cve", "CVE_DATABASE", match.match_confidence,
         f"{match.cve_id} (provider {provider}, severity {vuln.severity if vuln else '-'})",
         "vulnerability record from the local intelligence database")
    step("affected_range", "CVE_DATABASE", "HIGH", _ev(payload, "affected_range") or "-",
         "affected version range as supplied by the provider")
    if match.fixed_versions:
        step("fixed_versions", "CVE_DATABASE", "HIGH",
             f"earliest_fixed={match.earliest_fixed_version}; all={', '.join(match.fixed_versions)}",
             "provider-supplied fixed versions (never invented)")
    step("version_state", "CVE_DATABASE", match.identity_confidence, match.version_state,
         _version_reason(match))
    sig_detail = _ev(payload, "signature")
    if sig_detail:
        step("signature", "CVE_DATABASE", "MEDIUM", sig_detail,
             "provider vulnerable-code signature correlated against the canonical graph")
    step("reachability", "REACHABILITY", "MEDIUM", match.reachability_state,
         _reach_reason(match))

    intel = _external_intel(vuln)
    return {
        "cve_id": match.cve_id, "match_id": str(match.id), "correlation_state": match.correlation_state,
        "version_state": match.version_state, "reachability_state": match.reachability_state,
        "signature_state": match.signature_state, "identity_confidence": match.identity_confidence,
        "external_intelligence": intel,  # KEV/EPSS — separate axis, NOT exploitability
        "chain": steps,
        "note": "Evidence chain is deterministic and provider-attributed. External signals (KEV/EPSS) are "
                "intelligence only and are not an AndroidSecForge exploitability conclusion.",
    }


def _version_reason(match) -> str:
    return {
        "AFFECTED": "installed version falls inside the affected range",
        "NOT_AFFECTED": "installed version is outside the affected range",
        "POSSIBLY_AFFECTED": "identity present and an affected range exists, but the version is unknown/unparseable",
        "UNKNOWN": "no comparable version or affected range — state deliberately left UNKNOWN",
    }.get(match.version_state, "state preserved verbatim")


def _reach_reason(match) -> str:
    return {
        "REACHABLE": "vulnerable code is reachable from an entry point via the canonical graph",
        "NOT_REACHABLE": "vulnerable component present but not reachable from any entry point",
        "PRESENT": "component present; reachability not evaluated",
        "UNKNOWN": "reachability could not be determined (e.g. package not in decompiled code) — left UNKNOWN",
    }.get(match.reachability_state, "state preserved verbatim")


def _external_intel(vuln) -> dict:
    if vuln is None:
        return {"known_exploited": "UNKNOWN", "epss_score": None, "epss_percentile": None}
    return {
        "known_exploited": bool(vuln.known_exploited) if vuln.known_exploited is not None else "UNKNOWN",
        "epss_score": vuln.epss_score, "epss_percentile": vuln.epss_percentile,
        "note": "KEV/EPSS are external provider signals, kept separate from AndroidSecForge severity/risk",
    }


def _provider_from_evidence(payload) -> str:
    detail = _ev(payload, "cve") or ""
    if "source=" in detail:
        return detail.split("source=", 1)[1].split()[0]
    return "unknown"

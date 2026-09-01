"""Deterministic multi-provider conflict resolution (prompt 16).

When several providers describe the same CVE (stored as one Vulnerability row per
provider sharing a cve_id), we never arbitrarily overwrite. We keep every
provider's values and derive a canonical view with an explicit, deterministic
resolution reason and a list of disagreements.
"""

from __future__ import annotations

# Deterministic provider precedence for tie-breaking only (never overrides a
# higher CVSS score). Lower index = higher precedence.
_PROVIDER_PRECEDENCE = ["nvd", "ghsa", "osv", "import", "test", "local", "bundle"]

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "MODERATE": 2, "LOW": 1, "NONE": 0}


def _precedence(provider: str | None) -> int:
    try:
        return _PROVIDER_PRECEDENCE.index((provider or "").lower())
    except ValueError:
        return len(_PROVIDER_PRECEDENCE)


def _sev_rank(sev: str | None) -> int:
    return _SEV_RANK.get((sev or "").upper(), -1)


def resolve(vulns: list) -> dict:
    """Resolve a group of Vulnerability rows (same cve_id, different providers)."""
    if not vulns:
        return {}
    ordered = sorted(vulns, key=lambda v: (_precedence(v.source), v.source or ""))

    # canonical severity: highest CVSS score wins; ties broken by provider precedence,
    # then by severity rank. Deterministic.
    def sev_key(v):
        return (v.cvss_score if v.cvss_score is not None else -1.0,
                -_precedence(v.source), _sev_rank(v.severity))
    sev_source = max(ordered, key=sev_key)
    canonical_severity = sev_source.severity
    canonical_cvss = sev_source.cvss_score

    severities = {v.source: v.severity for v in ordered if v.severity}
    cvss = {v.source: v.cvss_score for v in ordered if v.cvss_score is not None}
    published = {v.source: v.published_at for v in ordered if v.published_at}
    modified = {v.source: v.provider_modified_at or v.modified_at for v in ordered
                if (v.provider_modified_at or v.modified_at)}

    disagreements = []
    if len({(s or "").upper() for s in severities.values()}) > 1:
        disagreements.append({"field": "severity", "values": severities})
    if len(set(cvss.values())) > 1:
        disagreements.append({"field": "cvss_score", "values": cvss})
    if len({(p or "") for p in published.values()}) > 1:
        disagreements.append({"field": "published_at", "values": published})

    aliases = sorted({a.alias for v in ordered for a in v.aliases})
    known_exploited = any(v.known_exploited for v in ordered)
    epss = next((v.epss_score for v in sorted(ordered, key=lambda v: -(v.epss_score or -1))
                 if v.epss_score is not None), None)

    reason = (f"canonical severity {canonical_severity} taken from provider "
              f"'{sev_source.source}' (highest CVSS={canonical_cvss}); "
              f"{len(disagreements)} field disagreement(s) preserved")
    return {
        "cve_id": ordered[0].cve_id,
        "providers": [v.source for v in ordered],
        "canonical_severity": canonical_severity,
        "canonical_cvss": canonical_cvss,
        "canonical_source": sev_source.source,
        "resolution_reason": reason,
        "disagreements": disagreements,
        "aliases": aliases,
        "known_exploited": known_exploited,
        "epss_score": epss,
        "provider_values": {
            "severity": severities, "cvss_score": cvss, "published_at": published, "modified_at": modified,
        },
    }

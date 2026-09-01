"""High-level vulnerability-intelligence service used by CLI + REST (prompt 16).

Thin, deterministic wrappers over the intel modules and the local CVE database.
All responses preserve UNKNOWN / POSSIBLY_AFFECTED and keep KEV/EPSS separate
from AndroidSecForge severity/risk.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.intel import conflicts, freshness
from app.intel.providers import providers_status
from app.models.cve import (
    AffectedProduct, Vulnerability, VulnerabilityIdentity, VulnerabilityScore, VulnerabilitySignature,
)


def providers() -> list[dict]:
    return providers_status()


def _group(db, cve_id: str) -> list[Vulnerability]:
    return list(db.scalars(
        select(Vulnerability)
        .options(selectinload(Vulnerability.products).selectinload(AffectedProduct.ranges),
                 selectinload(Vulnerability.references), selectinload(Vulnerability.aliases),
                 selectinload(Vulnerability.identities), selectinload(Vulnerability.signatures),
                 selectinload(Vulnerability.scores), selectinload(Vulnerability.provider_records))
        .where(Vulnerability.cve_id == cve_id)))


def show(db, cve_id: str) -> dict | None:
    group = _group(db, cve_id)
    if not group:
        return None
    resolution = conflicts.resolve(group)
    primary = group[0]
    return {
        "cve_id": cve_id,
        "canonical": {"severity": resolution["canonical_severity"], "cvss_score": resolution["canonical_cvss"],
                      "source": resolution["canonical_source"], "reason": resolution["resolution_reason"]},
        "providers": resolution["providers"],
        "disagreements": resolution["disagreements"],
        "aliases": resolution["aliases"],
        "external_intelligence": {"known_exploited": resolution["known_exploited"],
                                  "epss_score": resolution["epss_score"],
                                  "note": "external signals — separate from AndroidSecForge severity/risk"},
        "freshness": {"status": freshness.freshness_status(primary),
                      "first_seen": _iso(primary.first_seen), "last_seen": _iso(primary.last_seen),
                      "provider_modified_at": primary.provider_modified_at},
        "descriptions": {v.source: v.description or v.summary for v in group},
        "identities": identities(db, cve_id),
        "signatures": signatures(db, cve_id),
        "references": references(db, cve_id),
        "products": [{"ecosystem": p.ecosystem, "product": p.product, "vendor": p.vendor, "cpe": p.cpe,
                      "purl": p.purl, "package_name": p.package_name, "version_strategy": p.version_strategy,
                      "ranges": [{"introduced": r.introduced, "fixed": r.fixed, "last_affected": r.last_affected,
                                  "exact": r.exact, "raw": r.raw} for r in p.ranges]}
                     for v in group for p in v.products],
        "scores": scores(db, cve_id),
        "test_data": any(v.is_test_data for v in group),
    }


def identities(db, cve_id: str) -> list[dict]:
    rows = db.scalars(
        select(VulnerabilityIdentity).join(Vulnerability).where(Vulnerability.cve_id == cve_id))
    seen, out = set(), []
    for i in rows:
        key = (i.identity_type, i.value)
        if key in seen:
            continue
        seen.add(key)
        out.append({"identity_type": i.identity_type, "value": i.value, "ecosystem": i.ecosystem,
                    "confidence": i.confidence})
    return sorted(out, key=lambda d: (d["identity_type"], d["value"]))


def signatures(db, cve_id: str) -> list[dict]:
    rows = db.scalars(
        select(VulnerabilitySignature).join(Vulnerability).where(Vulnerability.cve_id == cve_id))
    return [{"kind": s.kind, "package": s.package, "class_name": s.class_name, "method": s.method,
             "descriptor": s.descriptor, "field": s.field, "native_symbol": s.native_symbol,
             "api_sequence": s.api_sequence, "provider": s.provider, "confidence": s.confidence}
            for s in rows]


def scores(db, cve_id: str) -> list[dict]:
    rows = db.scalars(
        select(VulnerabilityScore).join(Vulnerability).where(Vulnerability.cve_id == cve_id))
    return [{"kind": s.kind, "provider": s.provider, "score": s.score, "vector": s.vector,
             "severity": s.severity, "percentile": s.percentile, "extra": s.extra} for s in rows]


def references(db, cve_id: str) -> list[str]:
    group = _group(db, cve_id)
    return sorted({r.url for v in group for r in v.references})


def search(db, query: str | None = None, provider: str | None = None, severity: str | None = None,
           ecosystem: str | None = None, package: str | None = None, cpe: str | None = None,
           purl: str | None = None, known_exploited: bool | None = None, min_cvss: float | None = None,
           limit: int = 100) -> list[dict]:
    stmt = select(Vulnerability).distinct()
    if query:
        like = f"%{query.lower()}%"
        stmt = stmt.join(AffectedProduct, isouter=True).where(
            func.lower(Vulnerability.cve_id).like(like)
            | func.lower(func.coalesce(Vulnerability.summary, "")).like(like)
            | func.lower(func.coalesce(AffectedProduct.product, "")).like(like))
    if provider:
        stmt = stmt.where(func.lower(Vulnerability.source) == provider.lower())
    if severity:
        stmt = stmt.where(func.upper(func.coalesce(Vulnerability.severity, "")) == severity.upper())
    if known_exploited is not None:
        stmt = stmt.where(Vulnerability.known_exploited.is_(bool(known_exploited)))
    if min_cvss is not None:
        stmt = stmt.where(Vulnerability.cvss_score >= float(min_cvss))
    if ecosystem or package or cpe or purl:
        from app.models.cve import AffectedProduct as AP
        stmt = stmt.join(AP, isouter=True) if not query else stmt
        if ecosystem:
            stmt = stmt.where(func.lower(AP.ecosystem) == ecosystem.lower())
        if package:
            like = f"%{package.lower()}%"
            stmt = stmt.where(func.lower(func.coalesce(AP.package_name, AP.product)).like(like))
        if cpe:
            stmt = stmt.where(func.lower(func.coalesce(AP.cpe, "")).like(f"%{cpe.lower()}%"))
        if purl:
            stmt = stmt.where(func.lower(func.coalesce(AP.purl, "")).like(f"%{purl.lower()}%"))
    rows = list(db.scalars(stmt.limit(limit)))
    return sorted(({"cve_id": v.cve_id, "provider": v.source, "severity": v.severity, "cvss_score": v.cvss_score,
                    "known_exploited": v.known_exploited, "epss_score": v.epss_score,
                    "test_data": v.is_test_data, "summary": v.summary} for v in rows),
                  key=lambda d: (d["cve_id"], d["provider"] or ""))


def db_freshness(db) -> dict:
    return freshness.db_freshness(db)


def explain_match(db, analysis_id, match_id) -> dict | None:
    from app.intel.explain import explain_match as _explain
    from app.models.analysis import Analysis
    from app.models.cve import VulnerabilityMatch

    analysis = db.get(Analysis, analysis_id)
    match = db.get(VulnerabilityMatch, match_id)
    if analysis is None or match is None or match.analysis_id != analysis.id:
        return None
    return _explain(analysis, match)


def _iso(value):
    return value.isoformat() if value else None

"""Local CVE database operations: import (offline), sync (NVD, best-effort),
search, show. Analysis never calls sync — it reads the local DB only."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.analysis.cve import VulnRecord, ProductRecord, fixture_vulnerabilities, import_records, normalize_nvd
from app.models.cve import AffectedProduct, Vulnerability

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def import_fixtures(db: Session) -> int:
    """Load the deterministic TEST_DATA vulnerability fixtures."""
    return import_records(db, fixture_vulnerabilities(), is_test_data=True)


def import_from_file(db: Session, path: Path, provider: str | None = None) -> dict:
    """Import CVEs from a JSON file. Provider may be forced (nvd|osv|ghsa) or
    auto-detected from the payload shape; a list of pre-normalized records is
    also accepted. Malformed input fails gracefully."""
    from app.intel import providers as P

    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {"status": "FAILED", "error": str(error), "imported": 0}

    detected = (provider or "").lower() or P.detect_provider(payload)
    if detected in P.PROVIDERS and detected != "fixtures":
        try:
            records = P.normalize(detected, payload)
        except Exception as error:  # provider parse failure is isolated
            return {"status": "FAILED", "error": f"{detected} normalize failed: {error}", "imported": 0}
        source = detected
    elif isinstance(payload, list):
        records = [r for r in (_record_from_dict(item) for item in payload) if r is not None]
        source = "import"
    else:
        return {"status": "FAILED", "error": "unrecognized CVE JSON format", "imported": 0}
    count = import_records(db, records, is_test_data=False)
    return {"status": "COMPLETE", "source": source, "imported": count}


def _record_from_dict(item: dict) -> VulnRecord | None:
    try:
        products = [
            ProductRecord(
                ecosystem=p.get("ecosystem", "generic"), product=p["product"], vendor=p.get("vendor"),
                cpe=p.get("cpe"), package_name=p.get("package_name"),
                version_strategy=p.get("version_strategy", "GENERIC"), ranges=p.get("ranges", []))
            for p in item.get("products", [])
        ]
        return VulnRecord(
            cve_id=item["cve_id"], summary=item.get("summary"), description=item.get("description"),
            published_at=item.get("published_at"), modified_at=item.get("modified_at"),
            severity=item.get("severity"), cvss_score=item.get("cvss_score"), cvss_vector=item.get("cvss_vector"),
            cwe=item.get("cwe"), source=item.get("source", "import"), source_id=item.get("source_id"),
            references=item.get("references", []), products=products)
    except (KeyError, TypeError):
        return None


def sync_nvd(db: Session, keyword: str | None = None, results: int = 200) -> dict:
    """Best-effort NVD sync. Never required for analysis; fails gracefully offline."""
    try:
        import httpx
    except ImportError:
        return {"status": "UNAVAILABLE", "error": "httpx not installed", "imported": 0}
    params = {"resultsPerPage": min(results, 2000)}
    if keyword:
        params["keywordSearch"] = keyword
    try:
        response = httpx.get(NVD_API, params=params, timeout=30.0)
        response.raise_for_status()
        payload = response.json()
    except Exception as error:  # network/HTTP errors must not crash anything
        return {"status": "UNAVAILABLE", "error": str(error), "imported": 0}
    count = import_records(db, normalize_nvd(payload), is_test_data=False)
    return {"status": "COMPLETE", "source": "nvd", "imported": count}


def search(db: Session, query: str, limit: int = 50) -> list[dict]:
    like = f"%{query.lower()}%"
    stmt = (
        select(Vulnerability)
        .join(AffectedProduct, isouter=True)
        .where(
            func.lower(Vulnerability.cve_id).like(like)
            | func.lower(func.coalesce(Vulnerability.summary, "")).like(like)
            | func.lower(func.coalesce(AffectedProduct.product, "")).like(like)
        )
        .distinct()
        .limit(limit)
    )
    return [
        {"cve_id": v.cve_id, "severity": v.severity, "cvss_score": v.cvss_score,
         "source": v.source, "test_data": v.is_test_data, "summary": v.summary}
        for v in db.scalars(stmt)
    ]


def show(db: Session, cve_id: str) -> dict | None:
    vuln = db.scalar(
        select(Vulnerability)
        .options(selectinload(Vulnerability.products).selectinload(AffectedProduct.ranges),
                 selectinload(Vulnerability.references))
        .where(Vulnerability.cve_id == cve_id)
    )
    if vuln is None:
        return None
    return {
        "cve_id": vuln.cve_id, "summary": vuln.summary, "description": vuln.description,
        "severity": vuln.severity, "cvss_score": vuln.cvss_score, "cvss_vector": vuln.cvss_vector,
        "cwe": vuln.cwe, "source": vuln.source, "test_data": vuln.is_test_data,
        "published_at": vuln.published_at, "modified_at": vuln.modified_at,
        "references": [r.url for r in vuln.references],
        "products": [
            {"ecosystem": p.ecosystem, "product": p.product, "vendor": p.vendor, "cpe": p.cpe,
             "package_name": p.package_name, "version_strategy": p.version_strategy,
             "ranges": [{"introduced": r.introduced, "fixed": r.fixed, "last_affected": r.last_affected,
                         "exact": r.exact, "raw": r.raw} for r in p.ranges]}
            for p in vuln.products
        ],
    }


def stats(db: Session) -> dict:
    total = db.scalar(select(func.count(Vulnerability.id))) or 0
    test = db.scalar(select(func.count(Vulnerability.id)).where(Vulnerability.is_test_data.is_(True))) or 0
    return {"total": total, "test_data": test, "production": total - test}

"""Multi-provider vulnerability import adapters (prompt 16).

Each adapter normalizes a provider's native format into the canonical
``VulnRecord`` model. Everything works with zero network access; provider
failures are isolated (one provider failing never blocks the others or the local
DB). NVD is never mandatory. Original provider payloads are preserved (bounded)
for auditability via ``VulnRecord.raw``.
"""

from __future__ import annotations

from app.analysis.cve import ProductRecord, VulnRecord, normalize_nvd as _normalize_nvd

PROVIDERS = ("nvd", "osv", "ghsa", "fixtures")


def _severity_from_cvss(score) -> str | None:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    if s > 0.0:
        return "LOW"
    return None


def _cvss_score_from_vector_field(entry: dict):
    """OSV severity entries carry a CVSS vector string; the base score is not
    always numeric there, so return (score_or_None, vector)."""
    vector = entry.get("score") or entry.get("vector")
    return None, vector


# ---------------------------------------------------------------------------
# NVD (delegates to the existing normalizer, then tags provider)
# ---------------------------------------------------------------------------


def normalize_nvd(payload: dict) -> list[VulnRecord]:
    records = _normalize_nvd(payload)
    for r in records:
        r.provider_record_id = r.cve_id
    return records


# ---------------------------------------------------------------------------
# OSV (osv.dev schema; also the on-disk schema GitHub publishes advisories in)
# ---------------------------------------------------------------------------

_OSV_ECOSYSTEM = {"maven": "maven", "npm": "npm", "pypi": "pypi", "go": "go", "cargo": "cargo",
                  "nuget": "nuget", "android": "android"}


def normalize_osv(payload) -> list[VulnRecord]:
    """Accepts a single OSV object, a list of them, or {'vulns': [...]}"""
    items = _osv_items(payload)
    out: list[VulnRecord] = []
    for item in items:
        try:
            rec = _osv_record(item)
            if rec is not None:
                out.append(rec)
        except Exception:  # isolate malformed records
            continue
    return out


def _osv_items(payload) -> list[dict]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        if "vulns" in payload:
            return payload["vulns"]
        return [payload]
    return []


def _osv_record(item: dict) -> VulnRecord | None:
    osv_id = item.get("id")
    if not osv_id:
        return None
    aliases = [a for a in item.get("aliases", []) if a]
    cve_id = next((a for a in [osv_id, *aliases] if a.upper().startswith("CVE-")), osv_id)
    alias_set = [a for a in [osv_id, *aliases] if a and a != cve_id]

    db_specific = item.get("database_specific", {}) or {}
    cwes = list(db_specific.get("cwe_ids", []) or [])
    severity = db_specific.get("severity")
    score, vector = None, None
    scores: list[dict] = []
    for sev in item.get("severity", []) or []:
        _, vec = _cvss_score_from_vector_field(sev)
        vector = vector or vec
        stype = (sev.get("type") or "").upper()
        kind = "CVSS4" if "V4" in stype else ("CVSS31" if "3.1" in (vec or "") else "CVSS3")
        scores.append({"kind": kind, "provider": "osv", "vector": vec, "severity": severity})
    severity = severity or _severity_from_cvss(score)

    products: list[ProductRecord] = []
    signatures: list[dict] = []
    for aff in item.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        eco = _OSV_ECOSYSTEM.get((pkg.get("ecosystem") or "").lower(), "generic")
        name = pkg.get("name") or ""
        purl = pkg.get("purl")
        ranges = _osv_ranges(aff)
        products.append(ProductRecord(
            ecosystem=eco, product=name.split(":")[-1] if name else "", vendor=None,
            purl=purl, package_name=name or None,
            version_strategy="MAVEN" if eco == "maven" else "SEMVER", ranges=ranges))
        # provider-supplied code signatures (imports/symbols), never invented
        for imp in (aff.get("ecosystem_specific", {}) or {}).get("imports", []) or []:
            path = imp.get("path")
            for symbol in imp.get("symbols", []) or []:
                signatures.append({"kind": "METHOD", "class_name": path, "method": symbol,
                                   "provider": "osv", "confidence": "MEDIUM"})

    return VulnRecord(
        cve_id=cve_id, summary=item.get("summary"), description=item.get("details"),
        published_at=item.get("published"), modified_at=item.get("modified"),
        severity=severity, cvss_score=score, cvss_vector=vector, cwe=cwes[0] if cwes else None,
        source="osv", source_id=osv_id, provider_record_id=osv_id, provider_modified_at=item.get("modified"),
        withdrawn_at=item.get("withdrawn"),
        references=[r.get("url") for r in item.get("references", []) if r.get("url")],
        products=products, aliases=alias_set, cwes=cwes, signatures=signatures, scores=scores,
        raw={"id": osv_id, "modified": item.get("modified")})


def _osv_ranges(aff: dict) -> list[dict]:
    ranges: list[dict] = []
    for rng in aff.get("ranges", []) or []:
        introduced = fixed = last_affected = None
        for ev in rng.get("events", []) or []:
            if "introduced" in ev and ev["introduced"] not in ("0", None):
                introduced = ev["introduced"]
            if "fixed" in ev:
                fixed = ev["fixed"]
            if "last_affected" in ev:
                last_affected = ev["last_affected"]
        if introduced or fixed or last_affected:
            ranges.append({"introduced": introduced, "fixed": fixed, "last_affected": last_affected})
    for version in aff.get("versions", []) or []:
        ranges.append({"exact": version})
    return ranges


# ---------------------------------------------------------------------------
# GitHub Advisory Database (REST advisory schema)
# ---------------------------------------------------------------------------


def normalize_ghsa(payload) -> list[VulnRecord]:
    items = payload if isinstance(payload, list) else [payload]
    out: list[VulnRecord] = []
    for item in items:
        try:
            rec = _ghsa_record(item)
            if rec is not None:
                out.append(rec)
        except Exception:
            continue
    return out


def _ghsa_record(item: dict) -> VulnRecord | None:
    ghsa_id = item.get("ghsa_id") or item.get("id")
    if not ghsa_id:
        return None
    cve_id = item.get("cve_id") or ghsa_id
    aliases = [ghsa_id] if cve_id != ghsa_id else []
    for ident in item.get("identifiers", []) or []:
        val = ident.get("value")
        if val and val not in (cve_id, ghsa_id):
            aliases.append(val)

    severity = (item.get("severity") or "").upper() or None
    cvss = item.get("cvss") or {}
    score = cvss.get("score")
    vector = cvss.get("vector_string")
    severity = severity or _severity_from_cvss(score)
    cwes = [c.get("cwe_id") for c in (item.get("cwes", {}) or {}).get("nodes", []) if c.get("cwe_id")]

    products: list[ProductRecord] = []
    for vuln in item.get("vulnerabilities", []) or []:
        pkg = vuln.get("package", {}) or {}
        eco = (pkg.get("ecosystem") or "").lower()
        name = pkg.get("name") or ""
        rng_raw = vuln.get("vulnerable_version_range")
        fixed = (vuln.get("first_patched_version") or {}).get("identifier")
        ranges = []
        if rng_raw:
            ranges.append({"raw": rng_raw})
        if fixed:
            ranges.append({"fixed": fixed})
        products.append(ProductRecord(
            ecosystem="maven" if eco == "maven" else (eco or "generic"),
            product=name.split(":")[-1] if name else "", package_name=name or None,
            version_strategy="MAVEN" if eco == "maven" else "SEMVER", ranges=ranges))

    scores = []
    if score is not None or vector:
        scores.append({"kind": "CVSS31" if vector and "3.1" in vector else "CVSS3",
                       "provider": "ghsa", "score": score, "vector": vector, "severity": severity})
    return VulnRecord(
        cve_id=cve_id, summary=item.get("summary"), description=item.get("description"),
        published_at=item.get("published_at"), modified_at=item.get("updated_at"),
        withdrawn_at=item.get("withdrawn_at"),
        severity=severity, cvss_score=score, cvss_vector=vector, cwe=cwes[0] if cwes else None,
        source="ghsa", source_id=ghsa_id, provider_record_id=ghsa_id, provider_modified_at=item.get("updated_at"),
        references=[r.get("url") for r in item.get("references", []) if r.get("url")],
        products=products, aliases=aliases, cwes=cwes, scores=scores,
        raw={"ghsa_id": ghsa_id})


# ---------------------------------------------------------------------------
# Provider dispatch + status
# ---------------------------------------------------------------------------

_NORMALIZERS = {"nvd": normalize_nvd, "osv": normalize_osv, "ghsa": normalize_ghsa}


def normalize(provider: str, payload) -> list[VulnRecord]:
    provider = (provider or "").lower()
    fn = _NORMALIZERS.get(provider)
    if fn is None:
        raise ValueError(f"unknown provider '{provider}'. Known: {', '.join(_NORMALIZERS)}")
    return fn(payload)


def detect_provider(payload) -> str:
    """Best-effort provider detection from payload shape (deterministic)."""
    if isinstance(payload, dict):
        if "vulnerabilities" in payload and payload.get("vulnerabilities") and \
                isinstance(payload["vulnerabilities"][0], dict) and "cve" in payload["vulnerabilities"][0]:
            return "nvd"
        if "ghsa_id" in payload:
            return "ghsa"
        if "id" in payload and ("affected" in payload or "aliases" in payload):
            return "osv"
        if "vulns" in payload:
            return "osv"
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        if "ghsa_id" in payload[0]:
            return "ghsa"
        if "affected" in payload[0] or "id" in payload[0]:
            return "osv"
    return "unknown"


def providers_status() -> list[dict]:
    """Offline-safe provider capability report (never probes the network)."""
    try:
        import httpx  # noqa: F401
        http = True
    except ImportError:
        http = False
    return [
        {"name": "nvd", "import_supported": True, "sync_supported": http,
         "network": "UNKNOWN" if http else "UNAVAILABLE",
         "note": "NVD 2.0 JSON import always works offline; live sync is best-effort and never required"},
        {"name": "osv", "import_supported": True, "sync_supported": http,
         "network": "UNKNOWN" if http else "UNAVAILABLE",
         "note": "OSV JSON import works offline"},
        {"name": "ghsa", "import_supported": True, "sync_supported": http,
         "network": "UNKNOWN" if http else "UNAVAILABLE",
         "note": "GitHub advisory JSON import works offline"},
        {"name": "fixtures", "import_supported": True, "sync_supported": False,
         "network": "N/A", "note": "deterministic TEST_DATA"},
    ]

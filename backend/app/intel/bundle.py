"""Offline intelligence bundle: create / validate / import / export (prompt 16).

A bundle is a directory:

    asf-intel/
      manifest.json          bundle metadata + overall checksum
      vulnerabilities.jsonl   one normalized vulnerability record per line
      identities.jsonl        flattened identities (for inspection)
      signatures.jsonl        flattened signatures (for inspection)
      checksums.json          sha256 of each data file

Import is deterministic and checksum-verified. A corrupted bundle (any checksum
mismatch or missing file) is reported FAILED and nothing is imported. Partial
provider data stays explicitly partial.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from app.analysis.cve import ProductRecord, VulnRecord, import_records
from app.models.cve import IntelBundle, Vulnerability

BUNDLE_VERSION = "1"
_DATA_FILES = ("vulnerabilities.jsonl", "identities.jsonl", "signatures.jsonl")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _jsonl(records: list[dict]) -> bytes:
    lines = [json.dumps(r, sort_keys=True, default=str) for r in records]
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def vuln_to_dict(vuln: Vulnerability) -> dict:
    return {
        "cve_id": vuln.cve_id, "summary": vuln.summary, "description": vuln.description,
        "published_at": vuln.published_at, "modified_at": vuln.modified_at, "withdrawn_at": vuln.withdrawn_at,
        "provider_modified_at": vuln.provider_modified_at,
        "severity": vuln.severity, "cvss_score": vuln.cvss_score, "cvss_vector": vuln.cvss_vector,
        "cwe": vuln.cwe, "source": vuln.source, "source_id": vuln.source_id,
        "known_exploited": vuln.known_exploited, "epss_score": vuln.epss_score,
        "epss_percentile": vuln.epss_percentile, "is_test_data": vuln.is_test_data,
        "references": [r.url for r in vuln.references],
        "aliases": sorted(a.alias for a in vuln.aliases),
        "cwes": sorted({i.value for i in vuln.identities if i.identity_type == "CWE"}),
        "identities": [{"identity_type": i.identity_type, "value": i.value, "ecosystem": i.ecosystem,
                        "confidence": i.confidence} for i in vuln.identities if i.identity_type != "CWE"],
        "signatures": [{"kind": s.kind, "package": s.package, "class_name": s.class_name, "method": s.method,
                        "descriptor": s.descriptor, "field": s.field, "native_symbol": s.native_symbol,
                        "api_sequence": s.api_sequence, "provider": s.provider, "confidence": s.confidence}
                       for s in vuln.signatures],
        "scores": [{"kind": sc.kind, "provider": sc.provider, "score": sc.score, "vector": sc.vector,
                    "severity": sc.severity, "percentile": sc.percentile, "extra": sc.extra} for sc in vuln.scores],
        "products": [{"ecosystem": p.ecosystem, "product": p.product, "vendor": p.vendor, "cpe": p.cpe,
                      "purl": p.purl, "package_name": p.package_name, "version_strategy": p.version_strategy,
                      "ranges": [{"introduced": r.introduced, "fixed": r.fixed, "last_affected": r.last_affected,
                                  "exact": r.exact, "raw": r.raw} for r in p.ranges]}
                     for p in vuln.products],
    }


def record_from_dict(d: dict) -> VulnRecord | None:
    try:
        products = [ProductRecord(
            ecosystem=p.get("ecosystem", "generic"), product=p.get("product", ""), vendor=p.get("vendor"),
            cpe=p.get("cpe"), purl=p.get("purl"), package_name=p.get("package_name"),
            version_strategy=p.get("version_strategy", "GENERIC"), ranges=p.get("ranges", []))
            for p in d.get("products", [])]
        return VulnRecord(
            cve_id=d["cve_id"], summary=d.get("summary"), description=d.get("description"),
            published_at=d.get("published_at"), modified_at=d.get("modified_at"),
            withdrawn_at=d.get("withdrawn_at"), provider_modified_at=d.get("provider_modified_at"),
            severity=d.get("severity"), cvss_score=d.get("cvss_score"), cvss_vector=d.get("cvss_vector"),
            cwe=d.get("cwe"), source=d.get("source", "bundle"), source_id=d.get("source_id"),
            provider_record_id=d.get("source_id"),
            known_exploited=bool(d.get("known_exploited")), epss_score=d.get("epss_score"),
            epss_percentile=d.get("epss_percentile"),
            references=d.get("references", []), aliases=d.get("aliases", []), cwes=d.get("cwes", []),
            identities=d.get("identities", []), signatures=d.get("signatures", []), scores=d.get("scores", []),
            products=products)
    except (KeyError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Create / export
# ---------------------------------------------------------------------------


def create_bundle(db, out_dir: str | Path, name: str = "asf-intel", include_test: bool = True,
                  now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)

    query = select(Vulnerability)
    if not include_test:
        query = query.where(Vulnerability.is_test_data.is_(False))
    vulns = sorted(db.scalars(query), key=lambda v: (v.cve_id, v.source or ""))

    vuln_dicts = [vuln_to_dict(v) for v in vulns]
    identity_rows, signature_rows = [], []
    providers: set[str] = set()
    for vd in vuln_dicts:
        providers.add(vd["source"])
        for ident in vd["identities"]:
            identity_rows.append({"cve_id": vd["cve_id"], **ident})
        for sig in vd["signatures"]:
            signature_rows.append({"cve_id": vd["cve_id"], **sig})

    files = {"vulnerabilities.jsonl": _jsonl(vuln_dicts),
             "identities.jsonl": _jsonl(identity_rows),
             "signatures.jsonl": _jsonl(signature_rows)}
    checksums = {name_: _sha256_bytes(data) for name_, data in files.items()}
    for name_, data in files.items():
        (root / name_).write_bytes(data)
    checksums_bytes = json.dumps(checksums, sort_keys=True).encode("utf-8")
    (root / "checksums.json").write_bytes(checksums_bytes)

    manifest = {
        "bundle_version": BUNDLE_VERSION, "name": name, "created_at": now.isoformat(),
        "providers": sorted(providers),
        "counts": {"vulnerabilities": len(vuln_dicts), "identities": len(identity_rows),
                   "signatures": len(signature_rows)},
        "checksum": _sha256_bytes(checksums_bytes),
    }
    (root / "manifest.json").write_bytes(json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8"))
    return {"status": "COMPLETE", "path": str(root), "checksum": manifest["checksum"], **manifest["counts"]}


# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------


def validate_bundle(path: str | Path) -> dict:
    root = Path(path)
    errors: list[str] = []
    if not (root / "manifest.json").is_file() or not (root / "checksums.json").is_file():
        return {"status": "FAILED", "errors": ["missing manifest.json or checksums.json"]}
    try:
        manifest = json.loads((root / "manifest.json").read_text())
        checksums = json.loads((root / "checksums.json").read_text())
    except (OSError, json.JSONDecodeError) as error:
        return {"status": "FAILED", "errors": [f"unreadable metadata: {error}"]}

    # Verify manifest's checksum-of-checksums.
    checksums_bytes = json.dumps(checksums, sort_keys=True).encode("utf-8")
    if manifest.get("checksum") != _sha256_bytes(checksums_bytes):
        errors.append("manifest checksum does not match checksums.json")

    for name_ in _DATA_FILES:
        f = root / name_
        if not f.is_file():
            errors.append(f"missing data file: {name_}")
            continue
        actual = _sha256_bytes(f.read_bytes())
        expected = checksums.get(name_)
        if expected is None:
            errors.append(f"no checksum recorded for {name_}")
        elif actual != expected:
            errors.append(f"checksum mismatch for {name_}")

    status = "FAILED" if errors else "COMPLETE"
    return {"status": status, "errors": errors, "manifest": manifest,
            "counts": manifest.get("counts", {})}


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------


def import_bundle(db, path: str | Path, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    validation = validate_bundle(path)
    if validation["status"] == "FAILED":
        return {"status": "FAILED", "imported": 0, "errors": validation["errors"]}

    root = Path(path)
    records: list[VulnRecord] = []
    try:
        for line in (root / "vulnerabilities.jsonl").read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            rec = record_from_dict(json.loads(line))
            if rec is not None:
                records.append(rec)
    except (OSError, json.JSONDecodeError) as error:
        return {"status": "FAILED", "imported": 0, "errors": [str(error)]}

    imported = import_records(db, records, is_test_data=_all_test(records))
    manifest = validation["manifest"]
    bundle = IntelBundle(
        name=manifest.get("name", "asf-intel"), bundle_version=manifest.get("bundle_version", BUNDLE_VERSION),
        checksum=manifest.get("checksum", ""), status="COMPLETE",
        vulnerability_count=manifest.get("counts", {}).get("vulnerabilities", imported),
        identity_count=manifest.get("counts", {}).get("identities", 0),
        signature_count=manifest.get("counts", {}).get("signatures", 0),
        providers=manifest.get("providers", []), imported_at=now)
    db.add(bundle)
    db.commit()
    return {"status": "COMPLETE", "imported": imported, "checksum": manifest.get("checksum"),
            "providers": manifest.get("providers", [])}


def _all_test(records: list[VulnRecord]) -> bool:
    # Preserve TEST_DATA flag only when the whole bundle is test data.
    return bool(records) and all((r.source or "").lower() in ("test", "fixtures") for r in records)

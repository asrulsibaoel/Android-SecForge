"""CVE intelligence: provider-neutral import, matching, and reachability-aware
correlation.

Offline-first: analysis uses the locally stored vulnerability database and never
requires network access. ``sync`` (NVD) is a separate, best-effort operation. A
library-name match is never sufficient to declare a vulnerability — identity,
version, and reachability confidence are tracked separately and never upgraded
without evidence. ``VALIDATED`` is intentionally not a state in this milestone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.analysis import reachability as R
from app.analysis import versions as V
from app.models.cve import (
    AffectedProduct,
    AffectedVersionRange,
    Dependency,
    Vulnerability,
    VulnerabilityAlias,
    VulnerabilityIdentity,
    VulnerabilityMatch,
    VulnerabilityProviderRecord,
    VulnerabilityReference,
    VulnerabilityScore,
    VulnerabilitySignature,
)

# Version match states
MATCHED, NOT_AFFECTED, POSSIBLY_AFFECTED, UNKNOWN = "AFFECTED", "NOT_AFFECTED", "POSSIBLY_AFFECTED", "UNKNOWN"

# Correlation state machine
NOT_PRESENT = "NOT_PRESENT"
PRESENT_UNKNOWN_VERSION = "PRESENT_UNKNOWN_VERSION"
PRESENT_NOT_AFFECTED = "PRESENT_NOT_AFFECTED"
PRESENT_AFFECTED = "PRESENT_AFFECTED"
AFFECTED_NOT_REACHABLE = "AFFECTED_NOT_REACHABLE"
AFFECTED_REACHABLE = "AFFECTED_REACHABLE"
STATE_UNKNOWN = "UNKNOWN"

# Reachability states
REACH_PRESENT, REACH_AFFECTED, REACH_REACHABLE, REACH_NOT_REACHABLE, REACH_UNKNOWN = (
    "PRESENT", "AFFECTED", "REACHABLE", "NOT_REACHABLE", "UNKNOWN")


# ---------------------------------------------------------------------------
# Normalized import records
# ---------------------------------------------------------------------------


@dataclass
class ProductRecord:
    ecosystem: str
    product: str
    vendor: str | None = None
    cpe: str | None = None
    purl: str | None = None
    package_name: str | None = None
    version_strategy: str = "GENERIC"
    ranges: list[dict] = field(default_factory=list)  # {introduced, fixed, last_affected, exact, raw}


@dataclass
class VulnRecord:
    cve_id: str
    summary: str | None = None
    description: str | None = None
    published_at: str | None = None
    modified_at: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe: str | None = None
    source: str = "local"
    source_id: str | None = None
    references: list[str] = field(default_factory=list)
    products: list[ProductRecord] = field(default_factory=list)
    # Prompt-16 intelligence expansion (all optional; providers fill what they have).
    aliases: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    identities: list[dict] = field(default_factory=list)   # {identity_type, value, ecosystem, confidence}
    signatures: list[dict] = field(default_factory=list)    # {kind, package, class_name, method, descriptor, field, native_symbol, api_sequence, provider, confidence}
    scores: list[dict] = field(default_factory=list)        # {kind, provider, score, vector, severity, percentile, extra}
    known_exploited: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None
    withdrawn_at: str | None = None
    provider_modified_at: str | None = None
    provider_record_id: str | None = None
    raw: dict | None = None


def import_records(db: Session, records: list[VulnRecord], is_test_data: bool = False) -> int:
    """Persist normalized vulnerability records into the local CVE database."""
    count = 0
    now = datetime.now(timezone.utc)
    for record in records:
        try:
            existing = db.scalar(
                select(Vulnerability).where(
                    Vulnerability.cve_id == record.cve_id, Vulnerability.source == record.source
                )
            )
            if existing is not None:
                db.delete(existing)
                db.flush()
            vuln = Vulnerability(
                cve_id=record.cve_id, summary=record.summary, description=record.description,
                published_at=record.published_at, modified_at=record.modified_at, severity=record.severity,
                cvss_score=record.cvss_score, cvss_vector=record.cvss_vector, cwe=record.cwe,
                source=record.source, source_id=record.provider_record_id or record.source_id,
                retrieved_at=now, is_test_data=is_test_data,
                withdrawn_at=record.withdrawn_at, provider_modified_at=record.provider_modified_at or record.modified_at,
                first_seen=now, last_seen=now, known_exploited=bool(record.known_exploited),
                epss_score=record.epss_score, epss_percentile=record.epss_percentile,
            )
            for url in record.references:
                vuln.references.append(VulnerabilityReference(url=url, ref_type="advisory"))
            for prod in record.products:
                product = AffectedProduct(
                    ecosystem=prod.ecosystem, vendor=prod.vendor, product=prod.product, cpe=prod.cpe,
                    purl=prod.purl, package_name=prod.package_name, version_strategy=prod.version_strategy)
                for rng in prod.ranges:
                    product.ranges.append(AffectedVersionRange(
                        introduced=rng.get("introduced"), fixed=rng.get("fixed"),
                        last_affected=rng.get("last_affected"), exact=rng.get("exact"), raw=rng.get("raw")))
                vuln.products.append(product)
            _attach_intelligence(vuln, record, now)
            db.add(vuln)
            count += 1
        except Exception:  # never let one malformed record break the import
            db.rollback()
            continue
    db.commit()
    return count


def _attach_intelligence(vuln: Vulnerability, record: VulnRecord, now) -> None:
    """Persist aliases / identities / signatures / scores / provider-record.

    Identities and a canonical CVSS score are auto-derived from products when the
    provider did not supply them explicitly, using deterministic normalization."""
    from app.intel import identity as I

    for alias in dict.fromkeys(a for a in record.aliases if a):
        vuln.aliases.append(VulnerabilityAlias(alias=alias))

    # Explicit provider identities first, then auto-derived from products.
    seen_ids: set[tuple] = set()

    def add_identity(itype, value, ecosystem, confidence):
        value = (value or "").strip()
        if not value:
            return
        key = (itype, value.lower())
        if key in seen_ids:
            return
        seen_ids.add(key)
        vuln.identities.append(VulnerabilityIdentity(
            identity_type=itype, value=value, ecosystem=ecosystem, confidence=confidence))

    for ident in record.identities:
        add_identity(ident.get("identity_type", "PACKAGE"), ident.get("value"),
                     ident.get("ecosystem"), ident.get("confidence", "HIGH"))
    for cwe in dict.fromkeys(record.cwes or ([record.cwe] if record.cwe else [])):
        add_identity("CWE", cwe, None, "HIGH")
    for prod in record.products:
        if prod.cpe:
            add_identity("CPE", I.normalize_cpe(prod.cpe), prod.ecosystem, "HIGH")
        if prod.purl:
            add_identity("PURL", I.normalize_purl(prod.purl), prod.ecosystem, "HIGH")
        if prod.ecosystem == "maven" and prod.package_name:
            add_identity("MAVEN", I.normalize_maven(prod.package_name, prod.product), prod.ecosystem, "HIGH")
        if prod.package_name:
            add_identity("PACKAGE", prod.package_name, prod.ecosystem, "MEDIUM")
        if prod.ecosystem == "native":
            add_identity("SONAME", I.normalize_soname(prod.product), prod.ecosystem, "MEDIUM")

    for sig in record.signatures:
        vuln.signatures.append(VulnerabilitySignature(
            kind=sig.get("kind", "PACKAGE"), package=sig.get("package"), class_name=sig.get("class_name"),
            method=sig.get("method"), descriptor=sig.get("descriptor"), field=sig.get("field"),
            native_symbol=sig.get("native_symbol"), api_sequence=list(sig.get("api_sequence", [])),
            provider=sig.get("provider", record.source), confidence=sig.get("confidence", "MEDIUM")))

    scores = list(record.scores)
    if not any(s.get("kind", "").startswith("CVSS") for s in scores) and (record.cvss_score is not None or record.severity):
        kind = "CVSS31" if record.cvss_vector and "3.1" in record.cvss_vector else "CVSS3"
        scores.append({"kind": kind, "provider": record.source, "score": record.cvss_score,
                       "vector": record.cvss_vector, "severity": record.severity})
    if record.epss_score is not None:
        scores.append({"kind": "EPSS", "provider": record.source, "score": record.epss_score,
                       "percentile": record.epss_percentile})
    if record.known_exploited:
        scores.append({"kind": "KEV", "provider": record.source, "extra": {"known_exploited": True}})
    for s in scores:
        vuln.scores.append(VulnerabilityScore(
            kind=s.get("kind", "CVSS3"), provider=s.get("provider", record.source), score=s.get("score"),
            vector=s.get("vector"), severity=s.get("severity"), percentile=s.get("percentile"),
            extra=dict(s.get("extra", {}))))

    raw_excerpt = None
    if record.raw is not None:
        import json as _json
        raw_excerpt = _json.dumps(record.raw, default=str)[:4000]  # bounded auditable payload
    vuln.provider_records.append(VulnerabilityProviderRecord(
        provider=record.source, provider_record_id=record.provider_record_id or record.source_id,
        modified_at=record.provider_modified_at or record.modified_at, retrieved_at=now, raw_excerpt=raw_excerpt))


def normalize_nvd(payload: dict) -> list[VulnRecord]:
    """Normalize an NVD 2.0 API/feed payload into VulnRecords (best-effort)."""
    records: list[VulnRecord] = []
    for item in payload.get("vulnerabilities", []):
        try:
            cve = item.get("cve", item)
            cve_id = cve.get("id")
            if not cve_id:
                continue
            descriptions = cve.get("descriptions", [])
            desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
            metrics = cve.get("metrics", {})
            score, vector, severity = None, None, None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    data = metrics[key][0].get("cvssData", {})
                    score = data.get("baseScore")
                    vector = data.get("vectorString")
                    severity = (metrics[key][0].get("baseSeverity") or data.get("baseSeverity") or "").upper() or None
                    break
            cwe = None
            for weakness in cve.get("weaknesses", []):
                for d in weakness.get("description", []):
                    if d.get("value", "").startswith("CWE-"):
                        cwe = d["value"]
                        break
            products = _nvd_products(cve.get("configurations", []))
            records.append(VulnRecord(
                cve_id=cve_id, description=desc, summary=(desc or "")[:200] or None,
                published_at=cve.get("published"), modified_at=cve.get("lastModified"),
                severity=severity, cvss_score=score, cvss_vector=vector, cwe=cwe,
                source="nvd", source_id=cve_id,
                references=[r.get("url") for r in cve.get("references", []) if r.get("url")],
                products=products))
        except Exception:
            continue
    return records


def _nvd_products(configurations: list) -> list[ProductRecord]:
    products: list[ProductRecord] = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                product = parts[4] if len(parts) > 5 else cpe
                vendor = parts[3] if len(parts) > 4 else None
                rng: dict = {}
                if match.get("versionStartIncluding"):
                    rng["introduced"] = match["versionStartIncluding"]
                if match.get("versionEndExcluding"):
                    rng["fixed"] = match["versionEndExcluding"]
                if match.get("versionEndIncluding"):
                    rng["last_affected"] = match["versionEndIncluding"]
                products.append(ProductRecord(
                    ecosystem="generic", product=product, vendor=vendor, cpe=cpe,
                    ranges=[rng] if rng else []))
    return products


# ---------------------------------------------------------------------------
# Deterministic test fixtures (TEST_DATA)
# ---------------------------------------------------------------------------


def fixture_vulnerabilities() -> list[VulnRecord]:
    """Synthetic CVE records for tests. Clearly TEST_DATA; never production data."""
    return [
        VulnRecord(
            cve_id="CVE-TEST-0001", summary="okhttp affected < 3.14.0", severity="HIGH", cvss_score=7.5,
            cwe="CWE-295", source="test", references=["https://example.test/okhttp-0001"],
            aliases=["GHSA-test-okhttp"],
            products=[ProductRecord("maven", "okhttp", "squareup", cpe="cpe:2.3:a:squareup:okhttp",
                                    purl="pkg:maven/com.squareup.okhttp3/okhttp",
                                    package_name="com.squareup.okhttp3:okhttp",
                                    version_strategy="MAVEN", ranges=[{"raw": "< 3.14.0"}])],
            signatures=[{"kind": "METHOD", "class_name": "okhttp3.OkHttpClient", "method": "run",
                         "provider": "test", "confidence": "MEDIUM"}]),
        VulnRecord(
            cve_id="CVE-TEST-0002", summary="gson exact 2.8.5", severity="MEDIUM", cvss_score=5.9, source="test",
            products=[ProductRecord("maven", "gson", "google", cpe="cpe:2.3:a:google:gson",
                                    package_name="com.google.code.gson:gson",
                                    version_strategy="MAVEN", ranges=[{"exact": "2.8.5"}])]),
        VulnRecord(
            cve_id="CVE-TEST-0003", summary="bouncycastle >=1.0 <1.60", severity="MEDIUM", cvss_score=5.3, source="test",
            products=[ProductRecord("maven", "bouncy_castle", "bouncycastle",
                                    cpe="cpe:2.3:a:bouncycastle:bc-java", version_strategy="MAVEN",
                                    ranges=[{"introduced": "1.0", "fixed": "1.60"}])]),
        VulnRecord(
            cve_id="CVE-TEST-0004", summary="native libfoo < 2.0.0", severity="HIGH", cvss_score=8.1, source="test",
            products=[ProductRecord("native", "foo", version_strategy="GENERIC", ranges=[{"raw": "< 2.0.0"}])],
            signatures=[{"kind": "NATIVE_SYMBOL", "native_symbol": "foo_parse", "provider": "test",
                         "confidence": "MEDIUM"}]),
        VulnRecord(
            cve_id="CVE-TEST-0005", summary="jackson-databind multiple products", severity="CRITICAL", cvss_score=9.8,
            source="test", known_exploited=True, epss_score=0.94, epss_percentile=0.99,
            products=[
                ProductRecord("maven", "jackson-databind", "fasterxml", cpe="cpe:2.3:a:fasterxml:jackson-databind",
                              version_strategy="MAVEN", ranges=[{"raw": "< 2.9.10.7"}]),
                ProductRecord("maven", "jackson", "fasterxml", version_strategy="MAVEN", ranges=[{"raw": "< 2.9.10.7"}]),
            ]),
    ]


# ---------------------------------------------------------------------------
# Matching + reachability correlation
# ---------------------------------------------------------------------------


@dataclass
class _Candidate:
    vuln: Vulnerability
    product: AffectedProduct


def _severity_rank(sev: str | None) -> float:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get((sev or "").upper(), 0)


def _load_product_index(db: Session, include_test: bool) -> dict[tuple[str, str], list[_Candidate]]:
    query = select(Vulnerability).options(
        selectinload(Vulnerability.products).selectinload(AffectedProduct.ranges),
        selectinload(Vulnerability.identities),
        selectinload(Vulnerability.signatures),
    )
    if not include_test:
        query = query.where(Vulnerability.is_test_data.is_(False))
    index: dict[tuple[str, str], list[_Candidate]] = {}
    for vuln in db.scalars(query):
        for product in vuln.products:
            for token in _identity_tokens(product):
                index.setdefault((product.ecosystem, token), []).append(_Candidate(vuln, product))
    return index


def _identity_tokens(product: AffectedProduct) -> set[str]:
    tokens = {product.product.lower()}
    if product.package_name:
        tokens.add(product.package_name.lower())
    return {t for t in tokens if t}


def _dep_tokens(dep: Dependency) -> set[str]:
    tokens = {dep.name.lower()}
    if dep.product:
        tokens.add(dep.product.lower())
    if dep.cpe:
        parts = dep.cpe.split(":")
        if len(parts) > 4:
            tokens.add(parts[4].lower())
    return {t for t in tokens if t}


def match_analysis(db: Session, analysis, include_test: bool | None = None) -> list:
    """Identity + version matching (no reachability yet). Persists VulnerabilityMatch rows."""
    if include_test is None:
        include_test = bool(db.scalar(select(Vulnerability.id).where(Vulnerability.is_test_data.is_(True)).limit(1)))
    index = _load_product_index(db, include_test)

    rows: list[VulnerabilityMatch] = []
    for dep in analysis.dependencies:
        candidates: dict[str, _Candidate] = {}
        for token in _dep_tokens(dep):
            for cand in index.get((dep.ecosystem, token), []):
                candidates[cand.vuln.cve_id] = cand
            for cand in index.get(("generic", token), []):  # NVD generic-ecosystem CVEs
                candidates.setdefault(cand.vuln.cve_id, cand)

        for cand in candidates.values():
            # Prefer explicit normalized-identity matching; fall back to the
            # legacy name-token confidence when the provider supplied no identities.
            id_conf, id_match = _identity_confidence(dep, cand)
            match_method = "EXACT" if id_conf == "EXACT" else "HEURISTIC"
            ranges = [V.VersionRange(r.introduced, r.fixed, r.last_affected, r.exact, r.raw) for r in cand.product.ranges]
            version_state = _version_state(dep, ranges, cand.product.version_strategy)
            correlation = _correlation_without_reach(version_state)
            fixed = _fixed_versions(cand.product)
            # Everything the finding needs is persisted on the row (no transient state).
            row = VulnerabilityMatch(
                analysis=analysis, dependency=dep,  # both parents set atomically (autoflush-safe)
                vulnerability_id=cand.vuln.id, cve_id=cand.vuln.cve_id, match_method=match_method,
                match_confidence=id_conf, identity_confidence=id_conf,
                version_state=version_state, correlation_state=correlation,
                reachability_state=REACH_UNKNOWN if version_state == MATCHED else REACH_PRESENT,
                severity=_finding_severity(correlation, cand.vuln.severity),
                signature_state="NO_SIGNATURE",
                earliest_fixed_version=fixed[0] if fixed else None, fixed_versions=fixed,
                providers=sorted({cand.vuln.source}),
                evidence=_match_evidence(dep, cand, version_state, REACH_UNKNOWN, match_method, id_conf, id_match, fixed))
            db.add(row)
            rows.append(row)
    return rows


def _identity_confidence(dep: Dependency, cand: "_Candidate") -> tuple[str, dict | None]:
    from app.intel import identity as I

    if cand.vuln.identities:
        conf, match = I.identity_match(dep, cand.vuln.identities)
        if conf != I.UNKNOWN:
            return conf, match
    # Legacy fallback: name-token equality carries the dependency's own identity
    # confidence (HIGH for fingerprinted libs), else LOW.
    if dep.name.lower() in _identity_tokens(cand.product):
        return (dep.identity_confidence if dep.identity_confidence in ("EXACT", "HIGH") else "HIGH"), None
    return "LOW", None


def _fixed_versions(product: AffectedProduct) -> list[str]:
    """Normalized known fixed versions across a product's ranges (deterministic,
    version-sorted). Fixed versions are never invented — only provider-supplied."""
    fixed: set[str] = set()
    for r in product.ranges:
        if r.fixed:
            fixed.add(r.fixed)
        if r.raw:
            import re as _re
            for m in _re.finditer(r"<\s*([\w.\-+]+)", r.raw):
                fixed.add(m.group(1))
    def _key(v: str):
        toks = V._tokenize(v)
        return (0, toks) if toks else (1, v)
    return sorted(fixed, key=_key)


def correlate_reachability(analysis, graph) -> dict:
    """Refine reachability for AFFECTED matches using the existing code graph, and
    correlate provider-supplied vulnerable-code signatures against graph nodes."""
    from app.intel import signatures as SIG

    reachable = R.reachable_node_set(graph) if graph is not None else None
    counts = {REACH_REACHABLE: 0, REACH_NOT_REACHABLE: 0, REACH_UNKNOWN: 0}
    sig_index = SIG.build_signature_index(analysis) if graph is not None else {}
    for row in analysis.vulnerability_matches:
        # Signature correlation is independent of version state (evidence-granularity).
        sig_result = SIG.correlate_row(row, graph, reachable, sig_index)
        row.signature_state = sig_result["state"]
        if sig_result["evidence"]:
            row.evidence = _set_ev(row.evidence, "signature", sig_result["evidence"])
        if row.version_state != MATCHED:
            continue
        dep = row.dependency
        reach_state = _reachability(dep, graph, reachable)
        # A method-level vulnerable signature that is reachable is stronger evidence
        # of reachability than package-level heuristics.
        if sig_result["state"] == "METHOD_REACHABLE":
            reach_state = REACH_REACHABLE
        row.reachability_state = reach_state
        if reach_state == REACH_REACHABLE:
            row.correlation_state = AFFECTED_REACHABLE
        elif reach_state == REACH_NOT_REACHABLE:
            row.correlation_state = AFFECTED_NOT_REACHABLE
        else:
            row.correlation_state = PRESENT_AFFECTED
        counts[reach_state if reach_state in counts else REACH_UNKNOWN] += 1
        row.severity = _finding_severity(row.correlation_state, _ev_get(row.evidence, "cve_severity"))
        row.evidence = _set_ev(row.evidence, "reachability", reach_state)
    return counts


def cve_findings(analysis):
    """Generate CVE findings purely from persisted matches (no transient state)."""
    from app.rules.engine import Evidence, Finding

    findings = []
    for row in analysis.vulnerability_matches:
        rule = _FINDING_RULES.get(row.correlation_state)
        if rule is None:
            continue  # NOT_AFFECTED / UNKNOWN identity -> no finding
        rule_id, title = rule
        dep = row.dependency
        payload = row.evidence or []
        description = _ev_get(payload, "summary") or f"{row.cve_id} affects {dep.name}"
        references = [item["detail"] for item in payload if item.get("kind") == "reference"][:5]
        evidence = [Evidence(source="cve", location=dep.artifact or dep.name, detail=item["detail"],
                             artifact=dep.artifact)
                    for item in payload if item.get("kind") not in ("summary", "reference", "cve_severity")]
        findings.append(Finding(
            rule_id=rule_id, title=f"{title}: {row.cve_id} in {dep.name}", category="cve",
            severity=row.severity or "info",
            confidence=dep.identity_confidence.lower() if dep.identity_confidence != "UNKNOWN" else "low",
            status="POTENTIAL", description=description,
            remediation="Update the dependency to a fixed version and confirm whether the vulnerable code path is used.",
            references=references, evidence=evidence, component=dep.name))
    return findings


def _ev_get(payload, kind: str):
    for item in payload or []:
        if item.get("kind") == kind:
            return item.get("detail")
    return None


def _set_ev(payload, kind: str, detail: str) -> list:
    out = [dict(item) for item in (payload or []) if item.get("kind") != kind]
    out.append({"kind": kind, "detail": detail})
    return out


def _version_state(dep: Dependency, ranges, strategy: str) -> str:
    if not ranges:
        return UNKNOWN
    if not dep.version or dep.version_confidence == "UNKNOWN":
        return POSSIBLY_AFFECTED  # identity present, version unknown, affected ranges exist
    return V.match_ranges(dep.version, ranges, strategy or dep.version_strategy)


def _correlation_without_reach(version_state: str) -> str:
    if version_state == NOT_AFFECTED:
        return PRESENT_NOT_AFFECTED
    if version_state == POSSIBLY_AFFECTED:
        return PRESENT_UNKNOWN_VERSION
    if version_state == MATCHED:
        return PRESENT_AFFECTED
    return STATE_UNKNOWN


def _reachability(dep: Dependency, graph, reachable) -> str:
    if graph is None or reachable is None or not graph.methods:
        return REACH_UNKNOWN
    if dep.kind == "java":
        prefix = dep.package_prefix
        if not prefix:
            return REACH_UNKNOWN
        member_keys = [n.key for n in graph.nodes.values()
                       if n.node_type == R.N_JAVA_METHOD and (n.class_name or "").startswith(prefix)]
        if not member_keys:
            return REACH_UNKNOWN  # package not in decompiled code -> cannot tell
        if any(key in reachable for key in member_keys):
            return REACH_REACHABLE
        return REACH_NOT_REACHABLE
    # native: reachable only if a JNI boundary/binding into this library is reachable
    if dep.kind == "native" and dep.bundled:
        lib_boundaries = [n.key for n in graph.nodes.values()
                          if n.node_type == R.N_BOUNDARY and n.extra.get("boundary_type") == "JNI"]
        native_funcs = [n.key for n in graph.nodes.values()
                        if n.node_type == R.N_NATIVE_FUNC and dep.name in (n.extra.get("library") or "")]
        if not lib_boundaries and not native_funcs:
            return REACH_UNKNOWN  # no native call graph without Ghidra -> do not fabricate
        if any(key in reachable for key in lib_boundaries + native_funcs):
            return REACH_REACHABLE
        return REACH_UNKNOWN
    return REACH_UNKNOWN


def _finding_severity(correlation: str, cve_severity: str | None) -> str:
    # Evidence-based; never auto-CRITICAL.
    if correlation == AFFECTED_REACHABLE:
        return "high" if _severity_rank(cve_severity) >= 3 else "medium"
    if correlation == PRESENT_AFFECTED:
        return "medium"
    if correlation == AFFECTED_NOT_REACHABLE:
        return "low"
    if correlation == PRESENT_UNKNOWN_VERSION:
        return "low"
    return "info"


def _match_evidence(dep, cand, version_state, reach_state, match_method, id_conf="MEDIUM",
                    id_match=None, fixed=None) -> list:
    ev = [
        {"kind": "dependency", "detail": f"{dep.name} ({dep.ecosystem}) version={dep.version or 'UNKNOWN'} "
                                         f"identity={dep.identity_confidence} version_conf={dep.version_confidence}"},
        {"kind": "version_source", "detail": dep.version_source or "UNKNOWN"},
        {"kind": "cve", "detail": f"{cand.vuln.cve_id} severity={cand.vuln.severity} source={cand.vuln.source}"},
        {"kind": "identity", "detail": f"{id_conf}" + (f" via {id_match['identity_type']}={id_match['value']}"
                                                       if id_match else " (name-token)")},
        {"kind": "affected_range", "detail": _range_text(cand.product)},
        {"kind": "match_method", "detail": match_method},
        {"kind": "version_state", "detail": version_state},
        {"kind": "reachability", "detail": reach_state},
        {"kind": "cve_severity", "detail": cand.vuln.severity},
        {"kind": "summary", "detail": cand.vuln.summary or cand.vuln.description or ""},
    ]
    if fixed:
        ev.append({"kind": "fixed_versions", "detail": ", ".join(fixed)})
    if cand.vuln.known_exploited:
        ev.append({"kind": "kev", "detail": "KEV: provider reports known-exploited (external intelligence)"})
    if cand.vuln.epss_score is not None:
        ev.append({"kind": "epss", "detail": f"EPSS={cand.vuln.epss_score} (external intelligence)"})
    if dep.artifact:
        ev.append({"kind": "artifact", "detail": dep.artifact})
    for ref in list(cand.vuln.references)[:5]:
        ev.append({"kind": "reference", "detail": ref.url})
    return ev


def _range_text(product: AffectedProduct) -> str:
    parts = []
    for r in product.ranges:
        if r.raw:
            parts.append(r.raw)
        elif r.exact:
            parts.append(f"== {r.exact}")
        else:
            seg = []
            if r.introduced:
                seg.append(f">= {r.introduced}")
            if r.fixed:
                seg.append(f"< {r.fixed}")
            if r.last_affected:
                seg.append(f"<= {r.last_affected}")
            parts.append(" ".join(seg))
    return f"{product.product}: " + "; ".join(p for p in parts if p)


_FINDING_RULES = {
    AFFECTED_REACHABLE: ("ANDROID-CVE-003", "Affected dependency with reachable vulnerable code"),
    AFFECTED_NOT_REACHABLE: ("ANDROID-CVE-004", "Vulnerability present but vulnerable code not reachable"),
    PRESENT_AFFECTED: ("ANDROID-CVE-001", "Vulnerable dependency detected"),
    PRESENT_UNKNOWN_VERSION: ("ANDROID-CVE-002", "Dependency affected but version uncertain"),
}



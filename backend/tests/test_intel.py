"""Vulnerability-intelligence tests (prompt 16) — fully offline & deterministic.

Covers multi-provider import/normalization, identity normalization, version &
fixed-version evidence, code/native signatures, reachability correlation,
KEV/EPSS as a separate axis, provider conflict resolution, freshness, offline
bundle checksum validation, knowledge-graph projection + determinism, APK-diff
CVE transitions, and cross-analysis isolation.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401
from app.analysis import knowledge_graph as KG
from app.analysis.cve import (
    correlate_reachability, cve_findings, fixture_vulnerabilities, import_records, match_analysis,
)
from app.analysis.reachability import build_code_graph
from app.analysis.semantics import augment_graph
from app.core.config import settings
from app.db.session import Base
from app.intel import bundle as BUNDLE, conflicts, freshness, identity, providers
from app.intel.explain import explain_match
from app.models.analysis import Analysis, CodeNode
from app.models.cve import Dependency, Vulnerability
from app.services.cve_store import import_fixtures


@pytest.fixture
def intel_db(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path / "a"))
    monkeypatch.setattr(settings, "workspace_path", str(tmp_path / "w"))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, expire_on_commit=False)() as db:
        import_fixtures(db)
        yield db


def _analysis(db, sha=None):
    a = Analysis(apk_id=uuid.uuid4(), apk_sha256=sha or uuid.uuid4().hex, profile="static", status="PARTIAL")
    db.add(a)
    return a


def _java_dep(name="okhttp", product="okhttp", prefix="okhttp3", version="3.12.0", vconf="EXACT",
              cpe="cpe:2.3:a:squareup:okhttp"):
    return Dependency(name=name, product=product, package_prefix=prefix, ecosystem="maven", version=version,
                      version_confidence=vconf, version_source="POM_PROPERTIES", version_strategy="MAVEN",
                      kind="java", identity_confidence="HIGH", cpe=cpe)


# ---- identity normalization (5,6,7) ----

def test_cpe_normalization():
    assert identity.normalize_cpe("cpe:2.3:a:squareup:okhttp:3.12.0:*:*") == "cpe:2.3:a:squareup:okhttp"
    assert identity.normalize_cpe("cpe:/a:google:gson") == "cpe:2.3:a:google:gson"


def test_purl_normalization():
    assert identity.normalize_purl("pkg:maven/com.squareup.okhttp3/okhttp@3.12.0") == \
        "pkg:maven/com.squareup.okhttp3/okhttp"
    assert identity.purl_coordinate("pkg:maven/com.squareup.okhttp3/okhttp@3.12") == "com.squareup.okhttp3/okhttp"


def test_maven_and_soname_normalization():
    assert identity.normalize_maven("com.squareup.okhttp3:okhttp") == "com.squareup.okhttp3:okhttp"
    assert identity.normalize_maven("com.squareup.okhttp3", "okhttp") == "com.squareup.okhttp3:okhttp"
    assert identity.normalize_soname("libssl.so.1.1") == "ssl"
    assert identity.normalize_soname("libc++_shared.so") == "c++_shared"


def test_identity_confidence_gating():
    assert identity.is_confirmable("EXACT") and identity.is_confirmable("HIGH")
    assert not identity.is_confirmable("MEDIUM") and not identity.is_confirmable("LOW")


# ---- provider import (1,2,4) ----

def test_nvd_import(intel_db):
    payload = {"vulnerabilities": [{"cve": {
        "id": "CVE-2099-1000", "descriptions": [{"lang": "en", "value": "test nvd"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1, "vectorString": "CVSS:3.1/AV:N",
                                                    "baseSeverity": "CRITICAL"}, "baseSeverity": "CRITICAL"}]},
        "weaknesses": [{"description": [{"value": "CWE-79"}]}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:vendorx:libx:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0.0"}]}]}],
        "references": [{"url": "https://example.test/nvd"}]}}]}
    n = import_records(intel_db, providers.normalize_nvd(payload))
    assert n == 1
    v = intel_db.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2099-1000"))
    assert v.source == "nvd" and v.severity == "CRITICAL"
    assert any(i.identity_type == "CPE" for i in v.identities)


def test_osv_import_with_aliases_and_signature(intel_db):
    osv = {"id": "GHSA-xxxx-yyyy", "aliases": ["CVE-2099-2000"], "summary": "osv test",
           "affected": [{"package": {"ecosystem": "Maven", "name": "com.example:lib",
                                     "purl": "pkg:maven/com.example/lib"},
                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.5.0"}]}],
                         "ecosystem_specific": {"imports": [{"path": "com.example.Lib", "symbols": ["parse"]}]}}],
           "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-502"]}}
    n = import_records(intel_db, providers.normalize_osv(osv))
    assert n == 1
    v = intel_db.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2099-2000"))
    assert v.source == "osv"
    assert "GHSA-xxxx-yyyy" in {a.alias for a in v.aliases}
    assert any(s.kind == "METHOD" and s.method == "parse" for s in v.signatures)
    assert any(i.identity_type == "PURL" for i in v.identities)


def test_provider_detection():
    assert providers.detect_provider({"id": "GHSA-1", "affected": []}) == "osv"
    assert providers.detect_provider({"ghsa_id": "GHSA-1"}) == "ghsa"
    assert providers.detect_provider({"vulnerabilities": [{"cve": {"id": "CVE-1"}}]}) == "nvd"


# ---- provider conflict (3) ----

def test_provider_conflict_resolution(intel_db):
    from app.analysis.cve import ProductRecord, VulnRecord
    import_records(intel_db, [VulnRecord(cve_id="CVE-2099-3000", severity="HIGH", cvss_score=8.8, source="nvd",
                                         products=[ProductRecord("maven", "lib", ranges=[{"raw": "< 2.0"}])])])
    import_records(intel_db, [VulnRecord(cve_id="CVE-2099-3000", severity="MODERATE", cvss_score=5.3, source="osv",
                                         products=[ProductRecord("maven", "lib", ranges=[{"raw": "< 2.0"}])])])
    group = list(intel_db.scalars(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2099-3000")))
    resolution = conflicts.resolve(group)
    assert resolution["canonical_severity"] == "HIGH"  # highest CVSS wins, deterministically
    assert resolution["canonical_source"] == "nvd"
    assert any(d["field"] == "severity" for d in resolution["disagreements"])


# ---- version + fixed versions (8,9,12,13) ----

def test_affected_version_and_fixed_versions(intel_db):
    a = _analysis(intel_db)
    a.dependencies.append(_java_dep(version="3.12.0"))
    intel_db.flush()
    match_analysis(intel_db, a)
    m = next(m for m in a.vulnerability_matches if m.cve_id == "CVE-TEST-0001")
    assert m.version_state == "AFFECTED"
    assert m.identity_confidence in ("EXACT", "HIGH")
    assert m.fixed_versions == ["3.14.0"] and m.earliest_fixed_version == "3.14.0"


def test_possibly_affected_when_version_unknown(intel_db):
    a = _analysis(intel_db)
    a.dependencies.append(_java_dep(version=None, vconf="UNKNOWN"))
    intel_db.flush()
    match_analysis(intel_db, a)
    m = next(m for m in a.vulnerability_matches if m.cve_id == "CVE-TEST-0001")
    assert m.version_state == "POSSIBLY_AFFECTED"  # never upgraded to AFFECTED


def test_unknown_version_unparseable(intel_db):
    a = _analysis(intel_db)
    a.dependencies.append(_java_dep(version="not-a-version", vconf="LOW"))
    intel_db.flush()
    match_analysis(intel_db, a)
    m = next(m for m in a.vulnerability_matches if m.cve_id == "CVE-TEST-0001")
    assert m.version_state in ("UNKNOWN", "POSSIBLY_AFFECTED")  # never NOT_AFFECTED / AFFECTED


# ---- signatures (10,11) + reachability (14,15) ----

def _graph_with_okhttp(reachable=True):
    body = "OkHttpClient c=new OkHttpClient(); c.run();" if reachable else "int x=1;"
    src = [("com/app/Main.java", f"package com.app;\nclass Main{{ void onCreate(){{ {body} }} }}"),
           ("okhttp3/OkHttpClient.java", "package okhttp3;\nclass OkHttpClient{ void run(){} }")]
    comps = [{"name": ".Main", "type": "activity", "effective_exported": True, "permission": None, "intent_filters": []}]
    g = build_code_graph(src, [], [], comps)
    augment_graph(g, comps, [], [])
    return g


def test_code_signature_reachable(intel_db):
    a = _analysis(intel_db)
    a.dependencies.append(_java_dep(version="3.12.0"))
    g = _graph_with_okhttp(reachable=True)
    for node in g.nodes.values():
        a.code_nodes.append(CodeNode(node_key=node.key, node_type=node.node_type, label=node.label,
                                     class_name=node.class_name, method_name=node.method_name,
                                     confidence=node.confidence))
    intel_db.flush()
    match_analysis(intel_db, a)
    correlate_reachability(a, g)
    m = next(m for m in a.vulnerability_matches if m.cve_id == "CVE-TEST-0001")
    assert m.signature_state == "METHOD_REACHABLE"
    assert m.correlation_state == "AFFECTED_REACHABLE"


def test_code_signature_present_not_reachable(intel_db):
    a = _analysis(intel_db)
    a.dependencies.append(_java_dep(version="3.12.0"))
    g = _graph_with_okhttp(reachable=False)
    for node in g.nodes.values():
        a.code_nodes.append(CodeNode(node_key=node.key, node_type=node.node_type, label=node.label,
                                     class_name=node.class_name, method_name=node.method_name,
                                     confidence=node.confidence))
    intel_db.flush()
    match_analysis(intel_db, a)
    correlate_reachability(a, g)
    m = next(m for m in a.vulnerability_matches if m.cve_id == "CVE-TEST-0001")
    assert m.signature_state in ("METHOD_PRESENT", "CLASS_PRESENT")
    assert m.correlation_state == "AFFECTED_NOT_REACHABLE"


def test_native_signature_present(intel_db):
    from app.models.analysis import NativeFunction, NativeLibrary
    a = _analysis(intel_db)
    a.dependencies.append(Dependency(name="foo", product="foo", ecosystem="native", version="1.5.0",
                                     version_confidence="MEDIUM", kind="native", bundled=True))
    lib = NativeLibrary(archive_path="lib/arm64-v8a/libfoo.so", abi="arm64-v8a", filename="libfoo.so",
                        size_bytes=10, sha256="a" * 64, status="COMPLETE")
    a.native_libraries.append(lib)
    a.native_functions.append(NativeFunction(name="foo_parse", kind="exported", library=lib))
    a.code_nodes.append(CodeNode(node_key="nf:foo_parse", node_type="NATIVE_FUNCTION", label="foo_parse"))
    intel_db.flush()
    match_analysis(intel_db, a)
    # graph=None path still evaluates signatures against native_functions index? build a tiny graph.
    g = build_code_graph([], [], [], [])
    correlate_reachability(a, g)
    m = next(m for m in a.vulnerability_matches if m.cve_id == "CVE-TEST-0004")
    assert m.signature_state in ("METHOD_PRESENT", "SIGNATURE_NO_CODE")


# ---- KEV / EPSS (16,17) separate axis ----

def test_kev_epss_stored_and_separate(intel_db):
    v = intel_db.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-TEST-0005"))
    assert v.known_exploited is True and v.epss_score == 0.94
    a = _analysis(intel_db)
    a.dependencies.append(Dependency(name="jackson-databind", product="jackson-databind",
                                     package_prefix="com.fasterxml.jackson", ecosystem="maven", version="2.9.0",
                                     version_confidence="EXACT", version_strategy="MAVEN", kind="java",
                                     identity_confidence="HIGH"))
    intel_db.flush()
    match_analysis(intel_db, a)
    m = next(m for m in a.vulnerability_matches if m.cve_id == "CVE-TEST-0005")
    chain = explain_match(a, m)
    ext = chain["external_intelligence"]
    assert ext["known_exploited"] is True and ext["epss_score"] == 0.94
    # KEV/EPSS never assert exploitability.
    import json as _j
    assert "exploitable" not in _j.dumps(chain).lower()


# ---- freshness (18) ----

def test_stale_intelligence(intel_db):
    v = intel_db.scalar(select(Vulnerability))
    now = datetime.now(timezone.utc)
    v.last_seen = now - timedelta(days=settings.intel_stale_days + 5)
    assert freshness.freshness_status(v, now) == "STALE"
    v.last_seen = now
    assert freshness.freshness_status(v, now) == "CURRENT"
    v.last_seen = None
    v.retrieved_at = None
    assert freshness.freshness_status(v, now) == "UNKNOWN"


# ---- bundle (19,20) ----

def test_bundle_roundtrip_and_import(intel_db, tmp_path):
    out = tmp_path / "asf-intel"
    result = BUNDLE.create_bundle(intel_db, out, now=datetime.now(timezone.utc))
    assert result["status"] == "COMPLETE" and result["vulnerabilities"] == len(fixture_vulnerabilities())
    assert BUNDLE.validate_bundle(out)["status"] == "COMPLETE"
    # import into a fresh DB
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, expire_on_commit=False)() as db2:
        imp = BUNDLE.import_bundle(db2, out, now=datetime.now(timezone.utc))
        assert imp["status"] == "COMPLETE" and imp["imported"] == len(fixture_vulnerabilities())
        assert db2.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-TEST-0001")) is not None


def test_bundle_checksum_failure(intel_db, tmp_path):
    out = tmp_path / "asf-intel"
    BUNDLE.create_bundle(intel_db, out, now=datetime.now(timezone.utc))
    # Tamper a data file after checksums were written.
    (out / "vulnerabilities.jsonl").write_text("corrupted\n")
    validation = BUNDLE.validate_bundle(out)
    assert validation["status"] == "FAILED"
    assert any("checksum mismatch" in e for e in validation["errors"])
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, expire_on_commit=False)() as db2:
        imp = BUNDLE.import_bundle(db2, out, now=datetime.now(timezone.utc))
        assert imp["status"] == "FAILED" and imp["imported"] == 0


def test_corrupted_bundle_missing_files(tmp_path):
    (tmp_path / "empty").mkdir()
    assert BUNDLE.validate_bundle(tmp_path / "empty")["status"] == "FAILED"


# ---- knowledge-graph projection + determinism (21,22) ----

def _analysis_with_match(intel_db):
    a = _analysis(intel_db)
    a.dependencies.append(_java_dep(version="3.12.0"))
    g = _graph_with_okhttp(reachable=True)
    for node in g.nodes.values():
        a.code_nodes.append(CodeNode(node_key=node.key, node_type=node.node_type, label=node.label,
                                     class_name=node.class_name, method_name=node.method_name,
                                     confidence=node.confidence))
    intel_db.flush()
    match_analysis(intel_db, a)
    correlate_reachability(a, g)
    return a


def test_graph_projects_cve_intel(intel_db):
    a = _analysis_with_match(intel_db)
    kg = KG.build_knowledge_graph(a)
    types = {n.node_type for n in kg.nodes.values()}
    assert KG.N_CVE in types
    assert KG.N_CVE_IDENTITY in types  # okhttp fixture has CPE/PURL identities
    assert KG.N_CVE_SIGNATURE in types  # okhttp fixture has a METHOD signature
    assert KG.N_CVE_ALIAS in types  # okhttp fixture has a GHSA alias
    # signature links to a real code method node
    assert any(e.edge_type == KG.E_SIGNATURE_OF for e in kg.edges)


def test_graph_projection_deterministic(intel_db):
    a = _analysis_with_match(intel_db)
    assert KG.graph_digest(KG.build_knowledge_graph(a)) == KG.graph_digest(KG.build_knowledge_graph(a))


# ---- APK diff CVE transitions (23) + cross-analysis isolation (24) ----

def test_diff_cve_transitions(make_analysis, db_session):
    from app.analysis.diff import compare_analyses
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    m = next(m for m in b.vulnerability_matches if m.cve_id == "CVE-2020-0001")
    m.version_state = "AFFECTED"
    m.correlation_state = "AFFECTED_REACHABLE"
    m.reachability_state = "REACHABLE"
    db_session.flush()
    c = compare_analyses(db_session, a, b)
    db_session.flush()
    cve_changes = [ch for ch in c.changes if ch.category == "cve" and ch.change_type == "CHANGED"]
    assert cve_changes
    transitions = cve_changes[0].evidence.get("transitions", [])
    assert "STATE_CHANGED" in transitions and "REACHABILITY_CHANGED" in transitions


def test_cross_analysis_isolation(intel_db):
    a1 = _analysis_with_match(intel_db)
    a2 = _analysis(intel_db, sha="b" * 32)
    a2.dependencies.append(_java_dep(name="gson", product="gson", prefix="com.google.gson", version="2.8.5",
                                     cpe="cpe:2.3:a:google:gson"))
    intel_db.flush()
    match_analysis(intel_db, a2)
    # a1's matches are okhttp-only; a2's are gson-only — no leakage.
    assert {m.cve_id for m in a1.vulnerability_matches} == {"CVE-TEST-0001"}
    assert "CVE-TEST-0002" in {m.cve_id for m in a2.vulnerability_matches}
    assert all(m.analysis_id == a1.id for m in a1.vulnerability_matches)

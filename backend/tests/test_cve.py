import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401 register tables
from app.analysis.cve import correlate_reachability, cve_findings, fixture_vulnerabilities, import_records, match_analysis
from app.analysis.reachability import build_code_graph
from app.analysis.semantics import augment_graph
from app.db.session import Base
from app.models.analysis import Analysis
from app.models.cve import Dependency
from app.services.cve_store import import_fixtures, search, show, stats


@pytest.fixture
def cve_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        import_fixtures(session)
        yield session


def _analysis(db):
    a = Analysis(apk_id=uuid.uuid4(), apk_sha256="x", profile="static", status="PARTIAL")
    db.add(a)
    return a


def _java_dep(name, product, prefix, version, vconf="EXACT"):
    return Dependency(name=name, product=product, package_prefix=prefix, ecosystem="maven",
                      version=version, version_confidence=vconf, version_strategy="MAVEN",
                      kind="java", identity_confidence="HIGH")


def test_fixtures_are_test_data(cve_db):
    st = stats(cve_db)
    assert st["total"] == len(fixture_vulnerabilities())
    assert st["production"] == 0
    assert all(r["test_data"] for r in search(cve_db, "CVE-TEST"))


def test_affected_version_in_range(cve_db):
    a = _analysis(cve_db)
    a.dependencies.append(_java_dep("okhttp", "okhttp", "okhttp3", "3.12.0"))
    cve_db.flush()
    match_analysis(cve_db, a)
    correlate_reachability(a, None)
    m = a.vulnerability_matches[0]
    assert m.version_state == "AFFECTED"
    assert m.correlation_state == "PRESENT_AFFECTED"  # no graph -> reachability UNKNOWN
    assert "ANDROID-CVE-001" in {f.rule_id for f in cve_findings(a)}


def test_not_affected_version_out_of_range(cve_db):
    a = _analysis(cve_db)
    a.dependencies.append(_java_dep("okhttp", "okhttp", "okhttp3", "4.12.0"))
    cve_db.flush()
    match_analysis(cve_db, a)
    correlate_reachability(a, None)
    assert a.vulnerability_matches[0].version_state == "NOT_AFFECTED"
    assert a.vulnerability_matches[0].correlation_state == "PRESENT_NOT_AFFECTED"
    assert cve_findings(a) == []  # false-positive control


def test_possibly_affected_unknown_version(cve_db):
    a = _analysis(cve_db)
    a.dependencies.append(_java_dep("bouncycastle", "bouncy_castle", "org.bouncycastle", None, vconf="UNKNOWN"))
    cve_db.flush()
    match_analysis(cve_db, a)
    m = a.vulnerability_matches[0]
    assert m.version_state == "POSSIBLY_AFFECTED"
    assert m.correlation_state == "PRESENT_UNKNOWN_VERSION"
    assert "ANDROID-CVE-002" in {f.rule_id for f in cve_findings(a)}


def test_native_affected(cve_db):
    a = _analysis(cve_db)
    a.dependencies.append(Dependency(name="foo", product="foo", ecosystem="native", version="1.5.0",
                                     version_confidence="MEDIUM", kind="native", bundled=True))
    cve_db.flush()
    match_analysis(cve_db, a)
    assert a.vulnerability_matches[0].version_state == "AFFECTED"


def test_offline_empty_db_zero_matches():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, expire_on_commit=False)() as db:
        a = _analysis(db)
        a.dependencies.append(_java_dep("okhttp", "okhttp", "okhttp3", "3.12.0"))
        db.flush()
        assert match_analysis(db, a) == []  # 0 matches is valid


def test_reachability_correlation_reachable(cve_db):
    a = _analysis(cve_db)
    a.dependencies.append(_java_dep("okhttp", "okhttp", "okhttp3", "3.12.0"))
    cve_db.flush()
    src = [
        ("com/app/Main.java", "package com.app;\nclass Main { void onCreate(){ OkHttpClient client = new OkHttpClient(); client.run(); } }"),
        ("okhttp3/OkHttpClient.java", "package okhttp3;\nclass OkHttpClient { void run(){} }"),
    ]
    comps = [{"name": ".Main", "type": "activity", "effective_exported": True, "permission": None, "intent_filters": []}]
    graph = build_code_graph(src, [], [], comps)
    augment_graph(graph, comps, [], [])
    match_analysis(cve_db, a)
    correlate_reachability(a, graph)
    m = a.vulnerability_matches[0]
    assert m.correlation_state == "AFFECTED_REACHABLE"
    assert "ANDROID-CVE-003" in {f.rule_id for f in cve_findings(a)}


def test_reachability_correlation_not_reachable(cve_db):
    a = _analysis(cve_db)
    a.dependencies.append(_java_dep("okhttp", "okhttp", "okhttp3", "3.12.0"))
    cve_db.flush()
    # OkHttpClient present but nothing reaches it from an entry point
    src = [
        ("com/app/Main.java", "package com.app;\nclass Main { void onCreate(){ int x = 1; } }"),
        ("okhttp3/OkHttpClient.java", "package okhttp3;\nclass OkHttpClient { void run(){} }"),
    ]
    comps = [{"name": ".Main", "type": "activity", "effective_exported": True, "permission": None, "intent_filters": []}]
    graph = build_code_graph(src, [], [], comps)
    augment_graph(graph, comps, [], [])
    match_analysis(cve_db, a)
    correlate_reachability(a, graph)
    m = a.vulnerability_matches[0]
    assert m.correlation_state == "AFFECTED_NOT_REACHABLE"
    assert "ANDROID-CVE-004" in {f.rule_id for f in cve_findings(a)}


def test_show_and_import_records(cve_db):
    data = show(cve_db, "CVE-TEST-0001")
    assert data is not None
    assert data["products"][0]["product"] == "okhttp"
    assert data["test_data"] is True
    # importing a normalized list of records works
    from app.analysis.cve import ProductRecord, VulnRecord
    n = import_records(cve_db, [VulnRecord(cve_id="CVE-TEST-9999", summary="x", source="test",
                                           products=[ProductRecord("maven", "widget", ranges=[{"raw": "< 1.0"}])])],
                       is_test_data=True)
    assert n == 1
    assert show(cve_db, "CVE-TEST-9999") is not None

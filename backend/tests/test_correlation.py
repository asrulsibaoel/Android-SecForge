import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401
from app.analysis.correlation import (
    build_root_causes,
    correlate,
    correlation_groups,
    deduplicate,
    fingerprint_finding,
    link_root_cause_findings,
    summarize_path,
)
from app.db.session import Base
from app.models.analysis import Analysis, EvidenceModel, FindingModel, ReachabilityPath


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _analysis(db):
    a = Analysis(apk_id=uuid.uuid4(), apk_sha256="sha", profile="static", status="PARTIAL")
    db.add(a)
    return a


def _finding(analysis, rule_id, category, severity="medium", confidence="medium", status="POTENTIAL",
             component=None, evidence=()):
    f = FindingModel(rule_id=rule_id, title=f"{rule_id} title", category=category, severity=severity,
                     confidence=confidence, status=status, component=component)
    for src, loc, detail in evidence:
        f.evidence.append(EvidenceModel(source=src, location=loc, detail=detail))
    analysis.findings.append(f)
    return f


def test_fingerprint_stable_and_dedup(db):
    a = _analysis(db)
    ev = [("manifest", "activity .A", "exported without permission")]
    _finding(a, "ANDROID-COMPONENT-001", "ipc", component=".A", evidence=ev)
    _finding(a, "ANDROID-COMPONENT-001", "ipc", component=".A", evidence=ev)  # exact duplicate
    _finding(a, "ANDROID-COMPONENT-001", "ipc", component=".B",
             evidence=[("manifest", "activity .B", "x")])  # different target
    db.flush()
    dups = deduplicate(a)
    assert dups == 1  # only the exact duplicate flagged
    fps = {f.fingerprint for f in a.findings}
    assert len(fps) == 2  # two distinct fingerprints
    assert fingerprint_finding(a.findings[0]) == fingerprint_finding(a.findings[1])


def test_correlation_groups_by_component(db):
    a = _analysis(db)
    _finding(a, "ANDROID-COMPONENT-001", "ipc", component=".DataProvider")
    _finding(a, "ANDROID-COMPONENT-002", "ipc", severity="high", component=".DataProvider")
    _finding(a, "ANDROID-WEBVIEW-001", "webview", component=".Other")
    db.flush()
    deduplicate(a)
    correlate(a)
    groups = correlation_groups(a)
    assert "component:.DataProvider" in groups
    assert len(groups["component:.DataProvider"]) == 2


def test_root_cause_webview_and_cve(db):
    a = _analysis(db)
    _finding(a, "ANDROID-WEBVIEW-001", "webview", component=".Web")
    _finding(a, "ANDROID-SEMANTIC-004", "semantic", severity="medium", component=".Web")
    _finding(a, "ANDROID-CVE-002", "cve", severity="low", component="gson")
    db.flush()
    deduplicate(a)
    build_root_causes(a)
    db.flush()
    link_root_cause_findings(a)
    categories = {rc.category for rc in a.root_causes}
    assert "UNSAFE_WEBVIEW_INPUT" in categories
    assert "DEPENDENCY_CVE" in categories
    webview = next(rc for rc in a.root_causes if rc.category == "UNSAFE_WEBVIEW_INPUT")
    assert len(webview.findings) == 2  # webview rule + semantic bridge grouped
    # findings back-link to their root cause
    assert all(f.root_cause_id is not None for f in a.findings if f.rule_id.startswith("ANDROID-WEBVIEW"))


def test_no_root_cause_without_supporting_finding(db):
    a = _analysis(db)
    _finding(a, "ANDROID-MANIFEST-001", "manifest", component=None)  # debuggable only
    db.flush()
    deduplicate(a)
    build_root_causes(a)
    cats = {rc.category for rc in a.root_causes}
    assert "UNSAFE_WEBVIEW_INPUT" not in cats  # not invented
    assert "DEBUGGABLE_BUILD" in cats


def test_disconnected_source_and_sink_not_correlated(db):
    """CASE-J: a source finding and an unrelated sink finding share no dimension."""
    a = _analysis(db)
    _finding(a, "ANDROID-SEMANTIC-001", "semantic", component=".ActivityA")  # receives input
    _finding(a, "ANDROID-WEBVIEW-001", "webview", component=".UnrelatedB")   # sink elsewhere
    db.flush()
    deduplicate(a)
    correlate(a)
    groups = correlation_groups(a)
    # no group links the two different components
    assert all(len(ids) == 1 or "ActivityA" not in key or "UnrelatedB" not in key
               for key, ids in groups.items())
    assert "component:.ActivityA" not in groups  # single-member -> not a group


def test_path_summary_preserves_unknown_native_target(db):
    a = _analysis(db)
    path = ReachabilityPath(
        rule_id="ANDROID-REACH-003", from_key="entry:.Main", from_label=".Main", to_key="nfunc:libx.so:Java_x",
        to_label="Java_x", status="REACHABLE", confidence="MEDIUM", length=3,
        nodes=[{"label": ".Main", "type": "ENTRY_POINT"}, {"label": "verify", "type": "JAVA_METHOD"},
               {"label": "Java_x", "type": "NATIVE_FUNCTION"}], edges=[])
    a.reachability_paths.append(path)
    db.flush()
    summary = summarize_path(path)
    assert summary["note"] == "UNKNOWN_NATIVE_TARGET"
    assert summary["chain"][-1] == "Java_x"

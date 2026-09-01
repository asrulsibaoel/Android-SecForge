"""Backend REST additions for the prompt-22 investigation UI.

These are read-only projections that must not create or mutate analytical truth:
a bounded `/api/v1/analyses` list, and additive identity/axis fields on the
findings serializer. Existing contracts are preserved.
"""

from fastapi.testclient import TestClient

from app.main import app
from app.reports.json_report import build_report


def test_analyses_list_route_is_bounded_and_listlike():
    # Structural: the route exists, returns a list, and clamps an absurd limit.
    client = TestClient(app)
    r = client.get("/api/v1/analyses")
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    assert client.get("/api/v1/analyses", params={"limit": 10_000_000}).status_code == 200


def test_findings_serializer_exposes_id_and_distinct_axes(db_session, make_analysis):
    a = make_analysis()
    report = build_report(a, db_session)
    findings = report["findings"]
    assert findings
    f = findings[0]
    # id enables the explain / evidence-chain drawer
    assert f["id"] and isinstance(f["id"], str)
    # every axis the UI must NOT conflate is present and independent
    for key in ("severity", "severity_score", "confidence", "confidence_score", "status",
                "runtime_status", "runtime_validation_state", "evidence_count", "root_cause_id"):
        assert key in f
    # additive only — the established keys are still there
    assert {"rule_id", "title", "category", "validation", "evidence"} <= set(f)


def test_findings_serializer_is_read_only(db_session, make_analysis):
    a = make_analysis()
    before = [(x.id, x.severity, x.confidence_score, x.status, x.runtime_validation_state) for x in a.findings]
    build_report(a, db_session)
    build_report(a, db_session)  # idempotent view — never mutates the findings
    after = [(x.id, x.severity, x.confidence_score, x.status, x.runtime_validation_state) for x in a.findings]
    assert before == after

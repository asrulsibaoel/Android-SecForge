"""Investigation workspace tests (prompt 14): lifecycle, findings, hypotheses,
notes, bookmarks, timeline, export, and integrity — proving researcher state is
strictly separate from analytical truth.
"""

import json

import pytest

from app.analysis import investigation as INV
from app.reports.investigation_report import export_investigation, investigation_markdown


def test_create_and_view(make_analysis, db_session):
    a = make_analysis()
    inv = INV.create_investigation(db_session, a, name="Case 1")
    view = INV.investigation_view(inv)
    assert view["name"] == "Case 1" and view["analysis_id"] == str(a.id)
    assert view["counts"]["nodes"] == 0


def test_rename(make_analysis, db_session):
    a = make_analysis()
    inv = INV.create_investigation(db_session, a)
    INV.rename_investigation(db_session, inv, "Renamed")
    assert inv.name == "Renamed"


def test_add_finding_and_node(make_analysis, db_session):
    a = make_analysis()
    inv = INV.create_investigation(db_session, a)
    finding = a.findings[0]
    INV.add_finding(db_session, inv, finding)
    INV.add_finding(db_session, inv, finding)  # idempotent
    assert len(inv.findings) == 1
    INV.add_node(db_session, inv, "com.x.Web#onCreate", "CODE_METHOD", "Web.onCreate")
    assert len(inv.nodes) == 1


def test_hypothesis_lifecycle(make_analysis, db_session):
    a = make_analysis()
    inv = INV.create_investigation(db_session, a)
    hyp = INV.add_hypothesis(db_session, inv, "External input may control reflective class loading.")
    assert hyp.status == "OPEN"
    INV.attach_hypothesis_evidence(db_session, hyp, "FINDING", "ANDROID-REACH-001", "reachable path")
    INV.set_hypothesis_status(db_session, hyp, "SUPPORTED")
    assert hyp.status == "SUPPORTED"
    INV.set_hypothesis_status(db_session, hyp, "UNKNOWN")
    assert hyp.status == "UNKNOWN"
    assert len(hyp.evidence) == 1


def test_hypothesis_invalid_status_rejected(make_analysis, db_session):
    a = make_analysis()
    inv = INV.create_investigation(db_session, a)
    with pytest.raises(ValueError):
        INV.add_hypothesis(db_session, inv, "stmt", status="CONFIRMED")  # not a valid state


def test_hypothesis_never_auto_confirmed(make_analysis, db_session):
    a = make_analysis()
    inv = INV.create_investigation(db_session, a)
    hyp = INV.add_hypothesis(db_session, inv, "incomplete evidence hypothesis")
    # Attaching evidence does not change status; only an explicit action does.
    INV.attach_hypothesis_evidence(db_session, hyp, "NODE", "com.x.Web#onCreate")
    assert hyp.status == "OPEN"


def test_notes_and_bookmarks(make_analysis, db_session):
    a = make_analysis()
    inv = INV.create_investigation(db_session, a)
    INV.add_note(db_session, inv, "check the deep link handler", author="asrul")
    INV.add_bookmark(db_session, inv, "finding", "ANDROID-REACH-001", "primary")
    assert len(inv.notes) == 1 and inv.notes[0].author == "asrul"
    assert len(inv.bookmarks) == 1 and inv.bookmarks[0].ref_type == "FINDING"


def test_timeline_deterministic_and_ordered(make_analysis, db_session):
    a = make_analysis()
    inv = INV.create_investigation(db_session, a)
    view1 = INV.timeline_view(inv)
    INV.rebuild_timeline(db_session, inv, a)
    view2 = INV.timeline_view(inv)
    assert [e["event_type"] for e in view1] == [e["event_type"] for e in view2]
    kinds = {e["event_type"] for e in view1}
    assert "APK_INGESTION" in kinds and "RUNTIME_OBSERVATION" in kinds


def test_note_becomes_timeline_event(make_analysis, db_session):
    a = make_analysis()
    inv = INV.create_investigation(db_session, a)
    INV.add_note(db_session, inv, "a researcher note")
    kinds = [e["event_type"] for e in INV.timeline_view(inv)]
    assert "RESEARCHER_NOTE" in kinds


def test_add_path_pins_nodes(make_analysis, db_session):
    a = make_analysis()
    inv = INV.create_investigation(db_session, a)
    result = INV.add_path(db_session, inv, a, "Web", "loadUrl")
    assert result["pinned"] >= 2 and result["status"] == "REACHABLE"
    assert len(inv.nodes) >= 2 and len(inv.edges) >= 1


# ---- exports ----

def test_markdown_export_has_sections_and_evidence_links(make_analysis, db_session):
    a = make_analysis()
    inv = INV.create_investigation(db_session, a)
    INV.add_hypothesis(db_session, inv, "hypothesis about the exported activity")
    md = investigation_markdown(a, inv)
    for section in ("# Investigation", "## Scope", "## Findings", "## Root Causes", "## Attack Surface",
                    "## Evidence", "## Reachability Paths", "## Dependencies", "## CVEs",
                    "## Runtime Observations", "## Hypotheses", "## Uncertainties", "## Limitations",
                    "## Timeline"):
        assert section in md, f"missing section {section}"
    assert "FINDING:" in md and "CVE:" in md  # claims link to evidence identifiers
    assert "POSSIBLY_AFFECTED" in md and "exploitable" not in md.lower()


def test_export_formats(make_analysis, db_session):
    a = make_analysis()
    inv = INV.create_investigation(db_session, a)
    assert json.loads(export_investigation(a, inv, "json"))["nodes"]
    assert "<graphml" in export_investigation(a, inv, "graphml")
    assert export_investigation(a, inv, "dot").startswith("digraph")
    assert export_investigation(a, inv, "markdown").startswith("# Investigation")
    with pytest.raises(ValueError):
        export_investigation(a, inv, "pdf")


# ---- integrity (Phase 16) ----

def test_hypothesis_does_not_change_findings(make_analysis, db_session):
    a = make_analysis()
    finding = next(f for f in a.findings if f.rule_id == "ANDROID-REACH-001")
    before = (finding.severity, finding.confidence, finding.status, finding.confidence_score)
    inv = INV.create_investigation(db_session, a)
    hyp = INV.add_hypothesis(db_session, inv, "this finding is real")
    INV.set_hypothesis_status(db_session, hyp, "SUPPORTED", rationale="looks reachable")
    after = (finding.severity, finding.confidence, finding.status, finding.confidence_score)
    assert before == after  # machine finding untouched


def test_note_does_not_change_finding_or_risk(make_analysis, db_session):
    a = make_analysis()
    finding = a.findings[0]
    before = (finding.severity, finding.confidence, finding.description)
    surface_before = [(n.node_key, n.risk_score) for n in a.attack_surface_nodes]
    inv = INV.create_investigation(db_session, a)
    INV.add_note(db_session, inv, "I think severity should be higher", target_ref=str(finding.id))
    assert (finding.severity, finding.confidence, finding.description) == before
    assert [(n.node_key, n.risk_score) for n in a.attack_surface_nodes] == surface_before


def test_cross_analysis_finding_isolation(make_analysis, db_session):
    a = make_analysis(package="com.a")
    b = make_analysis(package="com.b")
    inv = INV.create_investigation(db_session, a)
    # A view of A's investigation never references B's findings.
    a_finding_ids = {str(f.id) for f in a.findings}
    INV.add_finding(db_session, inv, a.findings[0])
    view = INV.investigation_view(inv)
    assert set(view["findings"]) <= a_finding_ids
    assert not (set(view["findings"]) & {str(f.id) for f in b.findings})

"""Capability-aware integration tests for the REAL JADX executable.

These tests invoke the actual `jadx` binary and are therefore gated:

* JADX must be discoverable (on PATH or via ``ASF_JADX_PATH``), and
* a real APK path must be provided via the ``ASF_TEST_APK`` environment variable.

When either is missing the tests skip, so the suite stays portable and never
depends on JADX being installed. To run them locally:

    ASF_TEST_APK=/path/to/real.apk make test

They never mock the process — that is the whole point.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.analysis import jadx as jadx_engine
from app.analysis.code_index import index_sources
from app.analysis.orchestrator import analyze_apk
from app.rules.engine import run_code_rules

_REAL_APK = os.environ.get("ASF_TEST_APK")

pytestmark = [
    pytest.mark.skipif(jadx_engine.jadx_executable() is None, reason="jadx not installed"),
    pytest.mark.skipif(not _REAL_APK or not Path(_REAL_APK).is_file(), reason="ASF_TEST_APK not set to a real APK"),
]


def test_real_jadx_decompiles_and_indexes(tmp_path):
    apk = Path(_REAL_APK)
    result = jadx_engine.run_jadx(apk, tmp_path / "jadx", timeout=600)

    assert result.status == jadx_engine.SUCCESS
    assert result.version  # persisted tool version
    assert result.exit_code is not None
    assert result.sources_dir and Path(result.sources_dir).exists()

    index = index_sources(Path(result.sources_dir))
    assert index.file_count > 0
    assert index.class_count > 0
    assert index.method_count > 0

    # Rules execute over real decompiled sources (may or may not fire — that is fine).
    findings = run_code_rules(index.sources)
    for finding in findings:
        assert finding.evidence
        assert finding.evidence[0].source == "source_code"
        assert finding.evidence[0].line is not None


def test_real_jadx_pipeline_reports_code_analysis_complete(db_session):
    analysis = analyze_apk(Path(_REAL_APK), db_session)

    assert analysis.capabilities["jadx"] == "AVAILABLE"
    assert analysis.capabilities["code_analysis"] == "COMPLETE"
    assert any(entity.entity_type == "class" for entity in analysis.code_entities)
    jadx_stage = next(stage for stage in analysis.stages if stage["name"] == "jadx")
    assert jadx_stage["status"] == "COMPLETE"

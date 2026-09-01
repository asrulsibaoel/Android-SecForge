from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

import app.models  # noqa: F401  ensure all tables are registered on Base.metadata
from app.core.config import settings
from app.db.session import Base


@pytest.fixture
def isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path / "artifacts"))
    monkeypatch.setattr(settings, "workspace_path", str(tmp_path / "workspace"))
    return tmp_path


@pytest.fixture
def db_session(isolated_storage):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        yield session


@pytest.fixture
def no_jadx(monkeypatch):
    """Force JADX to appear uninstalled so pipeline results are deterministic."""
    monkeypatch.setattr("app.analysis.jadx.jadx_executable", lambda: None)


@pytest.fixture(autouse=True)
def no_ghidra(monkeypatch):
    """Hermetic tests: force Ghidra to appear absent regardless of whether the host
    has it installed (e.g. via a local .env). The Ghidra correlation paths are
    exercised deterministically with clearly-marked FIXTURE exports, never the live
    headless analyzer — so this keeps the suite fast and host-independent. A test
    that specifically needs a present Ghidra can override this."""
    monkeypatch.setattr("app.analysis.ghidra.analyze_headless_executable", lambda: None)


@pytest.fixture
def test_apk(isolated_storage) -> Path:
    from app.testapp.builder import build_test_apk

    return build_test_apk(isolated_storage / "AndroidSecForge-TestApp.apk")


@pytest.fixture
def native_so(isolated_storage) -> Path:
    """A real compiled shared object, or skip when no C compiler is present."""
    from app.testapp.builder import compile_native_fixture

    so = compile_native_fixture(isolated_storage / "libasfnative.so")
    if so is None:
        pytest.skip("no host C compiler available to build the native fixture")
    return so


@pytest.fixture
def native_apk(isolated_storage, native_so) -> Path:
    from app.testapp.builder import build_native_test_apk

    return build_native_test_apk(isolated_storage / "native-test.apk", native_so)


@pytest.fixture
def make_analysis(db_session):
    """Build a realistic, fully-populated Analysis directly from models (no JADX/
    device needed) for knowledge-graph + investigation tests. Deterministic."""
    import uuid

    from app.analysis import correlation as correlation_engine
    from app.models.analysis import (
        Analysis, AndroidEntryPoint, CodeEdge, CodeNode, ComponentModel, DataflowSource,
        EvidenceModel, FindingModel, IpcTransaction, ManifestModel, ReachabilityPath,
        SecurityBoundary, SecuritySink,
    )
    from app.models.correlation import (
        AttackSurfaceNode, FindingCorrelation, RootCause, RootCauseFinding,
    )
    from app.models.cve import Dependency, VulnerabilityMatch
    from app.models.runtime import RuntimeObservation, RuntimeSession

    def _make(package="com.x", sha=None, instrumented=True):
        sha = sha or (uuid.uuid4().hex + uuid.uuid4().hex)[:64]
        a = Analysis(apk_id=uuid.uuid4(), apk_sha256=sha, profile="static", status="COMPLETE",
                     capabilities={"jadx": "AVAILABLE", "code_analysis": "COMPLETE", "ghidra": "UNAVAILABLE"},
                     stages=[{"name": "ingest", "status": "COMPLETE", "detail": f"sha256={sha}"},
                             {"name": "manifest", "status": "COMPLETE", "detail": f"package={package}"},
                             {"name": "jadx", "status": "COMPLETE", "detail": "jadx"},
                             {"name": "reachability", "status": "COMPLETE", "detail": "1 reachable"},
                             {"name": "correlation", "status": "COMPLETE", "detail": "1 root cause"}])
        a.manifest = ManifestModel(status="parsed", source_format="binary_axml", package=package)
        db_session.add(a)

        a.components.append(ComponentModel(kind="activity", name=f"{package}.Web", exported=True,
                                           explicit_exported=True, effective_exported=True, exposure="EXPORTED"))
        a.components.append(ComponentModel(kind="service", name=f"{package}.Svc", exported=False,
                                           effective_exported=False, exposure="INTERNAL"))

        a.android_entry_points.append(AndroidEntryPoint(
            node_key=f"{package}.Web#onCreate", component=f"{package}.Web", component_type="activity",
            method="onCreate", lifecycle_event="onCreate", exported=True, confidence="HIGH",
            evidence="exported activity onCreate"))

        # Canonical code graph.
        entry = f"entry:{package}.Web"
        oncreate = f"{package}.Web#onCreate"
        for key, ntype, label, cls, meth, conf in [
            (entry, "ENTRY_POINT", "Web (activity)", None, None, "HIGH"),
            (oncreate, "JAVA_METHOD", "Web.onCreate", f"{package}.Web", "onCreate", "HIGH"),
            ("sink:web", "SECURITY_SINK", "WebView.loadUrl", None, None, "MEDIUM"),
            ("sink:low", "SECURITY_SINK", "WebView.loadData", None, None, "LOW"),
            ("sink:exec", "SECURITY_SINK", "Runtime.exec", None, None, "MEDIUM"),
            ("iso:a", "JAVA_METHOD", "A.foo", "com.x.A", "foo", "HIGH"),
            ("iso:b", "JAVA_METHOD", "B.bar", "com.x.B", "bar", "HIGH"),
        ]:
            a.code_nodes.append(CodeNode(node_key=key, node_type=ntype, label=label, class_name=cls,
                                         method_name=meth, confidence=conf))
        a.code_edges.append(CodeEdge(src_key=entry, dst_key=oncreate, edge_type="DECLARES", confidence="HIGH"))
        a.code_edges.append(CodeEdge(src_key=oncreate, dst_key="sink:web", edge_type="INVOKES", confidence="MEDIUM",
                                     evidence="loadUrl call"))
        a.code_edges.append(CodeEdge(src_key=oncreate, dst_key="sink:low", edge_type="INVOKES", confidence="LOW"))

        from app.models.analysis import SemanticEdge
        a.semantic_edges.append(SemanticEdge(src_key=oncreate, dst_key="reflect:UNKNOWN",
                                             edge_type="REFLECTION_TARGET", confidence="MEDIUM",
                                             evidence="reflection with non-constant target"))

        a.dataflow_sources.append(DataflowSource(node_key="src:1", source_type="intent", api="getIntent",
                                                 class_name=f"{package}.Web", method_name="onCreate"))
        a.security_sinks.append(SecuritySink(node_key="sink:web", sink_type="webview", api="loadUrl",
                                             category="java"))
        a.security_sinks.append(SecuritySink(node_key="sink:exec", sink_type="exec", api="exec", category="java"))

        a.reachability_paths.append(ReachabilityPath(
            rule_id="ANDROID-REACH-001", from_key=entry, from_label="Web (activity)", to_key="sink:web",
            to_label="WebView.loadUrl", status="REACHABLE", confidence="MEDIUM", length=3,
            nodes=[{"key": entry, "label": "Web (activity)"}, {"key": oncreate, "label": "Web.onCreate"},
                   {"key": "sink:web", "label": "WebView.loadUrl"}],
            edges=[{"type": "DECLARES"}, {"type": "INVOKES"}]))

        a.security_boundaries.append(SecurityBoundary(boundary_type="WEBVIEW_JS", component=f"{package}.Web",
                                                      node_key=oncreate, confidence="MEDIUM"))
        a.security_boundaries.append(SecurityBoundary(boundary_type="BINDER", component=f"{package}.Svc",
                                                      node_key="svc", confidence="LOW"))
        a.ipc_transactions.append(IpcTransaction(kind="SERVICE_ENTRY", class_name=f"{package}.Svc",
                                                 method_name="onTransact", confidence="LOW"))

        # Findings.
        reach = FindingModel(rule_id="ANDROID-REACH-001", title="External input reaches WebView.loadUrl",
                             category="reachability", severity="high", confidence="medium", status="POTENTIAL",
                             component=f"{package}.Web", confidence_score=60)
        reach.evidence.append(EvidenceModel(source="reachability", location=f"{package}.Web:onCreate",
                                            detail="[2] SECURITY_SINK WebView.loadUrl (INVOKES)"))
        webview = FindingModel(rule_id="ANDROID-WEBVIEW-001", title="JavaScript enabled in WebView",
                               category="webview", severity="medium", confidence="low", status="POTENTIAL",
                               component=f"{package}.Web", confidence_score=30, validation_state="NOT_OBSERVED")
        webview.evidence.append(EvidenceModel(source="code", location=f"{package}.Web", detail="setJavaScriptEnabled(true)"))
        cve = FindingModel(rule_id="ANDROID-CVE-001", title="CVE-2020-0001 in openssl",
                           category="cve", severity="high", confidence="medium", status="POTENTIAL",
                           component="libssl.so", confidence_score=50)
        cve.evidence.append(EvidenceModel(source="cve", location="openssl", detail="POSSIBLY_AFFECTED openssl 1.0.2"))
        for f in (reach, webview, cve):
            a.findings.append(f)

        # Dependencies + CVE matches (states preserved verbatim).
        dep = Dependency(name="openssl", product="openssl", ecosystem="native", version="1.0.2", kind="native",
                         identity_confidence="HIGH", version_confidence="MEDIUM")
        a.dependencies.append(dep)
        a.vulnerability_matches.append(VulnerabilityMatch(
            dependency=dep, cve_id="CVE-2020-0001", match_method="HEURISTIC", match_confidence="MEDIUM",
            version_state="POSSIBLY_AFFECTED", correlation_state="PRESENT_AFFECTED", reachability_state="UNKNOWN",
            severity="high"))
        a.vulnerability_matches.append(VulnerabilityMatch(
            dependency=dep, cve_id="CVE-2020-0002", match_method="EXACT", match_confidence="HIGH",
            version_state="AFFECTED", correlation_state="AFFECTED_REACHABLE", reachability_state="REACHABLE",
            severity="critical"))

        # Attack surface.
        a.attack_surface_nodes.append(AttackSurfaceNode(node_key=f"{package}.Web", node_type="component",
                                                        name=f"{package}.Web", exposure="PUBLIC",
                                                        component=f"{package}.Web", risk_score=80))

        # Runtime session + observation (mocked adapter kind).
        session = RuntimeSession(session_state="RUNNING", instrumentation_enabled=instrumented,
                                 device_serial="emulator-5554", package_name=package,
                                 metadata_={"adapter": "mock"})
        session.observations.append(RuntimeObservation(observation_type="JAVA", class_name="android.webkit.WebView",
                                                       method_name="loadUrl", source="FRIDA", confidence="MEDIUM"))
        a.runtime_sessions.append(session)

        db_session.flush()

        # Root cause linking + correlation index (need IDs).
        rc = RootCause(identifier="rc-web-exposure", category="webview_exposure", title="Exposed WebView surface",
                       severity="high", confidence="medium", affected_components=[f"{package}.Web"])
        a.root_causes.append(rc)
        db_session.flush()
        rc.findings.append(RootCauseFinding(finding_id=reach.id, rule_id=reach.rule_id))
        reach.root_cause_id = rc.id
        a.finding_correlations.append(FindingCorrelation(finding_id=reach.id, dimension="component",
                                                         correlation_key=f"{package}.Web"))
        a.finding_correlations.append(FindingCorrelation(finding_id=webview.id, dimension="component",
                                                         correlation_key=f"{package}.Web"))
        correlation_engine.deduplicate(a)  # assign stable fingerprints
        db_session.flush()
        return a

    return _make

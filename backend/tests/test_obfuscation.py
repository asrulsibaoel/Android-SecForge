"""Obfuscation & anti-analysis tests (prompt 19) — deterministic, offline.

Controlled synthetic inputs exercise identifier/string/control-flow/dynamic/
native detectors, anti-analysis evidence levels, uncertainty preservation, CVE
non-mutation, diff transitions, and deterministic fingerprints.
"""

import uuid

import pytest

from app.analysis import obfuscation as O
from app.models.analysis import (
    Analysis, CodeEdge, CodeEntity, CodeNode, EvidenceModel, FindingModel, ManifestModel,
    NativeLibrary, NativeFunction, ReachabilityPath, SecurityBoundary, SemanticEdge,
)
from app.models.cve import Dependency, VulnerabilityMatch


def _mk(db, package="com.example"):
    a = Analysis(apk_id=uuid.uuid4(), apk_sha256=uuid.uuid4().hex, profile="static", status="COMPLETE")
    a.manifest = ManifestModel(status="parsed", source_format="binary_axml", package=package)
    db.add(a)
    db.flush()
    return a


def _classes(a, db, names, package):
    for n in names:
        a.code_entities.append(CodeEntity(entity_type="class", name=n, class_name=f"{package}.{n}", package=package))
    db.flush()


def _sem(a, db, edge_type, src, dst, evidence=""):
    a.semantic_edges.append(SemanticEdge(src_key=src, dst_key=dst, edge_type=edge_type, evidence=evidence,
                                         confidence="MEDIUM"))
    db.flush()


def _reachable(a, db, from_key):
    a.reachability_paths.append(ReachabilityPath(rule_id="R", from_key=from_key, from_label="E", to_key="s",
                                                 to_label="S", status="REACHABLE", confidence="MEDIUM", length=2,
                                                 nodes=[{"key": from_key, "label": "E"}], edges=[]))
    db.flush()


def _by_cat(a, cat):
    return [o for o in O.build_intelligence(a)["observations"] if o.category == cat]


# ---- CASE 1: descriptive identifiers -> no strong finding ----

def test_case1_descriptive_no_finding(db_session):
    a = _mk(db_session)
    _classes(a, db_session, ["MainActivity", "UserRepository", "PaymentService", "LoginController",
                             "SettingsFragment", "NetworkClient", "DatabaseHelper", "TokenManager"], "com.example")
    obs = _by_cat(a, O.CAT_IDENTIFIER)
    assert not any(o.state == O.S_STRONG_INDICATOR for o in obs)


# ---- CASE 2: shortened identifiers -> IDENTIFIER_OBFUSCATION ----

def test_case2_identifier_obfuscation(db_session):
    a = _mk(db_session)
    _classes(a, db_session, ["a", "b", "c", "d", "e", "f", "g", "h"], "a.a")
    obs = _by_cat(a, O.CAT_IDENTIFIER)
    assert obs and obs[0].state == O.S_STRONG_INDICATOR and obs[0].confidence == "HIGH"
    assert "short_class_ratio" in obs[0].evidence_json


# ---- CASE 3: encoded strings -> STRING_OBFUSCATION ----

def test_case3_string_obfuscation(db_session):
    a = _mk(db_session)
    f = FindingModel(rule_id="ANDROID-CODE-001", title="x", category="code", severity="info", confidence="low",
                     status="POTENTIAL", component="com.example.A", fingerprint="fp")
    b64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"
    f.evidence.append(EvidenceModel(source="code", location="com.example.A", detail=f"const1={b64}"))
    f.evidence.append(EvidenceModel(source="code", location="com.example.A", detail=f"const2={b64}ABCD"))
    f.evidence.append(EvidenceModel(source="code", location="com.example.A", detail=f"const3={b64}EFGH"))
    f.evidence.append(EvidenceModel(source="code", location="com.example.A",
                                    detail="String s = new String(Base64.decode(const1));"))
    a.findings.append(f)
    db_session.flush()
    obs = _by_cat(a, O.CAT_STRING)
    assert obs and obs[0].state == O.S_STRONG_INDICATOR
    assert any("UNKNOWN" in u for u in obs[0].uncertainties)


# ---- CASE 4: constant reflection -> RESOLVED, no unresolved impact ----

def test_case4_constant_reflection_resolved(db_session):
    a = _mk(db_session)
    _sem(a, db_session, "REFLECTION_TARGET", "com.example.A#m", "com.example.Target", "constant target")
    intel = O.build_intelligence(a)
    refl = [o for o in intel["observations"] if o.category == O.CAT_DYNAMIC_RESOLUTION and "reflection" in o.indicator]
    assert refl and refl[0].state == O.S_RESOLVED
    assert not any(i.impact_category == O.I_UNRESOLVED_REFLECTION for i in intel["impacts"])


# ---- CASE 5: external input -> reflection -> unresolved + impact ----

def test_case5_external_reflection_impact(db_session):
    a = _mk(db_session)
    src = "com.example.Web#onCreate"
    _sem(a, db_session, "REFLECTION_TARGET", src, "reflect:UNKNOWN", "non-constant target")
    _reachable(a, db_session, src)
    intel = O.build_intelligence(a)
    refl = [o for o in intel["observations"] if o.category == O.CAT_DYNAMIC_RESOLUTION and "reflection" in o.indicator]
    assert refl and refl[0].state == O.S_EXTERNALLY_INFLUENCED
    cats = {i.impact_category for i in intel["impacts"]}
    assert O.I_UNRESOLVED_REFLECTION in cats and O.I_INCREASED_REACH in cats


# ---- CASE 6: constant dynamic load -> RESOLVED ----

def test_case6_constant_dynamic_load_resolved(db_session):
    a = _mk(db_session)
    _sem(a, db_session, "DYNAMIC_LOAD", "com.example.A#load", "assets/plugin.dex", "constant path")
    dl = [o for o in _by_cat(a, O.CAT_DYNAMIC_RESOLUTION) if "dynamic_load" in o.indicator]
    assert dl and dl[0].state == O.S_RESOLVED


# ---- CASE 7: external -> dynamic loading -> DYNAMIC_RESOLUTION + impact ----

def test_case7_external_dynamic_load_impact(db_session):
    a = _mk(db_session)
    src = "com.example.Web#load"
    _sem(a, db_session, "DYNAMIC_LOAD", src, "dynload:UNKNOWN", "external path")
    _reachable(a, db_session, src)
    intel = O.build_intelligence(a)
    dl = [o for o in intel["observations"] if o.category == O.CAT_DYNAMIC_RESOLUTION and "dynamic_load" in o.indicator]
    assert dl and dl[0].state == O.S_EXTERNALLY_INFLUENCED
    assert any(i.impact_category == O.I_UNRESOLVED_DYNAMIC_LOAD for i in intel["impacts"])


# ---- CASE 8: normal branching -> no CONTROL_FLOW_OBFUSCATION ----

def test_case8_normal_branching_no_control_flow(db_session):
    a = _mk(db_session)
    # a few normal calls, well below the dispatcher threshold
    for i in range(5):
        a.code_edges.append(CodeEdge(src_key="com.example.A#m", dst_key=f"com.example.B#n{i}",
                                     edge_type="CALLS", confidence="MEDIUM"))
    db_session.flush()
    assert _by_cat(a, O.CAT_CONTROL_FLOW) == []


# ---- CASE 9: single anti-analysis API -> INDICATOR ----

def test_case9_single_anti_analysis_indicator(db_session):
    a = _mk(db_session)
    f = FindingModel(rule_id="X", title="x", category="code", severity="info", confidence="low",
                     status="POTENTIAL", component="com.example.A", fingerprint="fp9")
    f.evidence.append(EvidenceModel(source="code", location="com.example.A", detail="Debug.isDebuggerConnected()"))
    a.findings.append(f)
    db_session.flush()
    anti = O.build_intelligence(a)["anti_analysis"]
    assert anti and all(x.evidence_level == O.L_INDICATOR for x in anti)


# ---- CASE 10: multiple independent -> SUPPORTED / CONFIRMED_STATIC ----

def test_case10_multiple_anti_analysis_supported(db_session):
    a = _mk(db_session)
    lib = NativeLibrary(archive_path="lib/arm64/lib.so", abi="arm64-v8a", filename="lib.so", size_bytes=1000,
                        sha256="a" * 64, status="COMPLETE")
    a.native_libraries.append(lib)
    a.native_functions.append(NativeFunction(name="ptrace", kind="imported", library=lib))
    f = FindingModel(rule_id="X", title="x", category="code", severity="info", confidence="low",
                     status="POTENTIAL", component="com.example.A", fingerprint="fp10")
    f.evidence.append(EvidenceModel(source="code", location="com.example.A", detail="frida-server detection"))
    a.findings.append(f)
    db_session.flush()
    anti = O.build_intelligence(a)["anti_analysis"]
    assert anti and any(x.evidence_level in (O.L_SUPPORTED, O.L_CONFIRMED_STATIC) for x in anti)


# ---- CASE 11: stripped native symbols -> NATIVE_INDIRECTION ----

def test_case11_stripped_native(db_session):
    a = _mk(db_session)
    a.native_libraries.append(NativeLibrary(archive_path="lib/arm64/libx.so", abi="arm64-v8a", filename="libx.so",
                                            size_bytes=100000, sha256="b" * 64, status="COMPLETE",
                                            stripped=True, symbols_available=False))
    db_session.flush()
    intel = O.build_intelligence(a)
    nat = [o for o in intel["observations"] if o.category == O.CAT_NATIVE_INDIRECTION]
    assert nat and any(o.state == O.S_OBSERVED for o in nat)
    assert any(i.impact_category == O.I_REDUCED_NATIVE for i in intel["impacts"])


# ---- CASE 12: unknown native target preserved ----

def test_case12_unknown_native_target_preserved(db_session):
    a = _mk(db_session)
    a.security_boundaries.append(SecurityBoundary(boundary_type="JNI", component="com.example.N",
                                                  node_key="com.example.N#init", confidence="MEDIUM"))
    db_session.flush()
    nat = [o for o in O.build_intelligence(a)["observations"] if o.category == O.CAT_NATIVE_INDIRECTION]
    jni = [o for o in nat if "UNKNOWN_NATIVE_TARGET" in o.indicator]
    assert jni and jni[0].state == O.S_UNKNOWN
    assert any("UNKNOWN_NATIVE_TARGET" in u for u in jni[0].uncertainties)


# ---- CASE 13: obfuscation never changes CVE state ----

def test_case13_cve_state_unchanged(db_session):
    a = _mk(db_session)
    dep = Dependency(name="okhttp", product="okhttp", package_prefix="okhttp3", ecosystem="maven", version=None,
                     version_confidence="UNKNOWN", kind="java", identity_confidence="HIGH")
    a.dependencies.append(dep)
    db_session.add(VulnerabilityMatch(analysis=a, dependency=dep, cve_id="CVE-1", match_confidence="HIGH",
                                      identity_confidence="HIGH", version_state="POSSIBLY_AFFECTED",
                                      correlation_state="PRESENT_UNKNOWN_VERSION", reachability_state="UNKNOWN"))
    _classes(a, db_session, ["a", "b", "c", "d", "e", "f", "g", "h"], "a.a")  # heavy obfuscation
    db_session.flush()
    before = [(m.cve_id, m.version_state, m.correlation_state) for m in a.vulnerability_matches]
    O.build_obfuscation(db_session, a)
    db_session.flush()
    assert [(m.cve_id, m.version_state, m.correlation_state) for m in a.vulnerability_matches] == before


# ---- CASE 14: unresolved dynamic resolution -> impact preserved (not verified) ----

def test_case14_unresolved_dynamic_impact(db_session):
    a = _mk(db_session)
    src = "com.example.Web#load"
    _sem(a, db_session, "DYNAMIC_LOAD", src, "dynload:UNKNOWN", "external path")
    _reachable(a, db_session, src)
    intel = O.build_intelligence(a)
    assert any(i.impact_category == O.I_UNRESOLVED_DYNAMIC_LOAD for i in intel["impacts"])
    dl = [o for o in intel["observations"] if "dynamic_load" in o.indicator]
    assert dl and dl[0].state != O.S_RESOLVED  # never resolved to a concrete target


# ---- CASE 15: A->A diff -> 0 obfuscation changes + deterministic fingerprint ----

def test_case15_diff_identical(make_analysis, db_session):
    from app.analysis.diff import compare_analyses
    a = make_analysis(package="com.x")
    c = compare_analyses(db_session, a, a)
    db_session.flush()
    obf = [ch for ch in c.changes if ch.category == "obfuscation"]
    assert obf == []
    assert O.obfuscation_view(a)["fingerprint"] == O.obfuscation_view(a)["fingerprint"]


# ---- CASE 16: A->B new anti-analysis -> NEW_ANTI_ANALYSIS_INDICATOR + conservative ----

def test_case16_diff_new_anti_analysis(make_analysis, db_session):
    from app.analysis.obfuscation import obfuscation_from_diff
    from app.analysis.diff import compare_analyses
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    f = FindingModel(rule_id="X", title="x", category="code", severity="info", confidence="low",
                     status="POTENTIAL", component="com.x.Web", fingerprint="fpanti")
    f.evidence.append(EvidenceModel(source="code", location="com.x.Web", detail="ptrace anti-debug"))
    b.findings.append(f)
    db_session.flush()
    c = compare_analyses(db_session, a, b)
    db_session.flush()
    diff = obfuscation_from_diff(c)
    assert any(ch.get("transition") == "NEW_ANTI_ANALYSIS_INDICATOR" for ch in diff["changes"])
    assert diff["security_impact"] == "INCONCLUSIVE"  # never SECURITY_REGRESSION on its own


# ---- CASE 17: disconnected source/sink -> no false reachability obfuscation ----

def test_case17_disconnected_no_false_reachability(db_session):
    from app.analysis.graph_queries import investigate_paths
    a = _mk(db_session)
    # a reflection whose source is NOT reachable -> UNRESOLVED (not externally influenced)
    _sem(a, db_session, "REFLECTION_TARGET", "com.example.Iso#m", "reflect:UNKNOWN", "isolated")
    a.code_nodes.append(CodeNode(node_key="iso:a", node_type="JAVA_METHOD", label="A.foo"))
    a.code_nodes.append(CodeNode(node_key="iso:b", node_type="JAVA_METHOD", label="B.bar"))
    db_session.flush()
    refl = [o for o in _by_cat(a, O.CAT_DYNAMIC_RESOLUTION) if "reflection" in o.indicator]
    assert refl and refl[0].state == O.S_UNRESOLVED  # not EXTERNALLY_INFLUENCED (src not reachable)
    assert investigate_paths(a, "A.foo", "B.bar")["count"] == 0  # find_paths() == []


# ---- determinism + integrity ----

def test_deterministic_fingerprints(make_analysis, db_session):
    a = make_analysis(package="com.x")
    b = make_analysis(package="com.x")
    assert O.obfuscation_view(a)["fingerprint"] == O.obfuscation_view(b)["fingerprint"]
    i1 = O.build_intelligence(a); i2 = O.build_intelligence(a)
    assert sorted(o.fingerprint for o in i1["observations"]) == sorted(o.fingerprint for o in i2["observations"])
    assert i1["score"]["score"] == i2["score"]["score"]


def test_build_read_only_and_no_exploitable(db_session):
    import json
    a = _mk(db_session)
    _classes(a, db_session, ["a", "b", "c", "d", "e", "f", "g", "h"], "a.a")
    f = FindingModel(rule_id="Y", title="y", category="code", severity="high", confidence="high",
                     status="CONFIRMED_BY_STATIC_ANALYSIS", component="a.a", fingerprint="fpr")
    a.findings.append(f)
    db_session.flush()
    before = (f.severity, f.confidence, f.status)
    O.build_obfuscation(db_session, a)
    db_session.flush()
    assert (f.severity, f.confidence, f.status) == before  # existing finding never mutated
    assert "exploitable" not in json.dumps(O.obfuscation_view(a)).lower()


def test_score_is_analysis_complexity(db_session):
    a = _mk(db_session)
    _classes(a, db_session, ["a", "b", "c", "d", "e", "f", "g", "h"], "a.a")
    view = O.obfuscation_view(a)
    assert 0 <= view["score"]["score"] <= 100
    assert "complexity" in view["score"]["note"].lower()

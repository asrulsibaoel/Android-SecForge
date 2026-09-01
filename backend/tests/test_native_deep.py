"""Deep native / Ghidra correlation tests (prompt 20).

Ghidra is optional and UNAVAILABLE in this environment; the Ghidra import /
correlation path is exercised via clearly-marked FIXTURE data (GhidraExport with
source="FIXTURE"). ELF-only mode must be fully functional. No test asserts
exploitability; UNKNOWN_NATIVE_TARGET is always preserved.
"""

import hashlib

import pytest

from app.models.analysis import JNIBinding, NativeFunction, NativeLibrary
from app.native import deep_native as D
from app.native.ghidra_adapter import GhidraExport, capability, parse_export


def _sha(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _add_native_lib(db, analysis, *, filename="libnative.so", arch="arm64", stripped=False,
                    functions=None, jni=None):
    """Attach a realistic ELF native library (+ functions + JNI bindings) to an
    existing analysis, mirroring what the prompt8 ELF/JNI stage would persist."""
    lib = NativeLibrary(analysis_id=analysis.id, archive_path=f"lib/arm64-v8a/{filename}", abi="arm64-v8a",
                        filename=filename, size_bytes=4096, sha256=_sha(filename), architecture=arch,
                        elf_type="ET_DYN", soname=filename, stripped=stripped, symbols_available=not stripped,
                        status="COMPLETE")
    analysis.native_libraries.append(lib)
    db.flush()
    for name, kind in (functions or []):
        lib.functions.append(NativeFunction(analysis_id=analysis.id, library_id=lib.id, name=name,
                                             address=0x1000, kind=kind, symbol_type="FUNC",
                                             is_jni=name.startswith("Java_"), source="ELF", confidence="HIGH"))
    for jc, jm, native_fn in (jni or []):
        analysis.jni_bindings.append(JNIBinding(
            analysis_id=analysis.id, source="JAVA_NATIVE", confidence="HIGH", java_class=jc, java_method=jm,
            java_signature="()V", library_name=filename, native_function=native_fn,
            evidence="RegisterNatives" if native_fn and not native_fn.startswith("Java_") else "static naming"))
    db.flush()
    return lib


# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------


def test_capability_honest_when_ghidra_absent():
    cap = capability()
    assert cap["state"] in ("READY", "PARTIAL", "UNAVAILABLE", "ERROR")
    # The `no_ghidra` autouse fixture forces the absent path deterministically,
    # so Ghidra must be reported honestly as UNAVAILABLE, never faked.
    assert cap["state"] == "UNAVAILABLE"
    assert "reason" in cap and cap["headless"] is False


def test_build_elf_only_mode_when_no_ghidra(db_session, make_analysis):
    a = make_analysis()
    _add_native_lib(db_session, a, functions=[("Java_com_x_N_run", "exported"), ("strcpy", "imported")],
                    jni=[("com.x.N", "run", "Java_com_x_N_run")])
    run = D.build_deep_native(db_session, a)
    assert run.mode == D.MODE_ELF_ONLY
    assert run.ghidra_capability == "UNAVAILABLE"
    assert run.binaries_count == 1
    assert run.functions_count >= 2
    # ELF-only: no Ghidra call edges -> no fabricated reachability.
    assert run.call_edge_count == 0
    assert not any(o.state == D.API_REACHED for o in a.native_api_observations)


# ---------------------------------------------------------------------------
# JNI registration classification + UNKNOWN_NATIVE_TARGET preservation
# ---------------------------------------------------------------------------


def test_jni_static_naming_resolved(db_session, make_analysis):
    a = make_analysis()
    _add_native_lib(db_session, a, functions=[("Java_com_x_N_run", "exported")],
                    jni=[("com.x.N", "run", "Java_com_x_N_run")])
    D.build_deep_native(db_session, a)
    j = next(j for j in a.native_deep_jni_bindings if j.java_method == "run")
    assert j.state == "RESOLVED"
    assert j.registration_type == "STATIC_NAMING"
    assert j.native_function_fp is not None


def test_jni_dynamic_register_from_fixture(db_session, make_analysis):
    a = make_analysis()
    _add_native_lib(db_session, a, functions=[("do_native_work", "exported")], jni=[])
    export = GhidraExport(program="libnative.so", source="FIXTURE",
                          functions=[{"name": "do_native_work", "address": "0x2000", "size": 32,
                                      "exported": True, "imported": False}],
                          jni_registrations=[{"java_class": "com.x.N", "java_method": "dyn",
                                              "signature": "()V", "native": "do_native_work"}])
    D.build_deep_native(db_session, a, ghidra_exports={"libnative.so": export})
    dyn = next(j for j in a.native_deep_jni_bindings if j.java_method == "dyn")
    assert dyn.registration_type == "DYNAMIC_REGISTER"
    assert dyn.state == "RESOLVED"


def test_jni_unresolved_preserves_unknown_native_target(db_session, make_analysis):
    a = make_analysis()
    # JNI declares a native method with no matching native function -> UNKNOWN.
    _add_native_lib(db_session, a, functions=[("unrelated", "local")],
                    jni=[("com.x.N", "ghost", None)])
    run = D.build_deep_native(db_session, a)
    ghost = next(j for j in a.native_deep_jni_bindings if j.java_method == "ghost")
    assert ghost.state == "UNKNOWN"
    assert (ghost.evidence_json or {}).get("native_target") == D.UNKNOWN_NATIVE_TARGET
    assert run.unresolved_target_count >= 1


# ---------------------------------------------------------------------------
# ELF <-> Ghidra identity reconciliation
# ---------------------------------------------------------------------------


def test_elf_ghidra_identity_reconciliation(db_session, make_analysis):
    a = make_analysis()
    _add_native_lib(db_session, a, functions=[("compute", "exported")], jni=[])
    export = GhidraExport(program="libnative.so", source="FIXTURE",
                          functions=[{"name": "compute", "address": "0x1000", "size": 64,
                                      "exported": True, "imported": False}])
    D.build_deep_native(db_session, a, ghidra_exports={"libnative.so": export})
    computes = [f for f in a.native_deep_functions if f.normalized_name == "compute"]
    # Same content identity -> a single reconciled function, not two.
    assert len(computes) == 1
    assert computes[0].source == "ELF+GHIDRA"


# ---------------------------------------------------------------------------
# Native call graph + API reachability (only Ghidra edges establish reachability)
# ---------------------------------------------------------------------------


def _reachable_fixture():
    return GhidraExport(
        program="libnative.so", source="FIXTURE",
        functions=[{"name": "Java_com_x_N_run", "address": "0x1000", "size": 64, "exported": True, "imported": False},
                   {"name": "helper", "address": "0x1100", "size": 32, "exported": False, "imported": False},
                   {"name": "strcpy", "address": "0x0", "size": 0, "exported": False, "imported": True}],
        calls=[{"src": "Java_com_x_N_run", "dst": "helper", "src_addr": "0x1000", "dst_addr": "0x1100"},
               {"src": "helper", "dst": "strcpy", "src_addr": "0x1100", "dst_addr": "0x0"}])


def test_ghidra_call_graph_reaches_api(db_session, make_analysis):
    a = make_analysis()
    _add_native_lib(db_session, a, functions=[("Java_com_x_N_run", "exported")],
                    jni=[("com.x.N", "run", "Java_com_x_N_run")])
    run = D.build_deep_native(db_session, a, ghidra_exports={"libnative.so": _reachable_fixture()})
    assert run.call_edge_count >= 2
    reached = [o for o in a.native_api_observations if o.state == D.API_REACHED]
    assert any(o.api == "strcpy" for o in reached)
    assert any(o.category == "unsafe_str" or o.category for o in reached)


def test_dynamic_register_resolves_and_reaches_api(db_session, make_analysis):
    """A dynamically-registered (RegisterNatives) binding resolved to a native
    function must be usable as a reachability start (Java→JNI→native→API)."""
    a = make_analysis()
    _add_native_lib(db_session, a, functions=[("do_boot", "exported")], jni=[])
    export = GhidraExport(
        program="libnative.so", source="FIXTURE",
        functions=[{"name": "do_boot", "address": "0x2000", "size": 64, "exported": True, "imported": False},
                   {"name": "strcpy", "address": "0x0", "size": 0, "exported": False, "imported": True}],
        calls=[{"src": "do_boot", "dst": "strcpy", "src_addr": "0x2000", "dst_addr": "0x0"}],
        jni_registrations=[{"java_class": "com.x.N", "java_method": "boot", "signature": "()V", "native": "do_boot"}])
    D.build_deep_native(db_session, a, ghidra_exports={"libnative.so": export})
    dyn = next(j for j in a.native_deep_jni_bindings if j.java_method == "boot")
    assert dyn.state == "RESOLVED" and dyn.native_function_fp is not None
    reached = [o for o in a.native_api_observations if o.state == D.API_REACHED]
    assert any(o.api == "strcpy" for o in reached)
    res = D.native_paths(a, "boot", "strcpy")
    assert any(p["status"] == "REACHABLE" for p in res["paths"])


def test_reachability_never_fabricated_without_call_edges(db_session, make_analysis):
    a = make_analysis()
    # strcpy present (imported) but NO call edges -> present, never reached.
    _add_native_lib(db_session, a, functions=[("Java_com_x_N_run", "exported"), ("strcpy", "imported")],
                    jni=[("com.x.N", "run", "Java_com_x_N_run")])
    D.build_deep_native(db_session, a)
    strcpy_obs = [o for o in a.native_api_observations if o.api == "strcpy"]
    assert strcpy_obs and all(o.state == D.API_PRESENT for o in strcpy_obs)
    assert not any(o.state == D.API_REACHED for o in a.native_api_observations)


# ---------------------------------------------------------------------------
# Determinism + idempotency
# ---------------------------------------------------------------------------


def test_rebuild_is_idempotent_and_deterministic(db_session, make_analysis):
    a = make_analysis()
    _add_native_lib(db_session, a, functions=[("Java_com_x_N_run", "exported"), ("strcpy", "imported")],
                    jni=[("com.x.N", "run", "Java_com_x_N_run")])
    run1 = D.build_deep_native(db_session, a, ghidra_exports={"libnative.so": _reachable_fixture()})
    fp1 = run1.fingerprint
    n_fns, n_jni, n_calls, n_api = (len(a.native_deep_functions), len(a.native_deep_jni_bindings),
                                    len(a.native_call_edges), len(a.native_api_observations))
    run2 = D.build_deep_native(db_session, a, ghidra_exports={"libnative.so": _reachable_fixture()})
    # No duplicate logical observations, and a stable content fingerprint.
    assert (len(a.native_deep_functions), len(a.native_deep_jni_bindings),
            len(a.native_call_edges), len(a.native_api_observations)) == (n_fns, n_jni, n_calls, n_api)
    assert run2.fingerprint == fp1
    # Fingerprint is content-derived (no DB ids / timestamps).
    assert len(fp1) == 32 and run1.id != run2.id


def test_fingerprint_ignores_db_ids(db_session, make_analysis):
    a1 = make_analysis(package="com.a")
    a2 = make_analysis(package="com.b")
    for a in (a1, a2):
        _add_native_lib(db_session, a, functions=[("compute", "exported")], jni=[])
    r1 = D.build_deep_native(db_session, a1)
    r2 = D.build_deep_native(db_session, a2)
    # Same native content -> same fingerprint despite different analysis ids.
    assert r1.fingerprint == r2.fingerprint


# ---------------------------------------------------------------------------
# CVE signature correlation never fabricates AFFECTED / exploitable
# ---------------------------------------------------------------------------


def test_cve_signatures_never_assert_affected(db_session, make_analysis):
    from app.models.cve import Vulnerability, VulnerabilitySignature
    a = make_analysis()
    _add_native_lib(db_session, a, functions=[("strcpy", "imported"), ("Java_com_x_N_run", "exported")],
                    jni=[("com.x.N", "run", "Java_com_x_N_run")])
    # Attach a native signature to an existing match's vulnerability.
    m = a.vulnerability_matches[0]
    vuln = Vulnerability(cve_id=m.cve_id, source="test", summary="t", is_test_data=True)
    vuln.signatures.append(VulnerabilitySignature(kind="NATIVE_SYMBOL", native_symbol="strcpy"))
    db_session.add(vuln)
    db_session.flush()
    m.vulnerability = vuln
    db_session.flush()
    D.build_deep_native(db_session, a)
    sigs = D.native_cve_signatures(a)
    assert sigs, "expected a native signature correlation"
    for s in sigs:
        assert s["state"] in ("MATCHED", "PARTIAL_MATCH", "UNRESOLVED_TARGET", "NOT_MATCHED", "UNKNOWN")
        assert "AFFECTED" not in s["state"]
        assert "exploit" not in s["note"].lower()
    # Source CVE match state is untouched.
    assert m.version_state == "POSSIBLY_AFFECTED"


# ---------------------------------------------------------------------------
# Path investigation preserves uncertainty boundaries
# ---------------------------------------------------------------------------


def test_native_paths_preserve_unknown_boundary(db_session, make_analysis):
    a = make_analysis()
    _add_native_lib(db_session, a, functions=[("x", "local")], jni=[("com.x.N", "ghost", None)])
    D.build_deep_native(db_session, a)
    res = D.native_paths(a, "ghost", "strcpy")
    assert res["count"] >= 1
    assert any(p["status"] == "UNKNOWN" and p.get("boundary") == D.UNKNOWN_NATIVE_TARGET for p in res["paths"])


def test_native_explain_distinguishes_states(db_session, make_analysis):
    a = make_analysis()
    _add_native_lib(db_session, a, functions=[("Java_com_x_N_run", "exported")],
                    jni=[("com.x.N", "run", "Java_com_x_N_run")])
    D.build_deep_native(db_session, a, ghidra_exports={"libnative.so": _reachable_fixture()})
    res = D.native_explain(a, "strcpy")
    # It may DISCLAIM exploitability, but must never positively assert it.
    joined = " ".join(res["explanation"]).lower()
    assert "is exploitable" not in joined and "exploitable path" not in joined
    assert "distinctions" in res and "exploitable" not in res["distinctions"]
    assert res["note"]


# ---------------------------------------------------------------------------
# Parser is bounded / offline
# ---------------------------------------------------------------------------


def test_parse_export_marks_fixture_source():
    payload = {"program": "libx.so", "functions": [{"name": "f", "address": "0x1", "exported": True}],
               "calls": [], "jni_registrations": []}
    export = parse_export(payload, source="FIXTURE")
    assert export.source == "FIXTURE"
    assert export.functions and export.functions[0]["name"] == "f"


# ---------------------------------------------------------------------------
# Integration: validation / remediation / obfuscation / diff / KG
# ---------------------------------------------------------------------------


def test_validation_gains_native_claims_without_mutating_existing(db_session, make_analysis):
    from app.analysis.validation import build_claims, C_NATIVE_JNI_CONFIRMED, C_NATIVE_TARGET_UNRESOLVED
    a = make_analysis()
    before = {c.fingerprint: c.state for c in build_claims(a)}
    _add_native_lib(db_session, a, functions=[("Java_com_x_N_run", "exported")],
                    jni=[("com.x.N", "run", "Java_com_x_N_run"), ("com.x.N", "ghost", None)])
    D.build_deep_native(db_session, a)
    claims = build_claims(a)
    types = {c.claim_type for c in claims}
    assert C_NATIVE_JNI_CONFIRMED in types
    assert C_NATIVE_TARGET_UNRESOLVED in types
    # Existing (non-native-deep) claims keep their state — no silent mutation.
    after = {c.fingerprint: c.state for c in claims}
    for fp, state in before.items():
        assert after.get(fp) == state


def test_remediation_gains_recommendation_only_native_items(db_session, make_analysis):
    from app.analysis.remediation import build_items
    a = make_analysis()
    _add_native_lib(db_session, a, functions=[("Java_com_x_N_run", "exported")],
                    jni=[("com.x.N", "run", "Java_com_x_N_run")])
    D.build_deep_native(db_session, a, ghidra_exports={"libnative.so": _reachable_fixture()})
    items = build_items(a)
    native_items = [i for i in items if i.target_type in ("NATIVE_DEEP_JNI", "NATIVE_DEEP_API")]
    assert native_items
    for i in native_items:
        assert i.status == "REVIEW_REQUIRED"  # recommendation only, never a fix/assertion


def test_obfuscation_note_never_changes_state(db_session, make_analysis):
    from app.analysis.obfuscation import obfuscation_view
    a = make_analysis()
    _add_native_lib(db_session, a, functions=[("Java_com_x_N_run", "exported")],
                    jni=[("com.x.N", "run", "Java_com_x_N_run")])
    before = obfuscation_view(a)
    D.build_deep_native(db_session, a)
    after = obfuscation_view(a)
    # The correlation note is present but the score / fingerprint are unchanged.
    assert after["native_deep_correlation"]["available"] is True
    assert after["score"] == before["score"]
    assert after["fingerprint"] == before["fingerprint"]


def test_kg_projection_opt_in_default_off(db_session, make_analysis):
    from app.analysis.knowledge_graph import build_knowledge_graph, N_NATIVE_ANALYSIS
    a = make_analysis()
    _add_native_lib(db_session, a, functions=[("Java_com_x_N_run", "exported")],
                    jni=[("com.x.N", "run", "Java_com_x_N_run")])
    D.build_deep_native(db_session, a, ghidra_exports={"libnative.so": _reachable_fixture()})
    default = build_knowledge_graph(a)
    assert not any(n.node_type == N_NATIVE_ANALYSIS for n in default.nodes.values())
    with_native = build_knowledge_graph(a, include_native_deep=True)
    assert any(n.node_type == N_NATIVE_ANALYSIS for n in with_native.nodes.values())
    # Opt-in must not shrink the default projection.
    assert len(with_native.nodes) >= len(default.nodes)


def test_diff_new_reachable_api_is_security_relevant(db_session, make_analysis):
    from app.analysis.diff import _diff_native_deep, CAT_NATIVE_DEEP
    baseline = make_analysis(package="com.base")
    candidate = make_analysis(package="com.cand")
    _add_native_lib(db_session, baseline, functions=[("Java_com_x_N_run", "exported")],
                    jni=[("com.x.N", "run", "Java_com_x_N_run")])
    _add_native_lib(db_session, candidate, functions=[("Java_com_x_N_run", "exported")],
                    jni=[("com.x.N", "run", "Java_com_x_N_run")])
    # Only the candidate has a Ghidra call chain reaching strcpy.
    D.build_deep_native(db_session, baseline)
    D.build_deep_native(db_session, candidate, ghidra_exports={"libnative.so": _reachable_fixture()})
    changes = _diff_native_deep(baseline, candidate)
    assert changes
    reachable = [c for c in changes if c.evidence.get("transition") == "NEW_REACHABLE_NATIVE_API_PATH"]
    assert reachable and all(c.security_relevant for c in reachable)
    # Everything else in the native_deep category defaults to not-security-relevant.
    assert all(c.category == CAT_NATIVE_DEEP for c in changes)


def test_report_section_and_markdown(db_session, make_analysis):
    from app.reports.native_report import native_deep_section, native_markdown, export_native
    a = make_analysis()
    _add_native_lib(db_session, a, functions=[("Java_com_x_N_run", "exported"), ("strcpy", "imported")],
                    jni=[("com.x.N", "run", "Java_com_x_N_run")])
    D.build_deep_native(db_session, a, ghidra_exports={"libnative.so": _reachable_fixture()})
    section = native_deep_section(a)
    assert section["capability"]["mode"] == D.MODE_FIXTURE
    assert "binaries" in section and "jni_bindings" in section and "api_paths" in section
    md = native_markdown(a)
    assert "# Deep native / Ghidra report" in md
    assert "No exploitability is asserted" in md
    assert export_native(a, "json")
    assert export_native(a, "markdown")
    with pytest.raises(ValueError):
        export_native(a, "csv")

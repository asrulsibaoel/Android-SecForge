import zipfile

from app.analysis.axml import encode_axml
from app.analysis.orchestrator import analyze_apk
from app.models.analysis import Analysis
from app.testapp.builder import manifest_spec


def _stage(analysis, name):
    return next(s for s in analysis.stages if s["name"] == name)


def test_native_pipeline_persists_all_entities(db_session, native_apk, no_jadx):
    analysis = analyze_apk(native_apk, db_session)

    assert _stage(analysis, "native")["status"] == "COMPLETE"
    assert _stage(analysis, "jni")["status"] == "COMPLETE"
    assert _stage(analysis, "native_rules")["status"] == "COMPLETE"
    assert analysis.capabilities["native_analysis"] == "COMPLETE"

    persisted = db_session.get(Analysis, analysis.id)
    assert len(persisted.native_libraries) == 2
    lib = persisted.native_libraries[0]
    assert lib.soname == "libasfnative.so"
    assert any(dep.needed.startswith("libc") for dep in lib.dependencies)

    assert any(f.is_jni and f.kind == "exported" for f in persisted.native_functions)
    binding_sources = {b.source for b in persisted.jni_bindings}
    assert {"ELF_EXPORT", "JNI_ONLOAD"} <= binding_sources
    elf_binding = next(b for b in persisted.jni_bindings if b.source == "ELF_EXPORT")
    assert elf_binding.library_id is not None
    assert elf_binding.native_function_id is not None

    native_findings = [f for f in persisted.findings if f.category == "native"]
    assert any(f.rule_id == "ASF-NATIVE-STR-001" for f in native_findings)


def test_ghidra_unavailable_does_not_break_elf(db_session, native_apk, no_jadx):
    analysis = analyze_apk(native_apk, db_session)
    assert _stage(analysis, "ghidra")["status"] == "UNAVAILABLE"
    assert analysis.capabilities["ghidra"] == "UNAVAILABLE"
    assert _stage(analysis, "native")["status"] == "COMPLETE"


def test_malformed_native_library_is_isolated(db_session, isolated_storage, no_jadx):
    apk = isolated_storage / "malformed-native.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", encode_axml(manifest_spec()))
        archive.writestr("classes.dex", b"dex")
        archive.writestr("lib/x86/libbad.so", b"\x7fELF\x09garbage")
    analysis = analyze_apk(apk, db_session)

    assert _stage(analysis, "native")["status"] == "COMPLETE"  # stage completes despite bad lib
    assert analysis.capabilities["native_analysis"] == "DEGRADED"
    assert analysis.status != "FAILED"
    lib = analysis.native_libraries[0]
    assert lib.status == "FAILED"
    assert lib.error
    # manifest analysis unaffected
    assert _stage(analysis, "manifest")["status"] == "COMPLETE"


def test_no_native_libraries_completes_with_zero(db_session, test_apk, no_jadx):
    # The standard test app has only a placeholder .so (minimal ELF header, no
    # dynsym); native discovery still completes.
    analysis = analyze_apk(test_apk, db_session)
    assert _stage(analysis, "native")["status"] == "COMPLETE"
    assert analysis.capabilities["native_analysis"] in ("COMPLETE", "DEGRADED")

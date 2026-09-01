import hashlib
import zipfile
from pathlib import Path

from app.analysis.native import discover_native_libraries


def test_discovery_parses_real_libraries(native_apk, isolated_storage):
    sha = hashlib.sha256(native_apk.read_bytes()).hexdigest()
    libs = discover_native_libraries(native_apk, sha)
    assert len(libs) == 2
    abis = {lib.abi for lib in libs}
    assert abis == {"arm64-v8a", "armeabi-v7a"}
    for lib in libs:
        assert lib.status == "COMPLETE"
        assert lib.soname == "libasfnative.so"
        assert any(name.startswith("libc") for name in lib.needed)
        assert lib.jni_export_symbols == ["Java_com_androidsecforge_testapp_NativeBridge_verify"]
        assert lib.has_jni_onload
        assert Path(lib.workspace_path).exists()
        imported = {f.name for f in lib.functions if f.kind == "imported"}
        assert "strcpy" in imported


def test_malformed_library_is_isolated(isolated_storage):
    apk = isolated_storage / "bad-native.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("lib/x86/libbad.so", b"\x7fELF\x09garbage-not-valid-elf")
        archive.writestr("lib/x86/libtext.so", b"not even elf magic")
    sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    libs = discover_native_libraries(apk, sha)
    assert len(libs) == 2
    assert all(lib.status == "FAILED" for lib in libs)
    assert all(lib.error for lib in libs)
    # workspace extraction still happened (original preserved, isolated copy made)
    assert all(Path(lib.workspace_path).exists() for lib in libs)


def test_no_libraries_returns_empty(isolated_storage):
    apk = isolated_storage / "no-native.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"dex")
    sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    assert discover_native_libraries(apk, sha) == []

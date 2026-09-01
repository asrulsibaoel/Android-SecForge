import pytest

from app.analysis.elf import parse_elf


def test_parse_real_shared_object(native_so):
    parsed = parse_elf(native_so.read_bytes())
    assert parsed.ok
    assert parsed.elf_class in ("ELF32", "ELF64")
    assert parsed.endianness == "little"
    assert parsed.machine in ("x86_64", "x86", "aarch64", "arm")
    assert parsed.elf_type == "ET_DYN"
    assert parsed.dynamic_symbols_available


def test_soname_and_needed(native_so):
    parsed = parse_elf(native_so.read_bytes())
    assert parsed.soname == "libasfnative.so"
    assert any(name.startswith("libc") for name in parsed.needed)


def test_exported_and_imported_symbols(native_so):
    parsed = parse_elf(native_so.read_bytes())
    exported = {s.name for s in parsed.exported() if s.type == "FUNC"}
    imported = {s.name.split("@")[0] for s in parsed.imported() if s.type == "FUNC"}
    assert "Java_com_androidsecforge_testapp_NativeBridge_verify" in exported
    assert "JNI_OnLoad" in exported
    assert "asf_normal_export" in exported
    assert "strcpy" in imported
    assert "strlen" in imported


def test_stripped_binary_handled(native_so, tmp_path):
    import subprocess

    stripped = tmp_path / "stripped.so"
    stripped.write_bytes(native_so.read_bytes())
    if subprocess.run(["strip", str(stripped)], capture_output=True).returncode != 0:
        pytest.skip("strip not available")
    parsed = parse_elf(stripped.read_bytes())
    assert parsed.ok
    assert parsed.stripped is True  # .symtab gone
    # dynamic symbols still expose exports/imports after stripping
    assert parsed.dynamic_symbols_available
    assert {s.name for s in parsed.exported()}


@pytest.mark.parametrize(
    "data",
    [b"", b"MZ\x90\x00", b"\x7fELF", b"\x7fELF\x09\x01" + b"\x00" * 40, b"\x03\x00\x08\x00"],
)
def test_malformed_input_reports_not_ok(data):
    parsed = parse_elf(data)
    assert not parsed.ok
    assert parsed.error

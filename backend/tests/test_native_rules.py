from dataclasses import dataclass, field

from app.rules.engine import run_native_rules


@dataclass
class _Func:
    name: str
    kind: str
    address: int = 0


@dataclass
class _Lib:
    filename: str
    archive_path: str
    status: str = "COMPLETE"
    functions: list = field(default_factory=list)


def _lib(imports, exports=()):
    funcs = [_Func(n, "imported") for n in imports] + [_Func(n, "exported") for n in exports]
    return _Lib("libx.so", "lib/arm64-v8a/libx.so", functions=funcs)


def test_unsafe_string_api_flagged():
    findings = run_native_rules([_lib(["strcpy", "malloc", "free"])])
    ids = {f.rule_id for f in findings}
    assert "ASF-NATIVE-STR-001" in ids
    finding = next(f for f in findings if f.rule_id == "ASF-NATIVE-STR-001")
    assert finding.status == "POTENTIAL"
    assert finding.component == "libx.so"
    assert finding.evidence[0].source == "native"
    assert "strcpy" in finding.evidence[0].detail


def test_command_execution_api_flagged():
    findings = run_native_rules([_lib(["system", "popen"])])
    assert "ASF-NATIVE-EXEC-001" in {f.rule_id for f in findings}


def test_clean_library_produces_no_native_findings():
    findings = run_native_rules([_lib(["malloc", "free", "memset"])])
    assert findings == []


def test_failed_library_is_skipped():
    lib = _lib(["strcpy"])
    lib.status = "FAILED"
    assert run_native_rules([lib]) == []


def test_only_imported_symbols_match():
    # strcpy present but as an EXPORT (not imported) -> no finding
    lib = _Lib("libx.so", "lib/arm64-v8a/libx.so", functions=[_Func("strcpy", "exported")])
    assert run_native_rules([lib]) == []

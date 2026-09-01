from dataclasses import dataclass, field

from app.analysis.jni import demangle_jni, discover_jni, find_java_native_methods, find_library_loads


def test_demangle_simple():
    assert demangle_jni("Java_com_example_Foo_bar") == ("com.example.Foo", "bar")


def test_demangle_escapes():
    assert demangle_jni("Java_com_example_Foo_1Bar_do_1work") == ("com.example.Foo_Bar", "do_work")
    assert demangle_jni("Java_a_B_x_00024y") == ("a.B", "x$y")


def test_demangle_overload_signature_stripped():
    assert demangle_jni("Java_com_example_Foo_bar__Ljava_lang_String_2") == ("com.example.Foo", "bar")


def test_demangle_non_jni_returns_none():
    assert demangle_jni("asf_normal_export") is None
    assert demangle_jni("JNI_OnLoad") is None


def test_find_java_native_methods():
    src = [("Foo.java", "package p;\nclass Foo {\n  public native int verify(String s);\n}")]
    methods = find_java_native_methods(src)
    assert methods[0]["java_class"] == "p.Foo"
    assert methods[0]["java_method"] == "verify"
    assert methods[0]["line"] == 3


def test_find_library_loads():
    src = [("Foo.java", 'class Foo { static { System.loadLibrary("native-lib"); } }')]
    loads = find_library_loads(src)
    assert loads[0]["library"] == "native-lib"


@dataclass
class _FakeFunc:
    name: str
    kind: str = "exported"


@dataclass
class _FakeLib:
    filename: str
    functions: list = field(default_factory=list)

    @property
    def jni_export_symbols(self):
        return [f.name for f in self.functions if f.kind == "exported" and f.name.startswith("Java_")]

    @property
    def has_jni_onload(self):
        return any(f.name == "JNI_OnLoad" and f.kind == "exported" for f in self.functions)


def test_discover_jni_cross_match_high_confidence():
    lib = _FakeLib(
        "libnative-lib.so",
        [
            _FakeFunc("Java_com_example_Foo_verify"),
            _FakeFunc("JNI_OnLoad"),
        ],
    )
    sources = [
        ("com/example/Foo.java", "package com.example;\nclass Foo {\n public native int verify(String s);\n static { System.loadLibrary(\"native-lib\"); }\n}"),
    ]
    bindings = discover_jni([lib], sources)
    by_source = {b.source for b in bindings}
    assert {"ELF_EXPORT", "JNI_ONLOAD", "LOAD_LIBRARY"} <= by_source

    elf = next(b for b in bindings if b.source == "ELF_EXPORT")
    assert elf.confidence == "HIGH"  # both ELF export and Java native method observed
    assert elf.java_class == "com.example.Foo"
    assert elf.java_method == "verify"

    load = next(b for b in bindings if b.source == "LOAD_LIBRARY")
    assert load.confidence == "HIGH"  # libnative-lib.so is present
    assert load.library_name == "libnative-lib.so"


def test_discover_jni_export_without_java_side_is_medium():
    lib = _FakeLib("libx.so", [_FakeFunc("Java_com_example_Bar_run")])
    bindings = discover_jni([lib], sources=[])
    elf = next(b for b in bindings if b.source == "ELF_EXPORT")
    assert elf.confidence == "MEDIUM"

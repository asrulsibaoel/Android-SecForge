from dataclasses import dataclass, field

from app.analysis.code_index import index_source_texts
from app.analysis.dependencies import build_dependencies


@dataclass
class _Func:
    name: str
    kind: str


@dataclass
class _Lib:
    filename: str
    soname: str
    abi: str = "arm64-v8a"
    architecture: str = "aarch64"
    status: str = "COMPLETE"
    archive_path: str = "lib/arm64-v8a/libfoo.so"
    needed: list = field(default_factory=list)
    functions: list = field(default_factory=list)


def test_java_fingerprint_from_packages():
    src = [
        ("okhttp3/OkHttpClient.java", "package okhttp3;\nclass OkHttpClient {}"),
        ("okhttp3/Request.java", "package okhttp3;\nclass Request {}"),
        ("com/google/gson/Gson.java", "package com.google.gson;\nclass Gson {}"),
        ("com/app/Main.java", "package com.app;\nclass Main {}"),  # not a known library
    ]
    index = index_source_texts(src)
    deps = build_dependencies(index, [], None)
    names = {d.name for d in deps}
    assert "okhttp" in names
    assert "gson" in names
    okhttp = next(d for d in deps if d.name == "okhttp")
    assert okhttp.kind == "java"
    assert okhttp.identity_confidence == "HIGH"
    assert okhttp.version is None  # never invented without metadata


def test_native_dependencies_bundled_vs_system():
    lib = _Lib(filename="libfoo.so", soname="libfoo.so", needed=["libc.so", "libcustom.so"],
               functions=[_Func("Java_x", "exported"), _Func("strcpy", "imported")])
    deps = build_dependencies(None, [lib], None)
    foo = next(d for d in deps if d.name == "foo")
    assert foo.kind == "native" and foo.bundled is True
    assert foo.architecture == "arm64-v8a"
    # libc is a system/platform dependency (not bundled)
    libc = next(d for d in deps if d.name == "c")
    assert libc.bundled is False
    assert any("system" in e.detail for e in libc.evidence)


def test_native_version_from_soname_suffix():
    lib = _Lib(filename="libssl.so.1.1", soname="libssl.so.1.1", archive_path="lib/x86/libssl.so.1.1")
    deps = build_dependencies(None, [lib], None)
    ssl = next(d for d in deps if d.name == "ssl")
    assert ssl.version == "1.1"
    assert ssl.version_source == "soname_suffix"

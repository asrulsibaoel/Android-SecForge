"""Builder for AndroidSecForge-TestApp — a deterministic, local-only test APK.

The APK is assembled directly (binary AXML manifest + a minimal valid DEX header)
so it can be produced without the Android SDK. It is intentionally
demonstrative: it declares debuggable/backup/cleartext flags, exported
components with no permission guard, an exported provider, and a deep link.

It contains NO real credentials and communicates with nothing. It exists solely
to exercise the analysis pipeline.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import zipfile
from pathlib import Path

from app.analysis.axml import BuildAttr, BuildElement, encode_axml

PACKAGE = "com.androidsecforge.testapp"
_NATIVE_SOURCE = Path(__file__).resolve().parent / "native_fixture.c"


def _attr(name: str, value: str, kind: str = "string") -> BuildAttr:
    return BuildAttr(name=name, value=value, kind=kind)


def manifest_spec() -> BuildElement:
    return BuildElement(
        "manifest",
        attrs=[
            BuildAttr("package", PACKAGE, "string", namespace=None),
            _attr("versionCode", "3", "int"),
            _attr("versionName", "1.3.0"),
        ],
        children=[
            BuildElement(
                "uses-sdk",
                attrs=[_attr("minSdkVersion", "23", "int"), _attr("targetSdkVersion", "33", "int")],
            ),
            BuildElement("uses-permission", attrs=[_attr("name", "android.permission.INTERNET")]),
            BuildElement("uses-permission", attrs=[_attr("name", "android.permission.READ_SMS")]),
            BuildElement("uses-permission", attrs=[_attr("name", "android.permission.CAMERA")]),
            BuildElement("uses-permission", attrs=[_attr("name", "com.androidsecforge.testapp.CUSTOM")]),
            BuildElement(
                "permission",
                attrs=[
                    _attr("name", "com.androidsecforge.testapp.CUSTOM"),
                    _attr("protectionLevel", "normal"),
                ],
            ),
            BuildElement(
                "application",
                attrs=[
                    _attr("debuggable", "true", "bool"),
                    _attr("allowBackup", "true", "bool"),
                    _attr("usesCleartextTraffic", "true", "bool"),
                    _attr("label", "AndroidSecForge TestApp"),
                ],
                children=[
                    BuildElement(
                        "activity",
                        attrs=[_attr("name", ".MainActivity"), _attr("exported", "true", "bool")],
                        children=[
                            BuildElement(
                                "intent-filter",
                                children=[
                                    BuildElement("action", attrs=[_attr("name", "android.intent.action.MAIN")]),
                                    BuildElement("category", attrs=[_attr("name", "android.intent.category.LAUNCHER")]),
                                ],
                            )
                        ],
                    ),
                    BuildElement(
                        "activity",
                        attrs=[_attr("name", ".DeepLinkActivity"), _attr("exported", "true", "bool")],
                        children=[
                            BuildElement(
                                "intent-filter",
                                children=[
                                    BuildElement("action", attrs=[_attr("name", "android.intent.action.VIEW")]),
                                    BuildElement("category", attrs=[_attr("name", "android.intent.category.BROWSABLE")]),
                                    BuildElement("data", attrs=[_attr("scheme", "asftest"), _attr("host", "open")]),
                                ],
                            )
                        ],
                    ),
                    BuildElement(
                        "service",
                        attrs=[_attr("name", ".ExportedService"), _attr("exported", "true", "bool")],
                    ),
                    BuildElement(
                        "receiver",
                        attrs=[_attr("name", ".BootReceiver")],
                        children=[
                            BuildElement(
                                "intent-filter",
                                children=[
                                    BuildElement("action", attrs=[_attr("name", "android.intent.action.BOOT_COMPLETED")]),
                                ],
                            )
                        ],
                    ),
                    BuildElement(
                        "provider",
                        attrs=[
                            _attr("name", ".DataProvider"),
                            _attr("exported", "true", "bool"),
                            _attr("authorities", f"{PACKAGE}.provider"),
                        ],
                    ),
                    BuildElement(
                        "activity",
                        attrs=[_attr("name", ".InternalActivity"), _attr("exported", "false", "bool")],
                    ),
                ],
            ),
        ],
    )


def _minimal_dex() -> bytes:
    """A minimal DEX with a valid, parseable header (not decompilable)."""
    dex = bytearray(112)
    dex[0:8] = b"dex\n035\0"
    struct.pack_into("<I", dex, 32, 112)  # file size
    struct.pack_into("<I", dex, 36, 112)  # header size
    struct.pack_into("<I", dex, 56, 12)  # string count
    struct.pack_into("<I", dex, 80, 4)  # field count
    struct.pack_into("<I", dex, 88, 6)  # method count
    struct.pack_into("<I", dex, 96, 3)  # class count
    return bytes(dex)


def _minimal_so() -> bytes:
    """A minimal ELF header so the structure inspector lists a native library."""
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # little-endian
    header[6] = 1  # version
    struct.pack_into("<H", header, 16, 3)  # ET_DYN
    struct.pack_into("<H", header, 18, 183)  # EM_AARCH64
    return bytes(header)


def build_test_apk(dest: Path) -> Path:
    """Assemble AndroidSecForge-TestApp.apk at ``dest`` and return the path."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    manifest = encode_axml(manifest_spec())
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", _minimal_dex())
        archive.writestr("classes2.dex", _minimal_dex())
        archive.writestr("lib/arm64-v8a/libtestapp.so", _minimal_so())
        archive.writestr("resources.arsc", b"\x00\x00\x00\x00")
        archive.writestr("res/layout/main.xml", b"<layout/>")
        archive.writestr("assets/notice.txt", b"INTENTIONALLY VULNERABLE TEST APPLICATION - local use only\n")
    return dest


def native_compiler() -> str | None:
    """Return a host C compiler capable of building a shared object, or None."""
    for candidate in ("cc", "gcc", "clang"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def compile_native_fixture(dest_so: Path) -> Path | None:
    """Compile the native test fixture into a real shared object.

    Returns the path, or None when no host C compiler is available (callers
    should skip native-build tests cleanly rather than fabricating ELF output).
    """
    compiler = native_compiler()
    if compiler is None:
        return None
    dest_so.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [compiler, "-shared", "-fPIC", "-Wl,-soname,libasfnative.so", "-o", str(dest_so), str(_NATIVE_SOURCE)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0 or not dest_so.exists():
        return None
    return dest_so


def build_native_test_apk(dest: Path, so_path: Path) -> Path:
    """Build a test APK that embeds a real shared object under two ABI dirs."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    so_bytes = so_path.read_bytes()
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", encode_axml(manifest_spec()))
        archive.writestr("classes.dex", _minimal_dex())
        archive.writestr("lib/arm64-v8a/libasfnative.so", so_bytes)
        archive.writestr("lib/armeabi-v7a/libasfnative.so", so_bytes)
        archive.writestr("assets/notice.txt", b"INTENTIONALLY DEMONSTRATIVE TEST APPLICATION - local use only\n")
    return dest

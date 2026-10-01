"""JNI discovery: connect Java/Kotlin native methods to ELF exports.

Combines two statically-observable sides:

* ELF exports named ``Java_<pkg>_<Class>_<method>`` (demangled per the JNI spec)
  and ``JNI_OnLoad`` (which signals possible dynamic registration).
* Decompiled Java/Kotlin: ``native`` method declarations and
  ``System.loadLibrary`` / ``System.load`` / ``Runtime...loadLibrary`` calls.

Mappings carry an explicit confidence and evidence. A mapping is only HIGH when
both sides are observed; nothing is claimed that cannot be shown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

_NATIVE_METHOD_RE = re.compile(
    r"(?:public|private|protected|static|final|synchronized|\s)*"
    r"\bnative\b[\w<>\[\].,\s]+?\b([A-Za-z_]\w*)\s*\(([^;{)]*)\)\s*;",
)
_CLASS_RE = re.compile(r"\b(?:class|interface|enum)\s+([A-Za-z_]\w*)")
_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
_LOAD_RE = re.compile(
    r"(?:System\.loadLibrary|System\.load|Runtime\.getRuntime\(\)\.loadLibrary|loadLibrary)"
    r"\s*\(\s*\"([^\"]+)\"",
)


@dataclass
class JniBinding:
    source: str  # ELF_EXPORT | JAVA_NATIVE | JNI_ONLOAD | LOAD_LIBRARY
    confidence: str
    java_class: str | None = None
    java_method: str | None = None
    java_signature: str | None = None
    library_name: str | None = None
    native_function: str | None = None
    evidence: str = ""


def demangle_jni(symbol: str) -> tuple[str | None, str | None] | None:
    """Decode a ``Java_...`` JNI export into (fully_qualified_class, method).

    Returns None if the symbol is not a JNI method export.
    """
    if not symbol.startswith("Java_"):
        return None
    body = symbol[len("Java_"):]
    # An overloaded method appends "__" + mangled argument signature.
    sep = body.find("__")
    name_part = body[:sep] if sep != -1 else body

    out: list[str] = []
    i = 0
    length = len(name_part)
    while i < length:
        char = name_part[i]
        if char == "_":
            nxt = name_part[i + 1] if i + 1 < length else ""
            if nxt == "1":
                out.append("_"); i += 2
            elif nxt == "2":
                out.append(";"); i += 2
            elif nxt == "3":
                out.append("["); i += 2
            elif nxt == "0":
                try:
                    out.append(chr(int(name_part[i + 2:i + 6], 16)))
                except ValueError:
                    out.append("_")
                i += 6
            else:
                out.append("."); i += 1  # package/class separator
        else:
            out.append(char)
            i += 1
    full = "".join(out)
    if "." not in full:
        return (None, full)
    java_class, method = full.rsplit(".", 1)
    return (java_class, method)


def find_java_native_methods(sources: list[tuple[str, str]]) -> list[dict]:
    results: list[dict] = []
    for path, content in sources:
        package_match = _PACKAGE_RE.search(content)
        package = package_match.group(1) if package_match else None
        current_class: str | None = None
        for line_no, line in enumerate(content.splitlines(), start=1):
            class_match = _CLASS_RE.search(line)
            if class_match:
                current_class = class_match.group(1)
            method_match = _NATIVE_METHOD_RE.search(line)
            if method_match:
                fqcn = f"{package}.{current_class}" if package and current_class else current_class
                results.append(
                    {
                        "java_class": fqcn,
                        "java_method": method_match.group(1),
                        "java_signature": method_match.group(2).strip(),
                        "file": path,
                        "line": line_no,
                    }
                )
    return results


def find_library_loads(sources: list[tuple[str, str]]) -> list[dict]:
    results: list[dict] = []
    for path, content in sources:
        package_match = _PACKAGE_RE.search(content)
        package = package_match.group(1) if package_match else None
        current_class: str | None = None
        for line_no, line in enumerate(content.splitlines(), start=1):
            class_match = _CLASS_RE.search(line)
            if class_match:
                current_class = class_match.group(1)
            for match in _LOAD_RE.finditer(line):
                fqcn = f"{package}.{current_class}" if package and current_class else current_class
                results.append(
                    {
                        "library": match.group(1),
                        "java_class": fqcn,
                        "file": path,
                        "line": line_no,
                    }
                )
    return results


@dataclass
class _LibExports:
    filename: str
    jni_exports: dict[tuple[str | None, str], str] = field(default_factory=dict)  # (class, method) -> symbol
    has_jni_onload: bool = False


def discover_jni(native_libraries: list, sources: list[tuple[str, str]]) -> list[JniBinding]:
    """Build JNI bindings from ELF exports and decompiled code.

    ``native_libraries`` items must expose ``.filename`` and an ``.exported_jni``
    iterable of (symbol_name,) plus ``.has_jni_onload`` — see native.py adapter.
    """
    bindings: list[JniBinding] = []

    # Index Java-side native methods for cross-matching.
    java_methods = find_java_native_methods(sources)
    java_index = {(m["java_class"], m["java_method"]): m for m in java_methods}
    matched_java: set[tuple[str | None, str | None]] = set()

    for lib in native_libraries:
        if getattr(lib, "has_jni_onload", False):
            bindings.append(
                JniBinding(
                    source="JNI_ONLOAD",
                    confidence=MEDIUM,
                    library_name=lib.filename,
                    native_function="JNI_OnLoad",
                    evidence=f"{lib.filename} exports JNI_OnLoad (dynamic registration possible)",
                )
            )
        for symbol in getattr(lib, "jni_export_symbols", []):
            demangled = demangle_jni(symbol)
            if demangled is None:
                continue
            java_class, java_method = demangled
            key = (java_class, java_method)
            java_hit = java_index.get(key)
            if java_hit:
                matched_java.add(key)
            bindings.append(
                JniBinding(
                    source="ELF_EXPORT",
                    confidence=HIGH if java_hit else MEDIUM,
                    java_class=java_class,
                    java_method=java_method,
                    java_signature=java_hit["java_signature"] if java_hit else None,
                    library_name=lib.filename,
                    native_function=symbol,
                    evidence=(
                        f"ELF export {symbol} in {lib.filename}"
                        + (f"; matches declared native method {java_class}.{java_method}" if java_hit else "")
                    ),
                )
            )

    # Java-side native methods with no matching ELF export (dynamic registration
    # or the implementing library was not decompiled/present).
    for method in java_methods:
        key = (method["java_class"], method["java_method"])
        if key in matched_java:
            continue
        bindings.append(
            JniBinding(
                source="JAVA_NATIVE",
                confidence=LOW,
                java_class=method["java_class"],
                java_method=method["java_method"],
                java_signature=method["java_signature"],
                evidence=f"declared native method at {method['file']}:{method['line']} (no matching ELF export found)",
            )
        )

    # loadLibrary calls.
    library_names = {lib.filename for lib in native_libraries}
    for load in find_library_loads(sources):
        candidate = f"lib{load['library']}.so"
        confidence = HIGH if candidate in library_names else LOW
        bindings.append(
            JniBinding(
                source="LOAD_LIBRARY",
                confidence=confidence,
                java_class=load["java_class"],
                library_name=candidate if candidate in library_names else load["library"],
                evidence=f"loadLibrary(\"{load['library']}\") at {load['file']}:{load['line']}",
            )
        )

    return bindings

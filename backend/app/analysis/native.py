"""Native library discovery: enumerate, extract, and ELF-parse ``lib/**/*.so``.

Produces normalized :class:`NativeLibResult` records (with functions and NEEDED
dependencies) that the orchestrator persists. Per-library failures are isolated:
a malformed ELF marks that library FAILED without affecting the others. Original
libraries are copied into the workspace, never modified.
"""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from app.analysis.dex import workspace_root
from app.analysis.elf import parse_elf

_JNI_ONLOAD = {"JNI_OnLoad", "JNI_OnUnload"}
# Cap local symbols persisted per library (exports/imports are always kept).
_LOCAL_SYMBOL_CAP = 4000


@dataclass
class NativeFunctionResult:
    name: str
    address: int
    symbol_type: str
    binding: str
    visibility: str
    size: int
    kind: str  # exported | imported | local
    is_jni: bool
    source: str = "ELF"
    confidence: str = "HIGH"


@dataclass
class NativeLibResult:
    archive_path: str
    abi: str
    filename: str
    size_bytes: int
    sha256: str
    workspace_path: str | None = None
    status: str = "COMPLETE"
    error: str | None = None
    elf_class: str | None = None
    architecture: str | None = None
    endianness: str | None = None
    elf_type: str | None = None
    entry_point: int | None = None
    soname: str | None = None
    stripped: bool = False
    symbols_available: bool = False
    functions_truncated: bool = False
    functions: list[NativeFunctionResult] = field(default_factory=list)
    needed: list[str] = field(default_factory=list)

    @property
    def jni_export_symbols(self) -> list[str]:
        return [f.name for f in self.functions if f.kind == "exported" and f.name.startswith("Java_")]

    @property
    def has_jni_onload(self) -> bool:
        return any(f.name in _JNI_ONLOAD and f.kind == "exported" for f in self.functions)


def _abi_of(archive_path: str) -> str:
    parts = archive_path.split("/")
    return parts[1] if len(parts) > 2 and parts[0] == "lib" else "unknown"


def discover_native_libraries(apk_path: Path, sha256: str, artifact_type: str = "apk") -> list[NativeLibResult]:
    root = workspace_root(sha256)
    results: list[NativeLibResult] = []
    with zipfile.ZipFile(apk_path) as archive:
        entries = sorted(
            name for name in archive.namelist() if name.startswith("lib/") and name.endswith(".so")
        )
        for name in entries:
            data = archive.read(name)
            abi = _abi_of(name)
            filename = Path(name).name
            record = NativeLibResult(
                archive_path=name,
                abi=abi,
                filename=filename,
                size_bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
            )
            # Extract into the workspace (never modify the original APK).
            out_dir = root / "native" / abi
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / filename
            out_path.write_bytes(data)
            record.workspace_path = str(out_path)

            parsed = parse_elf(data)
            if not parsed.ok:
                record.status = "FAILED"
                record.error = parsed.error
                results.append(record)
                continue

            record.elf_class = parsed.elf_class
            record.architecture = parsed.machine
            record.endianness = parsed.endianness
            record.elf_type = parsed.elf_type
            record.entry_point = parsed.entry
            record.soname = parsed.soname
            record.stripped = parsed.stripped
            record.symbols_available = parsed.dynamic_symbols_available or parsed.static_symbols_available
            record.needed = list(parsed.needed)
            record.functions, record.functions_truncated = _build_functions(parsed)
            results.append(record)
    return results


def _build_functions(parsed) -> tuple[list[NativeFunctionResult], bool]:
    seen: set[tuple[str, str, str]] = set()
    exported: list[NativeFunctionResult] = []
    imported: list[NativeFunctionResult] = []
    local: list[NativeFunctionResult] = []
    for symbol in parsed.symbols:
        base_name = symbol.name.split("@", 1)[0]
        if not base_name:
            continue
        key = (base_name, symbol.kind, symbol.type)
        if key in seen:
            continue
        seen.add(key)
        is_jni = base_name.startswith("Java_") or base_name in _JNI_ONLOAD
        confidence = "HIGH" if symbol.table == "dynsym" else "MEDIUM"
        func = NativeFunctionResult(
            name=base_name,
            address=symbol.value,
            symbol_type=symbol.type,
            binding=symbol.binding,
            visibility=symbol.visibility,
            size=symbol.size,
            kind=symbol.kind,
            is_jni=is_jni,
            confidence=confidence,
        )
        if symbol.kind == "exported":
            exported.append(func)
        elif symbol.kind == "imported":
            imported.append(func)
        else:
            local.append(func)
    truncated = len(local) > _LOCAL_SYMBOL_CAP
    return exported + imported + local[:_LOCAL_SYMBOL_CAP], truncated

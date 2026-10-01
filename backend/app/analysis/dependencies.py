"""Unified dependency inventory (Java + native).

Java dependencies are fingerprinted from decompiled package namespaces; versions
come only from embedded metadata (never inferred from a prefix). Native
dependencies come from the existing ELF analysis (bundled `.so` + SONAME +
DT_NEEDED), classified as bundled / application / system. Identity confidence and
version confidence are tracked separately, and versions are never invented.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from app.analysis.fingerprints import Fingerprint, match_prefix

# Native libraries that are Android/Linux platform-provided (not bundled vulns).
_SYSTEM_SONAMES = {
    "libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so", "libstdc++.so",
    "libandroid.so", "libjnigraphics.so", "libGLESv2.so", "libGLESv1_CM.so",
    "libEGL.so", "libOpenSLES.so", "libvulkan.so", "libmediandk.so", "libc++.so",
    "libc++_shared.so", "libnativewindow.so", "libaaudio.so", "libcamera2ndk.so",
}

_META_VERSION_RE = re.compile(r"^version=(.+)$", re.MULTILINE)
_META_ARTIFACT_RE = re.compile(r"^artifactId=(.+)$", re.MULTILINE)
_META_GROUP_RE = re.compile(r"^groupId=(.+)$", re.MULTILINE)
# libfoo.so.1.2.3  or  libfoo-1.2.3.so
_SONAME_VER_RE = re.compile(r"\.so\.(\d+(?:\.\d+)*)$")
_FILE_VER_RE = re.compile(r"-(\d+(?:\.\d+)+)\.so$")


@dataclass
class DependencyEvidence:
    source: str
    detail: str
    location: str | None = None


@dataclass
class Dependency:
    name: str
    ecosystem: str
    kind: str  # java | native
    product: str | None = None
    cpe: str | None = None
    version: str | None = None
    version_source: str | None = None
    version_strategy: str = "GENERIC"
    architecture: str | None = None
    artifact: str | None = None
    bundled: bool = False
    identity_confidence: str = "MEDIUM"
    version_confidence: str = "UNKNOWN"
    package_prefix: str | None = None
    evidence: list[DependencyEvidence] = field(default_factory=list)


def build_dependencies(code_index, native_results, apk_path: Path | None) -> list[Dependency]:
    java = _java_dependencies(code_index, apk_path)
    native = _native_dependencies(native_results)
    return java + native


# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------


def _java_dependencies(code_index, apk_path: Path | None) -> list[Dependency]:
    if code_index is None:
        return []
    packages: dict[str, int] = {}
    for entity in code_index.entities:
        pkg = entity.get("package")
        if pkg:
            packages[pkg] = packages.get(pkg, 0) + 1

    matched: dict[str, Dependency] = {}
    for package, count in packages.items():
        fp = match_prefix(package)
        if fp is None:
            continue
        dep = matched.get(fp.name)
        if dep is None:
            dep = Dependency(
                name=fp.name, ecosystem=fp.ecosystem, kind="java", product=fp.product, cpe=fp.cpe,
                package_prefix=fp.prefix, version_strategy=_strategy_for(fp.ecosystem),
            )
            matched[fp.name] = dep
        dep.evidence.append(DependencyEvidence("dex_package", f"package {package} ({count} classes)"))

    # A curated fingerprint is an exact package-signature match, so dependency
    # identity is HIGH. (Fuzzy/heuristic uncertainty is handled at CVE match time
    # via match_method=HEURISTIC, not here.)
    for dep in matched.values():
        dep.identity_confidence = "HIGH"

    if apk_path is not None:
        _attach_embedded_versions(matched, apk_path)
    return list(matched.values())


def _strategy_for(ecosystem: str) -> str:
    return {"maven": "MAVEN", "android": "ANDROID", "native": "GENERIC"}.get(ecosystem, "GENERIC")


def _attach_embedded_versions(matched: dict[str, Dependency], apk_path: Path) -> None:
    """Extract versions from META-INF metadata (pom.properties, *.version)."""
    try:
        with zipfile.ZipFile(apk_path) as archive:
            names = [n for n in archive.namelist() if n.startswith("META-INF/")]
            for name in names:
                lower = name.lower()
                if lower.endswith("pom.properties"):
                    try:
                        text = archive.read(name).decode("utf-8", errors="replace")
                    except (OSError, KeyError):
                        continue
                    ver = _META_VERSION_RE.search(text)
                    art = _META_ARTIFACT_RE.search(text)
                    grp = _META_GROUP_RE.search(text)
                    if not ver:
                        continue
                    version = ver.group(1).strip()
                    artifact = (art.group(1).strip() if art else "")
                    group = (grp.group(1).strip() if grp else "")
                    _apply_version(matched, artifact, group, version, name)
                elif lower.endswith(".version"):
                    try:
                        version = archive.read(name).decode("utf-8", errors="replace").strip()
                    except (OSError, KeyError):
                        continue
                    stem = Path(name).name[: -len(".version")]
                    _apply_version(matched, stem, stem, version, name)
    except (zipfile.BadZipFile, OSError):
        return


def _apply_version(matched: dict[str, Dependency], artifact: str, group: str, version: str, location: str) -> None:
    if not re.match(r"^\d", version):
        return
    for dep in matched.values():
        hay = f"{group} {artifact}".lower()
        if dep.name.lower() in hay or (dep.package_prefix and dep.package_prefix.split(".")[-1] in hay):
            dep.version = version
            dep.version_source = "embedded_metadata"
            dep.version_confidence = "EXACT"
            dep.evidence.append(DependencyEvidence("embedded_metadata", f"version={version} ({artifact})", location))
            return


# ---------------------------------------------------------------------------
# Native
# ---------------------------------------------------------------------------


def _native_dependencies(native_results) -> list[Dependency]:
    deps: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    for lib in native_results or []:
        if getattr(lib, "status", "COMPLETE") != "COMPLETE":
            continue
        key = (lib.filename, lib.abi)
        if key in seen:
            continue
        seen.add(key)
        soname = lib.soname or lib.filename
        version, source = _native_version(lib.filename, soname)
        dep = Dependency(
            name=_stem(soname), ecosystem="native", kind="native", product=_stem(soname),
            version=version, version_source=source, version_strategy="GENERIC",
            architecture=lib.abi, artifact=lib.archive_path, bundled=True,
            identity_confidence="HIGH", version_confidence="MEDIUM" if version else "UNKNOWN",
        )
        dep.evidence.append(DependencyEvidence("bundled_so", f"bundled {lib.archive_path} soname={lib.soname}", lib.archive_path))
        for needed in lib.needed:
            dep.evidence.append(DependencyEvidence("dt_needed", f"NEEDED {needed}"))
        deps.append(dep)

        # Record NEEDED dependencies (classified system vs application).
        for needed in lib.needed:
            nkey = ("needed", needed)
            if nkey in seen:
                continue
            seen.add(nkey)
            is_system = needed in _SYSTEM_SONAMES
            ndep = Dependency(
                name=_stem(needed), ecosystem="native", kind="native", product=_stem(needed),
                architecture=lib.abi, bundled=False,
                identity_confidence="MEDIUM", version_confidence="UNKNOWN",
            )
            ndep.evidence.append(DependencyEvidence(
                "dt_needed", f"{'system/platform' if is_system else 'application'} dependency (DT_NEEDED {needed})"))
            deps.append(ndep)
    return deps


def _native_version(filename: str, soname: str) -> tuple[str | None, str | None]:
    for candidate in (soname, filename):
        m = _SONAME_VER_RE.search(candidate) or _FILE_VER_RE.search(candidate)
        if m:
            return m.group(1), "soname_suffix"
    return None, None


def _stem(soname: str) -> str:
    name = soname
    if name.startswith("lib"):
        name = name[3:]
    name = re.sub(r"\.so(\.\d+(\.\d+)*)?$", "", name)
    return name or soname

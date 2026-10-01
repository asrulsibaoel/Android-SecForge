"""Index JADX-decompiled Java sources into a searchable code model.

This is a lightweight, regex-based indexer — not a full parser. It extracts
packages, classes (with superclass/interfaces), methods, and fields, and returns
the raw sources so the code rule engine can scan them. The goal is a real,
queryable code model, not a perfect whole-program call graph.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
_CLASS_RE = re.compile(
    r"(?:^|\s)(?:public|private|protected|final|abstract|static|sealed|\s)*"
    r"(class|interface|enum)\s+([A-Za-z_]\w*)"
    r"(?:\s+extends\s+([\w.$<>,\s]+?))?"
    r"(?:\s+implements\s+([\w.$<>,\s]+?))?"
    r"\s*\{",
)
_METHOD_RE = re.compile(
    r"(?:public|private|protected|static|final|synchronized|native|abstract|\s)+"
    r"[\w.$<>\[\]]+\s+([A-Za-z_]\w*)\s*\(([^;{)]*)\)\s*(?:throws [\w.,\s]+)?\{",
)
_FIELD_RE = re.compile(
    r"^\s*(?:public|private|protected|static|final|volatile|transient|\s)+"
    r"[\w.$<>\[\]]+\s+([A-Za-z_]\w*)\s*(?:=|;)",
)
_CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch", "synchronized", "return", "new"}


@dataclass
class CodeIndex:
    entities: list[dict] = field(default_factory=list)
    sources: list[tuple[str, str]] = field(default_factory=list)
    file_count: int = 0
    class_count: int = 0
    method_count: int = 0
    field_count: int = 0


def index_sources(sources_dir: Path, max_files: int = 20000) -> CodeIndex:
    """Walk a JADX ``sources`` directory and build a :class:`CodeIndex`."""
    index = CodeIndex()
    if not sources_dir.exists():
        return index
    java_files = sorted(sources_dir.rglob("*.java"))[:max_files]
    for path in java_files:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = str(path.relative_to(sources_dir))
        index.file_count += 1
        index.sources.append((relative, content))
        _index_file(index, relative, content)
    return index


def index_source_texts(sources: list[tuple[str, str]]) -> CodeIndex:
    """Index in-memory (relative_path, content) pairs (used by tests)."""
    index = CodeIndex()
    for relative, content in sources:
        index.file_count += 1
        index.sources.append((relative, content))
        _index_file(index, relative, content)
    return index


def _index_file(index: CodeIndex, relative: str, content: str) -> None:
    package_match = _PACKAGE_RE.search(content)
    package = package_match.group(1) if package_match else None
    current_class: str | None = None

    for class_match in _CLASS_RE.finditer(content):
        current_class = class_match.group(2)
        superclass = _clean(class_match.group(3))
        interfaces = _split_types(class_match.group(4))
        index.class_count += 1
        index.entities.append(
            {
                "entity_type": "class",
                "package": package,
                "class_name": current_class,
                "name": current_class,
                "signature": None,
                "superclass": superclass,
                "interfaces": interfaces,
                "source_file": relative,
            }
        )

    for method_match in _METHOD_RE.finditer(content):
        name = method_match.group(1)
        if name in _CONTROL_KEYWORDS:
            continue
        params = _clean(method_match.group(2)) or ""
        index.method_count += 1
        index.entities.append(
            {
                "entity_type": "method",
                "package": package,
                "class_name": current_class,
                "name": name,
                "signature": f"{name}({params})",
                "superclass": None,
                "interfaces": [],
                "source_file": relative,
            }
        )

    for line in content.splitlines():
        field_match = _FIELD_RE.match(line)
        if field_match and "(" not in line:
            index.field_count += 1
            index.entities.append(
                {
                    "entity_type": "field",
                    "package": package,
                    "class_name": current_class,
                    "name": field_match.group(1),
                    "signature": line.strip()[:200],
                    "superclass": None,
                    "interfaces": [],
                    "source_file": relative,
                }
            )


def _clean(value: str | None) -> str | None:
    if not value:
        return None
    return re.sub(r"\s+", " ", value).strip() or None


def _split_types(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in re.split(r",", _clean(value) or "") if item.strip()]

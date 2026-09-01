"""Data-driven security rule engine.

Rule metadata lives in JSON files under ``definitions/`` so the catalogue is
version-controlled and testable independently of the engine. Rules consume
normalized analysis facts:

* ``manifest`` rules evaluate named predicates over a :class:`ParsedManifest`.
* ``code`` rules scan decompiled source with regular expressions and only fire
  when the required patterns co-occur, so a bare suspicious API name is not
  enough to produce a finding.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from app.analysis.manifest import ParsedManifest

_DEFINITIONS_DIR = Path(__file__).resolve().parent / "definitions"
_SECRET_MASK = re.compile(r"""(['"])(?P<secret>[^'"]{4,})\1""")


@dataclass
class Evidence:
    source: str
    location: str
    detail: str
    artifact: str | None = None
    class_name: str | None = None
    method_name: str | None = None
    line: int | None = None


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    status: str
    description: str
    remediation: str
    references: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    component: str | None = None

    def to_legacy_dict(self) -> dict:
        detail = self.evidence[0].detail if self.evidence else self.description
        return {
            "id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": detail,
        }


@dataclass
class RuleDefinition:
    id: str
    title: str
    category: str
    severity: str
    confidence: str
    type: str
    description: str
    remediation: str
    references: list[str]
    status: str
    condition: str | None = None
    patterns: list[str] = field(default_factory=list)
    require_all: bool = False
    mask: bool = False
    symbols: list[str] = field(default_factory=list)


def _mask(value: str) -> str:
    if len(value) <= 8:
        return value[0] + "***" if value else "***"
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


@lru_cache(maxsize=1)
def load_rules() -> tuple[RuleDefinition, ...]:
    rules: list[RuleDefinition] = []
    for path in sorted(_DEFINITIONS_DIR.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        for entry in raw if isinstance(raw, list) else [raw]:
            rules.append(
                RuleDefinition(
                    id=entry["id"],
                    title=entry["title"],
                    category=entry["category"],
                    severity=entry["severity"],
                    confidence=entry["confidence"],
                    type=entry["type"],
                    description=entry.get("description", ""),
                    remediation=entry.get("remediation", ""),
                    references=list(entry.get("references", [])),
                    status=entry.get("status", "POTENTIAL"),
                    condition=entry.get("condition"),
                    patterns=list(entry.get("patterns", [])),
                    require_all=bool(entry.get("require_all", False)),
                    mask=bool(entry.get("mask", False)),
                    symbols=list(entry.get("symbols", [])),
                )
            )
    return tuple(rules)


def ruleset_version() -> str:
    """Stable content hash of the loaded rule catalogue for provenance."""
    import hashlib

    digest = hashlib.sha256()
    for rule in sorted(load_rules(), key=lambda item: item.id):
        digest.update(f"{rule.id}:{rule.severity}:{rule.confidence}:{rule.status}".encode())
        digest.update("|".join(rule.patterns).encode())
        digest.update("|".join(rule.symbols).encode())
        digest.update((rule.condition or "").encode())
    return digest.hexdigest()[:16]


# ---------------------------------------------------------------------------
# Manifest predicates
# ---------------------------------------------------------------------------


def _finding(rule: RuleDefinition, evidence: list[Evidence], component: str | None = None) -> Finding:
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        category=rule.category,
        severity=rule.severity,
        confidence=rule.confidence,
        status=rule.status,
        description=rule.description,
        remediation=rule.remediation,
        references=list(rule.references),
        evidence=evidence,
        component=component,
    )


def run_manifest_rules(manifest: ParsedManifest, artifact: str = "AndroidManifest.xml") -> list[Finding]:
    if manifest.status != "parsed":
        return []
    findings: list[Finding] = []
    for rule in load_rules():
        if rule.type != "manifest":
            continue
        findings.extend(_evaluate_manifest_rule(rule, manifest, artifact))
    return findings


def _evaluate_manifest_rule(rule: RuleDefinition, manifest: ParsedManifest, artifact: str) -> list[Finding]:
    if rule.condition == "debuggable_enabled" and manifest.debuggable is True:
        return [_finding(rule, [Evidence("manifest", "application", "android:debuggable=true", artifact)])]
    if rule.condition == "allow_backup_enabled" and manifest.allow_backup is True:
        return [_finding(rule, [Evidence("manifest", "application", "android:allowBackup=true", artifact)])]
    if rule.condition == "cleartext_enabled" and manifest.uses_cleartext_traffic is True:
        return [_finding(rule, [Evidence("manifest", "application", "android:usesCleartextTraffic=true", artifact)])]
    if rule.condition == "exported_component_without_permission":
        results = []
        for component in manifest.components:
            if component.effective_exported and not component.permission:
                location = f"{component.kind} {component.name}"
                detail = f"{component.exposure} component with no android:permission guard"
                results.append(
                    _finding(
                        rule,
                        [Evidence("manifest", location, detail, artifact)],
                        component=component.name,
                    )
                )
        return results
    if rule.condition == "exported_provider" and manifest.components:
        results = []
        for component in manifest.components:
            if component.kind == "provider" and component.effective_exported and not component.permission:
                location = f"provider {component.name}"
                detail = f"exported provider authorities={component.authorities}"
                results.append(_finding(rule, [Evidence("manifest", location, detail, artifact)], component.name))
        return results
    return []


# ---------------------------------------------------------------------------
# Code scanning
# ---------------------------------------------------------------------------

_CLASS_RE = re.compile(r"\b(?:class|interface)\s+([A-Za-z_][\w$]*)")
_METHOD_RE = re.compile(r"[\w<>\[\]]+\s+([A-Za-z_][\w$]*)\s*\([^;{]*\)\s*\{")


def run_code_rules(sources: Iterable[tuple[str, str]]) -> list[Finding]:
    code_rules = [rule for rule in load_rules() if rule.type == "code"]
    if not code_rules:
        return []
    compiled = {rule.id: [re.compile(pattern) for pattern in rule.patterns] for rule in code_rules}
    findings: list[Finding] = []
    for path, content in sources:
        lines = content.splitlines()
        context = _line_context(lines)
        for rule in code_rules:
            findings.extend(_scan_file(rule, compiled[rule.id], path, lines, context))
    return findings


def _line_context(lines: list[str]) -> list[tuple[str | None, str | None]]:
    context: list[tuple[str | None, str | None]] = []
    current_class: str | None = None
    current_method: str | None = None
    for line in lines:
        class_match = _CLASS_RE.search(line)
        if class_match:
            current_class = class_match.group(1)
        method_match = _METHOD_RE.search(line)
        if method_match and method_match.group(1) not in {"if", "for", "while", "switch", "catch"}:
            current_method = method_match.group(1)
        context.append((current_class, current_method))
    return context


def _scan_file(
    rule: RuleDefinition,
    patterns: list[re.Pattern[str]],
    path: str,
    lines: list[str],
    context: list[tuple[str | None, str | None]],
) -> list[Finding]:
    matched_patterns = 0
    evidence: list[Evidence] = []
    for pattern in patterns:
        pattern_hit = False
        for index, line in enumerate(lines):
            if pattern.search(line):
                pattern_hit = True
                if len(evidence) < 5:
                    class_name, method_name = context[index]
                    detail = line.strip()
                    if rule.mask:
                        detail = _SECRET_MASK.sub(lambda m: f'"{_mask(m.group("secret"))}"', detail)
                    evidence.append(
                        Evidence(
                            source="source_code",
                            location=f"{path}:{index + 1}",
                            detail=detail[:200],
                            artifact=path,
                            class_name=class_name,
                            method_name=method_name,
                            line=index + 1,
                        )
                    )
        if pattern_hit:
            matched_patterns += 1
    if not evidence:
        return []
    if rule.require_all and matched_patterns < len(patterns):
        return []
    return [_finding(rule, evidence)]


# ---------------------------------------------------------------------------
# Native (ELF import) rules
# ---------------------------------------------------------------------------


def run_native_rules(libraries) -> list[Finding]:
    """Scan each library's imported symbols for dangerous native APIs.

    ``libraries`` items expose ``.filename``, ``.archive_path``, ``.status`` and a
    ``.functions`` list of objects with ``.name``/``.kind``/``.address``.
    """
    native_rules = [rule for rule in load_rules() if rule.type == "native"]
    if not native_rules:
        return []
    findings: list[Finding] = []
    for lib in libraries:
        if getattr(lib, "status", "COMPLETE") != "COMPLETE":
            continue
        imported = {
            func.name: func for func in getattr(lib, "functions", []) if func.kind == "imported"
        }
        if not imported:
            continue
        for rule in native_rules:
            evidence: list[Evidence] = []
            for symbol in rule.symbols:
                func = imported.get(symbol)
                if func is None:
                    continue
                evidence.append(
                    Evidence(
                        source="native",
                        location=f"{lib.filename}!{symbol}",
                        detail=f"imports {symbol} (potential unsafe API usage; indicator only)",
                        artifact=lib.archive_path,
                        method_name=symbol,
                        line=None,
                    )
                )
            if evidence:
                findings.append(_finding(rule, evidence, component=lib.filename))
    return findings

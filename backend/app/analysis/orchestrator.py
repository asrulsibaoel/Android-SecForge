"""Analysis orchestrator: the end-to-end static pipeline for one APK.

Runs stages in order, isolates per-stage failures (one analyzer failing does not
destroy unrelated stages), records status/duration/errors per stage, and persists
a relational :class:`Analysis` with manifest, permissions, components, DEX
artifacts, code entities, findings, and evidence.
"""

from __future__ import annotations

import platform
import threading
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from sqlalchemy.orm import Session

from app.analysis import attack_surface as attack_surface_engine, code_index, correlation as correlation_engine
from app.analysis import cve as cve_engine, dependencies as dep_engine
from app.analysis import ghidra as ghidra_engine, jadx as jadx_engine, reachability, risk as risk_engine, semantics
from app.analysis.dex import extract_dex, workspace_root
from app.analysis.jni import discover_jni
from app.analysis.manifest import ParsedManifest, parse_manifest
from app.analysis.native import discover_native_libraries
from app.analysis.permissions import classify_permissions
from app.core.config import settings
from app.models.analysis import (
    Analysis,
    ArtifactRecord,
    CodeEdge,
    CodeEntity,
    CodeNode,
    ComponentModel,
    DataflowSource,
    DexArtifact,
    EntryPointModel,
    EvidenceModel,
    FindingModel,
    JNIBinding,
    ManifestModel,
    NativeDependency,
    NativeFunction,
    NativeLibrary,
    PermissionModel,
    ReachabilityPath,
    SecuritySink,
)
from app.models.analysis import (
    AndroidEntryPoint,
    DeepLink,
    IntentModel,
    IpcTransaction,
    SecurityBoundary,
    SemanticEdge,
)
from app.models.cve import Dependency, DependencyEvidence
from app.models.apk import APKArtifact
from app.rules.engine import (
    Finding,
    run_code_rules,
    run_manifest_rules,
    run_native_rules,
    ruleset_version,
)
from app.services.apk_ingestion import ingest_apk
from app.services.inspection import read_manifest_bytes

# Stage statuses.
COMPLETE = "COMPLETE"
FAILED = "FAILED"
PARTIAL = "PARTIAL"
UNAVAILABLE = "UNAVAILABLE"
SKIPPED = "SKIPPED"
DEGRADED = "DEGRADED"

try:  # version for provenance; optional at runtime
    from importlib.metadata import version as _pkg_version

    _ASF_VERSION = _pkg_version("androidsecforge")
except Exception:  # pragma: no cover - metadata may be absent in some checkouts
    _ASF_VERSION = "0.0.0"


@dataclass
class StageResult:
    name: str
    status: str
    duration_seconds: float = 0.0
    detail: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "duration_seconds": self.duration_seconds,
            "detail": self.detail,
            "errors": self.errors,
        }


def analyze_apk(apk_path: Path, db: Session, profile: str = "static") -> Analysis:
    """Ingest and analyze an APK, persisting a relational Analysis record."""
    artifact = ingest_apk(apk_path, db)
    source = Path(artifact.storage_path)

    analysis = Analysis(
        apk_id=artifact.id,
        apk_sha256=artifact.sha256,
        profile=profile,
        status="PARTIAL",
        ruleset_version=ruleset_version(),
    )
    db.add(analysis)

    stages: list[StageResult] = []
    capabilities: dict[str, str] = {}

    # Record the ingested APK as an artifact of this analysis.
    analysis.artifacts.append(
        ArtifactRecord(kind="original_apk", path=artifact.storage_path, sha256=artifact.sha256, size_bytes=artifact.size_bytes)
    )
    stages.append(StageResult("ingest", COMPLETE, detail=f"sha256={artifact.sha256}"))
    _emit_progress("ingest", stages)

    parsed = _run_stage(stages, "manifest", lambda: _stage_manifest(analysis, source))
    _run_stage(stages, "permissions", lambda: _stage_permissions(analysis, parsed))
    _run_stage(stages, "components", lambda: _stage_components(analysis, parsed))
    _run_stage(stages, "dex", lambda: _stage_dex(analysis, artifact, source))

    jadx_result = _run_stage(stages, "jadx", lambda: _stage_jadx(analysis, artifact, source, capabilities))
    index = _run_stage(stages, "code_index", lambda: _stage_code_index(analysis, jadx_result, capabilities))
    _run_stage(stages, "rules", lambda: _stage_rules(analysis, parsed, index))

    native = _run_stage(stages, "native", lambda: _stage_native(analysis, artifact, source, db, capabilities))
    _run_stage(stages, "jni", lambda: _stage_jni(analysis, native, index, db))
    ghidra_result = _run_stage(stages, "ghidra", lambda: _stage_ghidra(analysis, native, artifact, db, capabilities))
    _run_stage(stages, "native_rules", lambda: _stage_native_rules(analysis, native))

    graph = _run_stage(stages, "graph", lambda: _stage_graph(analysis, parsed, index, native, capabilities))
    _run_stage(stages, "reachability", lambda: _stage_reachability(analysis, graph, capabilities))
    _run_stage(stages, "semantics", lambda: _stage_semantics(analysis, graph, capabilities))

    _run_stage(stages, "dependency_fingerprint", lambda: _stage_dependencies(analysis, index, native, artifact, capabilities))
    _run_stage(stages, "vulnerability_match", lambda: _stage_vuln_match(analysis, db, capabilities))
    _run_stage(stages, "vulnerability_reachability", lambda: _stage_vuln_reachability(analysis, graph, capabilities))

    _run_stage(stages, "correlation", lambda: _stage_correlation(analysis, db, capabilities))
    _run_stage(stages, "attack_surface", lambda: _stage_attack_surface(analysis, capabilities))
    _run_stage(stages, "risk", lambda: _stage_risk(analysis, capabilities))
    _run_stage(stages, "graph_snapshot", lambda: _stage_graph_snapshot(analysis, db, capabilities))
    _run_stage(stages, "validation", lambda: _stage_validation(analysis, db, capabilities))
    _run_stage(stages, "obfuscation", lambda: _stage_obfuscation(analysis, db, capabilities))
    _run_stage(stages, "native_deep", lambda: _stage_native_deep(analysis, db, capabilities))

    analysis.tool_versions = {
        "androidsecforge": _ASF_VERSION,
        "python": platform.python_version(),
        "jadx": jadx_result.version if jadx_result else None,
        "ghidra": ghidra_result.get("version") if ghidra_result else None,
        "ruleset": analysis.ruleset_version,
    }
    capabilities.setdefault("manifest", COMPLETE if (parsed and parsed.status == "parsed") else DEGRADED)
    capabilities.setdefault("dex_analysis", COMPLETE)
    analysis.capabilities = capabilities
    analysis.stages = [stage.to_dict() for stage in stages]
    analysis.errors = [error for stage in stages for error in stage.errors]
    analysis.status = _overall_status(stages)
    analysis.completed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(analysis)
    return analysis


# Optional, thread-local progress sink (prompt 26). When the web execution service
# sets it, `_run_stage` reports each completed stage for live progress. It defaults
# to unset (no-op), so CLI/test behavior is byte-for-byte unchanged and no call site
# needs to change. Reporting failures never affect the analysis.
_progress_local = threading.local()


def set_progress_sink(sink) -> None:
    _progress_local.sink = sink


def clear_progress_sink() -> None:
    _progress_local.sink = None


def _emit_progress(name: str, stages: list[StageResult]) -> None:
    sink = getattr(_progress_local, "sink", None)
    if sink is None:
        return
    try:
        sink(name, [s.to_dict() for s in stages])
    except Exception:  # progress reporting is operational only — never break analysis
        pass


def _run_stage(stages: list[StageResult], name: str, action: Callable):
    started = time.monotonic()
    try:
        value, status, detail = action()
        duration = round(time.monotonic() - started, 3)
        stages.append(StageResult(name, status, duration, detail))
        _emit_progress(name, stages)
        return value
    except Exception as error:  # isolate: one analyzer failing must not crash the pipeline
        duration = round(time.monotonic() - started, 3)
        stages.append(StageResult(name, FAILED, duration, "", [f"{type(error).__name__}: {error}"]))
        _emit_progress(name, stages)
        return None


def _stage_manifest(analysis: Analysis, source: Path):
    with zipfile.ZipFile(source) as archive:
        raw = read_manifest_bytes(archive)
    if raw is None:
        parsed = ParsedManifest(status="missing", source_format="none")
        analysis.manifest = _manifest_row(parsed)
        return parsed, SKIPPED, "no AndroidManifest.xml"
    parsed = parse_manifest(raw)
    analysis.manifest = _manifest_row(parsed)
    if parsed.status == "parsed":
        return parsed, COMPLETE, f"package={parsed.package} format={parsed.source_format}"
    return parsed, DEGRADED, f"manifest status={parsed.status}"


def _manifest_row(parsed: ParsedManifest) -> ManifestModel:
    return ManifestModel(
        status=parsed.status,
        source_format=parsed.source_format,
        package=parsed.package,
        version_name=parsed.version_name,
        version_code=parsed.version_code,
        min_sdk=parsed.min_sdk,
        target_sdk=parsed.target_sdk,
        compile_sdk=parsed.compile_sdk,
        debuggable=parsed.debuggable,
        allow_backup=parsed.allow_backup,
        uses_cleartext_traffic=parsed.uses_cleartext_traffic,
        network_security_config=parsed.network_security_config,
    )


def _stage_permissions(analysis: Analysis, parsed: ParsedManifest | None):
    if parsed is None or parsed.status != "parsed":
        return [], SKIPPED, "manifest unavailable"
    infos = classify_permissions(parsed.permissions)
    for info in infos:
        analysis.permissions.append(
            PermissionModel(
                name=info.name,
                protection_level=info.protection_level,
                permission_group=info.group,
                is_dangerous=info.is_dangerous,
                is_custom=info.is_custom,
            )
        )
    dangerous = sum(1 for info in infos if info.is_dangerous)
    return infos, COMPLETE, f"{len(infos)} permissions, {dangerous} dangerous"


def _stage_components(analysis: Analysis, parsed: ParsedManifest | None):
    if parsed is None or parsed.status != "parsed":
        return [], SKIPPED, "manifest unavailable"
    for component in parsed.components:
        analysis.components.append(
            ComponentModel(
                kind=component.kind,
                name=component.name,
                exported=component.exported,
                explicit_exported=component.explicit_exported,
                effective_exported=component.effective_exported,
                exposure=component.exposure,
                permission=component.permission,
                authorities=component.authorities,
                intent_filters=[
                    {
                        "actions": list(item.actions),
                        "categories": list(item.categories),
                        "data": list(item.data),
                    }
                    for item in component.intent_filters
                ],
            )
        )
    exported = sum(1 for component in parsed.components if component.effective_exported)
    return parsed.components, COMPLETE, f"{len(parsed.components)} components, {exported} externally reachable"


def _stage_dex(analysis: Analysis, artifact: APKArtifact, source: Path):
    root, records = extract_dex(source, artifact.sha256, artifact.artifact_type)
    for record in records:
        analysis.dex_artifacts.append(
            DexArtifact(
                archive_path=record["archive_path"],
                filename=record["filename"],
                sha256=record["sha256"],
                size_bytes=record["size"],
                valid=record["valid"],
                class_count=record.get("class_count"),
                method_count=record.get("method_count"),
                field_count=record.get("field_count"),
                string_count=record.get("string_count"),
                workspace_path=record.get("workspace_path"),
            )
        )
    if not records:
        return records, SKIPPED, "no DEX files"
    return records, COMPLETE, f"{len(records)} DEX file(s)"


def _stage_jadx(analysis: Analysis, artifact: APKArtifact, source: Path, capabilities: dict):
    from app.analysis.dex import workspace_root

    base = Path(artifact.workspace_path) if artifact.workspace_path else workspace_root(artifact.sha256)
    output_dir = base / "jadx"
    result = jadx_engine.run_jadx(source, output_dir)
    capabilities["jadx"] = "AVAILABLE" if result.status == jadx_engine.SUCCESS else result.status
    if result.status == jadx_engine.SUCCESS and result.output_dir:
        analysis.artifacts.append(ArtifactRecord(kind="jadx_output", path=result.output_dir))
        return result, COMPLETE, f"jadx {result.version} in {result.duration_seconds}s"
    if result.status == jadx_engine.UNAVAILABLE:
        return result, UNAVAILABLE, "jadx not installed"
    return result, FAILED, result.error or result.status


def _stage_code_index(analysis: Analysis, jadx_result, capabilities: dict):
    if jadx_result is None or jadx_result.status != jadx_engine.SUCCESS or not jadx_result.sources_dir:
        capabilities["code_analysis"] = UNAVAILABLE
        return None, SKIPPED, "no decompiled sources"
    index = code_index.index_sources(Path(jadx_result.sources_dir))
    for entity in index.entities:
        analysis.code_entities.append(CodeEntity(**entity))
    capabilities["code_analysis"] = COMPLETE
    return index, COMPLETE, f"{index.class_count} classes, {index.method_count} methods"


def _stage_rules(analysis: Analysis, parsed: ParsedManifest | None, index):
    findings: list[Finding] = []
    if parsed is not None:
        findings.extend(run_manifest_rules(parsed))
    if index is not None and index.sources:
        findings.extend(run_code_rules(index.sources))
    for finding in findings:
        analysis.findings.append(_finding_row(finding))
    counts = _severity_counts(findings)
    return findings, COMPLETE, f"{len(findings)} findings ({counts})"


def _finding_row(finding: Finding) -> FindingModel:
    row = FindingModel(
        rule_id=finding.rule_id,
        title=finding.title,
        category=finding.category,
        # Normalize casing: rules emit lowercase, reachability/semantic emit
        # uppercase — persist one consistent form so correlation/risk score cleanly.
        severity=(finding.severity or "info").lower(),
        confidence=(finding.confidence or "low").lower(),
        status=finding.status,
        description=finding.description,
        remediation=finding.remediation,
        references=list(finding.references),
        component=finding.component,
    )
    for item in finding.evidence:
        row.evidence.append(
            EvidenceModel(
                source=item.source,
                location=item.location,
                detail=item.detail,
                artifact=item.artifact,
                class_name=item.class_name,
                method_name=item.method_name,
                line=item.line,
            )
        )
    return row


@dataclass
class _NativeStageData:
    results: list
    lib_rows: dict  # archive_path -> NativeLibrary
    func_rows: dict  # (filename, name, kind) -> NativeFunction


def _stage_native(analysis: Analysis, artifact: APKArtifact, source: Path, db: Session, capabilities: dict):
    results = discover_native_libraries(source, artifact.sha256, artifact.artifact_type)
    lib_rows: dict = {}
    func_rows: dict = {}
    failed = 0
    abi_counts: dict[str, int] = {}
    for lib in results:
        abi_counts[lib.abi] = abi_counts.get(lib.abi, 0) + 1
        if lib.status != "COMPLETE":
            failed += 1
        row = NativeLibrary(
            archive_path=lib.archive_path,
            abi=lib.abi,
            filename=lib.filename,
            size_bytes=lib.size_bytes,
            sha256=lib.sha256,
            elf_class=lib.elf_class,
            architecture=lib.architecture,
            endianness=lib.endianness,
            elf_type=lib.elf_type,
            entry_point=lib.entry_point,
            soname=lib.soname,
            stripped=lib.stripped,
            symbols_available=lib.symbols_available,
            functions_truncated=lib.functions_truncated,
            status=lib.status,
            error=lib.error,
            workspace_path=lib.workspace_path,
        )
        analysis.native_libraries.append(row)
        lib_rows[lib.archive_path] = row
        for needed in lib.needed:
            row.dependencies.append(NativeDependency(needed=needed))
        for func in lib.functions:
            func_row = NativeFunction(
                name=func.name,
                address=func.address,
                symbol_type=func.symbol_type,
                binding=func.binding,
                visibility=func.visibility,
                size=func.size,
                kind=func.kind,
                is_jni=func.is_jni,
                source=func.source,
                confidence=func.confidence,
            )
            row.functions.append(func_row)
            analysis.native_functions.append(func_row)
            func_rows[(lib.filename, func.name, func.kind)] = func_row
    db.flush()  # assign IDs so JNI/Ghidra stages can link rows

    capabilities["native_analysis"] = DEGRADED if failed else COMPLETE
    data = _NativeStageData(results=results, lib_rows=lib_rows, func_rows=func_rows)
    abi_summary = ", ".join(f"{abi}:{count}" for abi, count in sorted(abi_counts.items())) or "none"
    detail = f"{len(results)} libraries [{abi_summary}]" + (f", {failed} failed" if failed else "")
    return data, COMPLETE, detail


def _stage_jni(analysis: Analysis, native: "_NativeStageData | None", index, db: Session):
    if native is None:
        return None, SKIPPED, "native discovery unavailable"
    sources = index.sources if index is not None else []
    complete_libs = [lib for lib in native.results if lib.status == "COMPLETE"]
    bindings = discover_jni(complete_libs, sources)
    high = 0
    for binding in bindings:
        if binding.confidence == "HIGH":
            high += 1
        lib_row = _find_lib_row(native, binding.library_name)
        func_row = None
        if lib_row is not None and binding.native_function:
            func_row = native.func_rows.get((lib_row.filename, binding.native_function, "exported"))
        row = JNIBinding(
            source=binding.source,
            confidence=binding.confidence,
            java_class=binding.java_class,
            java_method=binding.java_method,
            java_signature=binding.java_signature,
            library_name=binding.library_name,
            native_function=binding.native_function,
            evidence=binding.evidence,
        )
        if lib_row is not None:
            row.library_id = lib_row.id
        if func_row is not None:
            row.native_function_id = func_row.id
        analysis.jni_bindings.append(row)
    return bindings, COMPLETE, f"{len(bindings)} bindings ({high} high-confidence)"


def _find_lib_row(native: "_NativeStageData", library_name: str | None):
    if not library_name:
        return None
    for row in native.lib_rows.values():
        if row.filename == library_name:
            return row
    return None


def _stage_ghidra(analysis: Analysis, native: "_NativeStageData | None", artifact: APKArtifact, db: Session, capabilities: dict):
    if not ghidra_engine.is_available():
        capabilities["ghidra"] = UNAVAILABLE
        return {"status": UNAVAILABLE, "version": None}, UNAVAILABLE, "Ghidra not installed"
    if not settings.ghidra_enabled:
        capabilities["ghidra"] = "DISABLED"
        return {"status": "DISABLED", "version": None}, SKIPPED, "Ghidra available but disabled (set ASF_GHIDRA_ENABLED=true)"
    if native is None:
        capabilities["ghidra"] = "AVAILABLE"
        return {"status": "AVAILABLE", "version": None}, SKIPPED, "no native libraries"

    project_dir = workspace_root(artifact.sha256) / "ghidra"
    added = 0
    version = None
    analyzed = 0
    for lib in native.results:
        if lib.status != "COMPLETE" or not lib.workspace_path:
            continue
        result = ghidra_engine.analyze_library(Path(lib.workspace_path), project_dir)
        version = version or result.version
        if result.status != ghidra_engine.SUCCESS:
            continue
        analyzed += 1
        lib_row = native.lib_rows.get(lib.archive_path)
        if lib_row is None:
            continue
        for func in result.functions:
            func_row = NativeFunction(
                name=func.name,
                address=_safe_int(func.address),
                symbol_type="FUNC",
                binding="GLOBAL",
                visibility="DEFAULT",
                size=func.size,
                kind="ghidra",
                is_jni=func.name.startswith("Java_"),
                source="Ghidra",
                confidence=func.confidence,
            )
            lib_row.functions.append(func_row)
            analysis.native_functions.append(func_row)
            added += 1
    capabilities["ghidra"] = COMPLETE
    return {"status": ghidra_engine.SUCCESS, "version": version}, COMPLETE, f"Ghidra analyzed {analyzed} libraries, {added} functions"


def _safe_int(value: str) -> int:
    try:
        return int(str(value), 16) if str(value).startswith("0x") else int(value)
    except (TypeError, ValueError):
        return 0


def _stage_native_rules(analysis: Analysis, native: "_NativeStageData | None"):
    if native is None:
        return [], SKIPPED, "native discovery unavailable"
    findings = run_native_rules([lib for lib in native.results if lib.status == "COMPLETE"])
    for finding in findings:
        analysis.findings.append(_finding_row(finding))
    return findings, COMPLETE, f"{len(findings)} native findings"


def _stage_graph(analysis: Analysis, parsed, index, native: "_NativeStageData | None", capabilities: dict):
    sources = index.sources if index is not None else []
    native_results = native.results if native is not None else []
    components = []
    if parsed is not None and parsed.status == "parsed":
        components = [
            {
                "name": c.name,
                "type": c.kind,
                "effective_exported": c.effective_exported,
                "permission": c.permission,
                "intent_filters": [
                    {"actions": list(i.actions), "categories": list(i.categories), "data": list(i.data)}
                    for i in c.intent_filters
                ],
            }
            for c in parsed.components
        ]

    graph = reachability.build_code_graph(sources, native_results, analysis.jni_bindings, components)
    # Augment the SAME graph with Android execution semantics (framework dispatch,
    # deep links, provider inputs, WebView bridges, reflection, dynamic loading,
    # intents, IPC, security boundaries) so reachability traverses them too.
    semantics.augment_graph(graph, components, analysis.jni_bindings, native_results)
    _persist_semantics(analysis, graph)

    # Persist entry points / sources / sinks (always) and code nodes/edges (bounded).
    for entry in graph.entry_points:
        analysis.entry_points.append(
            EntryPointModel(
                node_key=entry["key"], component=entry["component"], kind=entry["kind"],
                exported=bool(entry["exported"]), permission=entry.get("permission"),
                intent_filters=entry.get("intent_filters", []), evidence=entry.get("evidence", ""),
            )
        )
    for src in graph.sources:
        analysis.dataflow_sources.append(
            DataflowSource(
                node_key=src["key"], source_type=src["type"], api=src["api"], class_name=src.get("class"),
                method_name=src.get("method"), line=src.get("line"), confidence=src.get("confidence", "MEDIUM"),
                evidence=src.get("evidence", ""),
            )
        )
    for sink in graph.sinks:
        analysis.security_sinks.append(
            SecuritySink(
                node_key=sink["key"], sink_type=sink["type"], api=sink["api"], category=sink.get("category", "java"),
                class_name=sink.get("class"), method_name=sink.get("method"), line=sink.get("line"),
                confidence=sink.get("confidence", "MEDIUM"), evidence=sink.get("evidence", ""),
            )
        )

    node_cap = settings.reach_max_persisted_nodes
    edge_cap = settings.reach_max_persisted_edges
    for node in list(graph.nodes.values())[:node_cap]:
        analysis.code_nodes.append(
            CodeNode(
                node_key=node.key, node_type=node.node_type, label=node.label, class_name=node.class_name,
                method_name=node.method_name, source_file=node.source_file, line=node.line, confidence=node.confidence,
            )
        )
    for edge in graph.edges[:edge_cap]:
        analysis.code_edges.append(
            CodeEdge(
                src_key=edge.src, dst_key=edge.dst, edge_type=edge.edge_type, evidence=edge.evidence,
                line=edge.line, confidence=edge.confidence,
            )
        )

    capabilities["reachability"] = COMPLETE if sources else DEGRADED
    truncated = len(graph.nodes) > node_cap or len(graph.edges) > edge_cap
    detail = f"{len(graph.nodes)} nodes, {len(graph.edges)} edges, {len(graph.entry_points)} entry points, {len(graph.sources)} sources, {len(graph.sinks)} sinks"
    if truncated:
        detail += " (persistence truncated)"
    if not sources:
        detail += " [no decompiled sources; native/manifest graph only]"
    return graph, COMPLETE, detail


def _persist_semantics(analysis: Analysis, graph) -> None:
    for entry in graph.android_entry_points:
        analysis.android_entry_points.append(AndroidEntryPoint(
            node_key=entry["node_key"], component=entry["component"], component_type=entry["component_type"],
            method=entry["method"], lifecycle_event=entry["lifecycle_event"], exported=bool(entry["exported"]),
            permission=entry.get("permission"), intent_filters=entry.get("intent_filters", []),
            evidence=entry.get("evidence", ""), confidence=entry.get("confidence", "HIGH")))
    for intent in graph.intents:
        analysis.intents.append(IntentModel(
            operation=intent["operation"], action=intent.get("action"), data_uri=intent.get("data_uri"),
            categories=intent.get("categories", []), target_component=intent.get("target_component"),
            target_package=intent.get("target_package"), class_name=intent.get("class_name"),
            method_name=intent.get("method_name"), line=intent.get("line"),
            confidence=intent.get("confidence", "MEDIUM"), evidence=intent.get("evidence", "")))
    for dl in graph.deep_links:
        analysis.deep_links.append(DeepLink(
            node_key=dl["node_key"], component=dl["component"], scheme=dl.get("scheme"), host=dl.get("host"),
            port=dl.get("port"), path=dl.get("path"), path_prefix=dl.get("path_prefix"),
            path_pattern=dl.get("path_pattern"), mime_type=dl.get("mime_type"), action=dl.get("action"),
            category=dl.get("category"), evidence=dl.get("evidence", ""), confidence=dl.get("confidence", "HIGH")))
    for txn in graph.ipc_transactions:
        analysis.ipc_transactions.append(IpcTransaction(
            kind=txn["kind"], class_name=txn.get("class_name"), method_name=txn.get("method_name"),
            interface_name=txn.get("interface_name"), transaction_code=txn.get("transaction_code"),
            confidence=txn.get("confidence", "LOW"), evidence=txn.get("evidence", "")))
    for boundary in graph.security_boundaries:
        analysis.security_boundaries.append(SecurityBoundary(
            boundary_type=boundary["boundary_type"], component=boundary.get("component"),
            node_key=boundary["node_key"], evidence=boundary.get("evidence", ""),
            confidence=boundary.get("confidence", "MEDIUM")))
    cap = settings.reach_max_persisted_edges
    for edge in graph.semantic_edges[:cap]:
        analysis.semantic_edges.append(SemanticEdge(
            src_key=edge.src, dst_key=edge.dst, edge_type=edge.edge_type, evidence=edge.evidence,
            line=edge.line, confidence=edge.confidence))


def _stage_semantics(analysis: Analysis, graph, capabilities: dict):
    if graph is None:
        return [], SKIPPED, "graph unavailable"
    findings = semantics.semantic_findings(graph, max_depth=settings.reach_max_depth)
    for finding in findings:
        analysis.findings.append(_finding_row(finding))
    capabilities["semantics"] = COMPLETE if graph.methods else DEGRADED
    counts = (
        f"{len(graph.android_entry_points)} entry points, {len(graph.deep_links)} deep links, "
        f"{len(graph.intents)} intents, {len(graph.ipc_transactions)} IPC, "
        f"{len(graph.security_boundaries)} boundaries, {len(findings)} semantic findings"
    )
    return findings, COMPLETE, counts


def _stage_dependencies(analysis: Analysis, index, native, artifact: APKArtifact, capabilities: dict):
    from pathlib import Path as _Path

    native_results = native.results if native is not None else []
    deps = dep_engine.build_dependencies(index, native_results, _Path(artifact.storage_path))
    for dep in deps:
        row = Dependency(
            name=dep.name, product=dep.product, package_prefix=dep.package_prefix, ecosystem=dep.ecosystem,
            version=dep.version, version_source=dep.version_source, version_strategy=dep.version_strategy,
            architecture=dep.architecture, artifact=dep.artifact, kind=dep.kind, bundled=dep.bundled,
            identity_confidence=dep.identity_confidence, version_confidence=dep.version_confidence, cpe=dep.cpe)
        for ev in dep.evidence:
            row.evidences.append(DependencyEvidence(source=ev.source, detail=ev.detail, location=ev.location))
        analysis.dependencies.append(row)
    capabilities["dependency_analysis"] = COMPLETE
    java = sum(1 for d in deps if d.kind == "java")
    nat = sum(1 for d in deps if d.kind == "native")
    versioned = sum(1 for d in deps if d.version)
    return deps, COMPLETE, f"{len(deps)} dependencies ({java} java, {nat} native, {versioned} versioned)"


def _stage_vuln_match(analysis: Analysis, db: Session, capabilities: dict):
    try:
        matches = cve_engine.match_analysis(db, analysis)
    except Exception as error:  # optional CVE DB / provider must not destroy analysis
        capabilities["cve_analysis"] = "FAILED"
        return [], FAILED, f"{type(error).__name__}: {error}"
    capabilities["cve_analysis"] = COMPLETE
    from collections import Counter
    states = Counter(m.version_state for m in matches)
    return matches, COMPLETE, f"{len(matches)} matches ({dict(states)})"


def _stage_vuln_reachability(analysis: Analysis, graph, capabilities: dict):
    counts = cve_engine.correlate_reachability(analysis, graph)
    findings = cve_engine.cve_findings(analysis)
    for finding in findings:
        analysis.findings.append(_finding_row(finding))
    return findings, COMPLETE, (
        f"reachable={counts.get('REACHABLE', 0)} not_reachable={counts.get('NOT_REACHABLE', 0)} "
        f"unknown={counts.get('UNKNOWN', 0)}, {len(findings)} CVE findings")


def _stage_correlation(analysis: Analysis, db: Session, capabilities: dict):
    from collections import Counter

    db.flush()  # findings created by earlier stages need persistent IDs
    duplicates = correlation_engine.deduplicate(analysis)
    links = correlation_engine.correlate(analysis)
    root_causes = correlation_engine.build_root_causes(analysis)
    db.flush()  # root causes + membership need IDs before back-linking findings
    correlation_engine.link_root_cause_findings(analysis)
    capabilities["correlation"] = COMPLETE
    categories = Counter(rc.category for rc in root_causes)
    return root_causes, COMPLETE, (
        f"{len(root_causes)} root causes {dict(categories)}, {links} correlation links, "
        f"{duplicates} duplicate finding(s) flagged")


def _stage_attack_surface(analysis: Analysis, capabilities: dict):
    from collections import Counter

    nodes = attack_surface_engine.build_attack_surface(analysis)
    capabilities["attack_surface"] = COMPLETE
    exposures = Counter(n.exposure for n in nodes)
    return nodes, COMPLETE, f"{len(nodes)} attack-surface nodes {dict(exposures)}"


def _stage_risk(analysis: Analysis, capabilities: dict):
    overall, entries = risk_engine.assess_risk(analysis)
    capabilities["risk"] = COMPLETE
    return overall, COMPLETE, (
        f"overall risk {overall.overall_score}/100 severity={overall.severity} "
        f"confidence={overall.confidence}, {len(entries)} entry-point assessment(s)")


def _stage_graph_snapshot(analysis: Analysis, db: Session, capabilities: dict):
    """Project the knowledge graph and persist a deterministic snapshot for
    reproducibility. Does not create a second graph — it summarizes the canonical
    one plus the projected entity nodes."""
    from app.analysis import knowledge_graph as kg_engine

    db.flush()  # findings/root causes need IDs for the projection
    snap = kg_engine.build_snapshot(analysis, datetime.now(timezone.utc))
    capabilities["knowledge_graph"] = COMPLETE
    return snap, COMPLETE, (
        f"{snap.node_count} nodes, {snap.edge_count} edges, digest={snap.digest[:12]}")


def _stage_validation(analysis: Analysis, db: Session, capabilities: dict):
    """Security verification & validation intelligence — a deterministic
    projection over persisted evidence. Idempotent; never changes finding
    severity/confidence/runtime_status, risk, remediation priority, or CVE state."""
    from app.analysis import validation as validation_engine

    db.flush()
    claims = validation_engine.build_validation(db, analysis)
    capabilities["validation"] = COMPLETE
    from collections import Counter
    states = Counter(c.validation_state for c in claims)
    return claims, COMPLETE, f"{len(claims)} validation claims {dict(states)}"


def _stage_obfuscation(analysis: Analysis, db: Session, capabilities: dict):
    """Obfuscation & anti-analysis intelligence — a deterministic projection over
    persisted evidence. Status-safe: JADX/native/reflection being unavailable
    yields UNKNOWN/UNAVAILABLE categories, never a failed analysis. Never mutates
    findings/CVE/risk/remediation/validation/graph."""
    from app.analysis import obfuscation as obf_engine

    db.flush()
    intel = obf_engine.build_obfuscation(db, analysis)
    capabilities["obfuscation"] = COMPLETE
    avail = obf_engine._availability(intel["stats"])
    detail = (f"{len(intel['observations'])} observations, {len(intel['anti_analysis'])} anti-analysis, "
              f"{len(intel['impacts'])} impacts, score={intel['score']['score']}")
    status = COMPLETE if any(v == "AVAILABLE" for v in avail.values()) else PARTIAL
    return intel, status, detail


def _stage_native_deep(analysis: Analysis, db: Session, capabilities: dict):
    """Deep native / Ghidra correlation. Status-safe: Ghidra absent → ELF_ONLY
    (still builds binaries/functions/JNI/API observations); never fails the
    analysis. Idempotent; never mutates findings/CVE/risk/remediation/validation."""
    from app.native.deep_native import build_deep_native

    db.flush()
    run = build_deep_native(db, analysis)
    capabilities["native_deep"] = COMPLETE if run.mode != "ELF_ONLY" else DEGRADED
    capabilities["ghidra_deep"] = run.ghidra_capability
    if not analysis.native_libraries:
        return run, UNAVAILABLE, "no native libraries"
    detail = (f"mode={run.mode} ghidra={run.ghidra_capability} binaries={run.binaries_count} "
              f"functions={run.functions_count} jni={run.jni_count} calls={run.call_edge_count} "
              f"api={run.api_observation_count} unresolved={run.unresolved_target_count}")
    status = COMPLETE if run.mode != "ELF_ONLY" else PARTIAL
    return run, status, detail


def _stage_reachability(analysis: Analysis, graph, capabilities: dict):
    if graph is None:
        return [], SKIPPED, "graph unavailable"
    paths = reachability.reachability_paths(graph, max_depth=settings.reach_max_depth)
    findings = reachability.reachability_findings(paths)
    finding_by_path: dict[tuple[str, str], object] = {}
    for finding in findings:
        # map back to the terminal node key via evidence chain end
        finding_by_path[(finding.evidence[0].class_name or finding.component, finding.evidence[-1].detail)] = finding

    for path in paths:
        rule_id = None
        # attach a rule id if this path produced a finding (matched by endpoints)
        for finding in findings:
            if finding.evidence and finding.evidence[-1].detail.endswith(path.nodes[-1].label):
                rule_id = finding.rule_id
                break
        analysis.reachability_paths.append(
            ReachabilityPath(
                rule_id=rule_id,
                from_key=path.nodes[0].key, from_label=path.nodes[0].label,
                to_key=path.nodes[-1].key, to_label=path.nodes[-1].label,
                status=path.status, confidence=path.confidence, length=len(path.nodes),
                nodes=[{"key": n.key, "type": n.node_type, "label": n.label,
                        "file": n.source_file, "line": n.line} for n in path.nodes],
                edges=[{"src": e.src, "dst": e.dst, "type": e.edge_type,
                        "evidence": e.evidence, "line": e.line, "confidence": e.confidence} for e in path.edges],
            )
        )

    for finding in findings:
        analysis.findings.append(_finding_row(finding))

    reachable = sum(1 for p in paths if p.status == "REACHABLE")
    capabilities.setdefault("reachability", COMPLETE)
    return findings, COMPLETE, f"{len(paths)} paths ({reachable} reachable), {len(findings)} reachability findings"


def _severity_counts(findings: list[Finding]) -> str:
    order = ("critical", "high", "medium", "low", "info")
    counts = {level: 0 for level in order}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return ", ".join(f"{level.upper()}={counts[level]}" for level in order if counts.get(level))


# Ghidra is a deep, optional enhancement layered on top of ELF analysis. Its
# absence must not flip an otherwise fully-analyzed APK to PARTIAL, so it is
# excluded from the overall-status calculation.
_STATUS_EXEMPT_STAGES = {"ghidra", "graph_snapshot", "validation", "obfuscation", "native_deep"}


def _overall_status(stages: list[StageResult]) -> str:
    considered = [stage for stage in stages if stage.name not in _STATUS_EXEMPT_STAGES]
    statuses = {stage.status for stage in considered}
    if FAILED in statuses:
        # A failure of any single stage yields PARTIAL unless the manifest itself
        # could not be produced at all (fundamental).
        manifest_stage = next((stage for stage in considered if stage.name == "manifest"), None)
        if manifest_stage and manifest_stage.status == FAILED:
            return "FAILED"
        return "PARTIAL"
    if statuses <= {COMPLETE}:
        return "COMPLETE"
    return "PARTIAL"

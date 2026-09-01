import argparse
import json
from pathlib import Path
from uuid import UUID

try:
    import typer
except ImportError:
    typer = None

from sqlalchemy import select

from app.analysis.orchestrator import analyze_apk
from app.db.session import SessionLocal, initialize_database
from app.models.analysis import Analysis
from app.reports.json_report import build_report
from app.services.apk_ingestion import (
    APKIngestionError,
    get_artifact,
    ingest_apk,
)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def import_apk(path: Path) -> None:
    """Import an APK artifact and persist its fingerprints."""
    initialize_database()
    with SessionLocal() as db:
        try:
            artifact = ingest_apk(path, db)
        except APKIngestionError as error:
            raise ValueError(str(error)) from error
        print(f"analysis_id={artifact.id}")
        print(f"sha256={artifact.sha256}")


def analyze(path: Path, as_json: bool = False) -> None:
    """Run the static analysis pipeline over an APK and report findings."""
    initialize_database()
    with SessionLocal() as db:
        try:
            analysis = analyze_apk(path, db)
        except APKIngestionError as error:
            raise ValueError(str(error)) from error
        if as_json:
            print(json.dumps(build_report(analysis, db), indent=2))
            return
        _print_analysis_summary(analysis)


def _print_analysis_summary(analysis: Analysis) -> None:
    manifest = analysis.manifest
    print(f"analysis_id={analysis.id}")
    print(f"apk={manifest.package if manifest and manifest.package else '(unknown package)'}")
    print(f"sha256={analysis.apk_sha256}")
    print(f"profile={analysis.profile}")
    print(f"status={analysis.status}")
    print("stages:")
    for stage in analysis.stages:
        detail = f" ({stage['detail']})" if stage.get("detail") else ""
        print(f"  {stage['name']}={stage['status']}{detail}")
    capabilities = " ".join(f"{key}={value}" for key, value in sorted(analysis.capabilities.items()))
    print(f"capabilities: {capabilities}")
    findings = sorted(
        analysis.findings,
        key=lambda item: (_SEVERITY_ORDER.get(item.severity, 9), item.rule_id),
    )
    print(f"findings={len(findings)}")
    for finding in findings:
        location = finding.evidence[0].location if finding.evidence else finding.component or ""
        print(f"  {finding.severity.upper()} [{finding.status}] {finding.rule_id}: {finding.title} @ {location}")


def _load_analysis(analysis_id: UUID):
    initialize_database()
    db = SessionLocal()
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        db.close()
        raise ValueError("Analysis not found")
    return db, analysis


def show_analysis(analysis_id: UUID, as_json: bool = False) -> None:
    """Show a stored analysis record."""
    db, analysis = _load_analysis(analysis_id)
    try:
        if as_json:
            print(json.dumps(build_report(analysis, db), indent=2))
            return
        _print_analysis_summary(analysis)
    finally:
        db.close()


def show_findings(analysis_id: UUID, as_json: bool = False) -> None:
    """List findings for an analysis."""
    db, analysis = _load_analysis(analysis_id)
    try:
        findings = sorted(
            analysis.findings,
            key=lambda item: (_SEVERITY_ORDER.get(item.severity, 9), item.rule_id),
        )
        if as_json:
            report = build_report(analysis, db)
            print(json.dumps(report["findings"], indent=2))
            return
        if not findings:
            print("No findings.")
            return
        for finding in findings:
            print(f"{finding.severity.upper()} [{finding.status}] {finding.rule_id}: {finding.title}")
            for item in finding.evidence:
                print(f"    - {item.source} {item.location}: {item.detail}")
    finally:
        db.close()


def inspect_dex(analysis_id: UUID, as_json: bool = False) -> None:
    """Show the DEX inventory recorded for an analysis."""
    db, analysis = _load_analysis(analysis_id)
    try:
        records = [
            {
                "archive_path": dex.archive_path,
                "sha256": dex.sha256,
                "valid": dex.valid,
                "class_count": dex.class_count,
                "method_count": dex.method_count,
                "field_count": dex.field_count,
                "string_count": dex.string_count,
            }
            for dex in sorted(analysis.dex_artifacts, key=lambda item: item.archive_path)
        ]
        if as_json:
            print(json.dumps(records, indent=2))
            return
        print(f"jadx={analysis.capabilities.get('jadx', 'UNAVAILABLE')}")
        print(f"dex_files={len(records)}")
        for record in records:
            print(
                f"  {record['archive_path']}: valid={record['valid']} "
                f"classes={record['class_count']} methods={record['method_count']} sha256={record['sha256']}"
            )
    finally:
        db.close()


def native_list(analysis_id: UUID, as_json: bool = False) -> None:
    """List native libraries discovered in an analysis."""
    db, analysis = _load_analysis(analysis_id)
    try:
        libs = sorted(analysis.native_libraries, key=lambda item: item.archive_path)
        rows = [
            {
                "library": lib.filename,
                "abi": lib.abi,
                "architecture": lib.architecture,
                "elf_type": lib.elf_type,
                "size_bytes": lib.size_bytes,
                "sha256": lib.sha256,
                "stripped": lib.stripped,
                "status": lib.status,
            }
            for lib in libs
        ]
        if as_json:
            print(json.dumps(rows, indent=2))
            return
        print(f"native_libraries={len(rows)}")
        for row in rows:
            print(
                f"  {row['library']:<28} {row['abi']:<12} {row['architecture'] or '-':<9} "
                f"{row['size_bytes']:>10}  {row['status']:<8} {row['sha256'][:16]}"
            )
    finally:
        db.close()


def native_inspect(analysis_id: UUID, as_json: bool = False) -> None:
    """Show ELF details and dependencies for each native library."""
    db, analysis = _load_analysis(analysis_id)
    try:
        libs = sorted(analysis.native_libraries, key=lambda item: item.archive_path)
        payload = [
            {
                "library": lib.filename,
                "abi": lib.abi,
                "elf_class": lib.elf_class,
                "architecture": lib.architecture,
                "endianness": lib.endianness,
                "elf_type": lib.elf_type,
                "entry_point": lib.entry_point,
                "soname": lib.soname,
                "stripped": lib.stripped,
                "status": lib.status,
                "error": lib.error,
                "needed": sorted(dep.needed for dep in lib.dependencies),
                "exported": sum(1 for f in lib.functions if f.kind == "exported"),
                "imported": sum(1 for f in lib.functions if f.kind == "imported"),
            }
            for lib in libs
        ]
        if as_json:
            print(json.dumps(payload, indent=2))
            return
        for lib in payload:
            print(f"{lib['library']} ({lib['abi']}) {lib['status']}")
            print(f"  {lib['elf_class']} {lib['architecture']} {lib['endianness']} {lib['elf_type']} entry={lib['entry_point']}")
            print(f"  soname={lib['soname']} stripped={lib['stripped']}")
            print(f"  exported={lib['exported']} imported={lib['imported']} needed={lib['needed']}")
            if lib["error"]:
                print(f"  error={lib['error']}")
    finally:
        db.close()


def native_functions(analysis_id: UUID, as_json: bool = False) -> None:
    """List native functions (exported/imported/JNI) for an analysis."""
    db, analysis = _load_analysis(analysis_id)
    try:
        funcs = [
            {
                "library": func.library.filename,
                "name": func.name,
                "kind": func.kind,
                "type": func.symbol_type,
                "binding": func.binding,
                "address": func.address,
                "is_jni": func.is_jni,
                "source": func.source,
            }
            for func in analysis.native_functions
        ]
        funcs.sort(key=lambda item: (item["library"], item["kind"], item["name"]))
        if as_json:
            print(json.dumps(funcs, indent=2))
            return
        print(f"native_functions={len(funcs)}")
        for func in funcs:
            jni = " [JNI]" if func["is_jni"] else ""
            print(f"  {func['library']:<24} {func['kind']:<9} {func['name']}{jni}")
    finally:
        db.close()


def native_jni(analysis_id: UUID, as_json: bool = False) -> None:
    """Show JNI bindings (Java <-> native) for an analysis."""
    db, analysis = _load_analysis(analysis_id)
    try:
        bindings = [
            {
                "source": b.source,
                "confidence": b.confidence,
                "java_class": b.java_class,
                "java_method": b.java_method,
                "library": b.library_name,
                "native_function": b.native_function,
                "evidence": b.evidence,
            }
            for b in analysis.jni_bindings
        ]
        if as_json:
            print(json.dumps(bindings, indent=2))
            return
        print(f"jni_bindings={len(bindings)}")
        for b in bindings:
            target = f"{b['java_class']}.{b['java_method']}" if b["java_class"] else (b["native_function"] or b["library"])
            print(f"  [{b['confidence']:<6}] {b['source']:<12} {target}")
            print(f"      {b['evidence']}")
    finally:
        db.close()


def _graph_from_db(analysis):
    from app.analysis.reachability import CodeGraph, Edge, Node

    graph = CodeGraph()
    for node in analysis.code_nodes:
        graph.add_node(Node(node.node_key, node.node_type, node.label, node.class_name,
                            node.method_name, node.source_file, node.line, node.confidence))
    for edge in analysis.code_edges:
        graph.add_edge(Edge(edge.src_key, edge.dst_key, edge.edge_type, edge.evidence, edge.line, edge.confidence))
    return graph


def graph_build(analysis_id: UUID, as_json: bool = False) -> None:
    """Report the code graph summary built during analysis."""
    db, analysis = _load_analysis(analysis_id)
    try:
        summary = {
            "nodes": len(analysis.code_nodes),
            "edges": len(analysis.code_edges),
            "entry_points": len(analysis.entry_points),
            "sources": len(analysis.dataflow_sources),
            "sinks": len(analysis.security_sinks),
            "reachability_paths": len(analysis.reachability_paths),
            "reachable": sum(1 for p in analysis.reachability_paths if p.status == "REACHABLE"),
            "unknown": sum(1 for p in analysis.reachability_paths if p.status == "UNKNOWN"),
        }
        if as_json:
            print(json.dumps(summary, indent=2))
            return
        for key, value in summary.items():
            print(f"{key}={value}")
    finally:
        db.close()


def graph_entrypoints(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        rows = [
            {"component": e.component, "kind": e.kind, "exported": e.exported,
             "permission": e.permission, "intent_filters": e.intent_filters}
            for e in analysis.entry_points
        ]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"entry_points={len(rows)}")
        for r in rows:
            print(f"  {r['kind']:<10} {r['component']}  exported={r['exported']} permission={r['permission']}")
    finally:
        db.close()


def graph_sources(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        rows = [
            {"api": s.api, "type": s.source_type, "class": s.class_name, "method": s.method_name,
             "line": s.line, "confidence": s.confidence}
            for s in analysis.dataflow_sources
        ]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"sources={len(rows)}")
        for r in rows:
            print(f"  {r['api']:<28} {r['class']}.{r['method']}:{r['line']}")
    finally:
        db.close()


def graph_sinks(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        rows = [
            {"api": s.api, "type": s.sink_type, "category": s.category, "class": s.class_name,
             "method": s.method_name, "line": s.line, "confidence": s.confidence}
            for s in analysis.security_sinks
        ]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"sinks={len(rows)}")
        for r in rows:
            print(f"  [{r['category']:<6}] {r['api']:<28} {r['class']}.{r['method']}:{r['line']}")
    finally:
        db.close()


def graph_paths(analysis_id: UUID, from_query: str | None = None, to_query: str | None = None,
                max_depth: int = 50, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        if from_query or to_query:
            from app.analysis.reachability import find_paths

            graph = _graph_from_db(analysis)
            froms = [k for k, n in graph.nodes.items()
                     if not from_query or _match(n, k, from_query)]
            tos = [k for k, n in graph.nodes.items()
                   if not to_query or _match(n, k, to_query)]
            results = []
            for f in froms[:50]:
                for t in tos[:50]:
                    if f == t:
                        continue
                    for p in find_paths(graph, f, t, max_depth=max_depth, limit=5):
                        results.append(p)
            payload = [_path_payload(p) for p in sorted(results, key=lambda p: len(p.nodes))[:50]]
            status = "NOT_REACHABLE" if (froms and tos and not payload) else ("UNKNOWN" if not (froms and tos) else "REACHABLE")
            if as_json:
                print(json.dumps({"status": status, "paths": payload}, indent=2)); return
            print(f"query status={status} paths={len(payload)}")
            for p in payload:
                print("  " + " -> ".join(n["label"] for n in p["nodes"]) + f"  [{p['status']}/{p['confidence']}]")
            return

        rows = [_reach_row(p) for p in sorted(analysis.reachability_paths, key=lambda p: p.length)]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"reachability_paths={len(rows)}")
        for r in rows:
            chain = " -> ".join(n["label"] for n in r["nodes"])
            rule = f" {r['rule_id']}" if r["rule_id"] else ""
            print(f"  [{r['status']}/{r['confidence']}]{rule}: {chain}")
    finally:
        db.close()


def _match(node, key, query) -> bool:
    hay = f"{node.label} {node.class_name or ''} {key}"
    return query.lower() in hay.lower()


def _path_payload(path) -> dict:
    return {
        "status": path.status, "confidence": path.confidence,
        "nodes": [{"key": n.key, "type": n.node_type, "label": n.label, "file": n.source_file, "line": n.line}
                  for n in path.nodes],
        "edges": [{"type": e.edge_type, "evidence": e.evidence, "confidence": e.confidence} for e in path.edges],
    }


def _reach_row(path) -> dict:
    return {"rule_id": path.rule_id, "status": path.status, "confidence": path.confidence,
            "length": path.length, "nodes": path.nodes, "edges": path.edges}


def semantic_entrypoints(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        rows = [
            {"component": e.component, "type": e.component_type, "method": e.method,
             "lifecycle_event": e.lifecycle_event, "exported": e.exported, "permission": e.permission,
             "confidence": e.confidence, "evidence": e.evidence}
            for e in analysis.android_entry_points
        ]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"android_entry_points={len(rows)}")
        for r in rows:
            print(f"  {r['type']:<10} {r['component']}.{r['method']} [{r['lifecycle_event']}] exported={r['exported']}")
    finally:
        db.close()


def semantic_intents(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        rows = [
            {"operation": i.operation, "action": i.action, "data_uri": i.data_uri,
             "target_component": i.target_component, "class": i.class_name, "method": i.method_name,
             "confidence": i.confidence, "evidence": i.evidence}
            for i in analysis.intents
        ]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"intents={len(rows)}")
        for r in rows:
            print(f"  {r['operation']:<22} action={r['action']} data={r['data_uri']} [{r['confidence']}]")
    finally:
        db.close()


def semantic_ipc(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        rows = [
            {"kind": t.kind, "class": t.class_name, "method": t.method_name, "interface": t.interface_name,
             "transaction_code": t.transaction_code, "confidence": t.confidence, "evidence": t.evidence}
            for t in analysis.ipc_transactions
        ]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"ipc_transactions={len(rows)}")
        for r in rows:
            print(f"  [{r['kind']:<13}] {r['class']}.{r['method']} codes={r['transaction_code']} [{r['confidence']}]")
    finally:
        db.close()


def semantic_deeplinks(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        rows = [
            {"component": d.component, "scheme": d.scheme, "host": d.host, "path": d.path,
             "path_prefix": d.path_prefix, "path_pattern": d.path_pattern, "mime_type": d.mime_type,
             "action": d.action, "confidence": d.confidence, "evidence": d.evidence}
            for d in analysis.deep_links
        ]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"deep_links={len(rows)}")
        for r in rows:
            print(f"  {r['scheme']}://{r['host'] or ''}{r['path'] or r['path_prefix'] or ''} -> {r['component']}")
    finally:
        db.close()


def semantic_boundaries(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        rows = [
            {"boundary_type": b.boundary_type, "component": b.component, "confidence": b.confidence,
             "evidence": b.evidence}
            for b in analysis.security_boundaries
        ]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"security_boundaries={len(rows)}")
        for r in rows:
            print(f"  {r['boundary_type']:<16} {r['component'] or ''} [{r['confidence']}]")
    finally:
        db.close()


def dependency_list(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        rows = [
            {"name": d.name, "ecosystem": d.ecosystem, "kind": d.kind, "version": d.version,
             "version_source": d.version_source, "version_confidence": d.version_confidence,
             "identity_confidence": d.identity_confidence, "bundled": d.bundled, "architecture": d.architecture,
             "artifact": d.artifact}
            for d in analysis.dependencies
        ]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"dependencies={len(rows)}")
        for r in rows:
            print(f"  [{r['kind']:<6}] {r['name']:<24} {r['version'] or 'UNKNOWN':<12} "
                  f"id={r['identity_confidence']} ver={r['version_confidence']} {r['ecosystem']}")
    finally:
        db.close()


def dependency_inspect(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        payload = [
            {"name": d.name, "product": d.product, "package_prefix": d.package_prefix, "ecosystem": d.ecosystem,
             "kind": d.kind, "version": d.version, "version_source": d.version_source,
             "version_confidence": d.version_confidence, "identity_confidence": d.identity_confidence,
             "bundled": d.bundled, "cpe": d.cpe, "artifact": d.artifact,
             "evidence": [{"source": e.source, "detail": e.detail, "location": e.location} for e in d.evidences]}
            for d in analysis.dependencies
        ]
        if as_json:
            print(json.dumps(payload, indent=2)); return
        for d in payload:
            print(f"{d['name']} ({d['kind']}/{d['ecosystem']}) version={d['version']} [{d['version_confidence']}]")
            for e in d["evidence"]:
                print(f"    - {e['source']}: {e['detail']}")
    finally:
        db.close()


def cve_import(path: str, provider: str | None = None) -> None:
    from app.services.cve_store import import_from_file
    initialize_database()
    with SessionLocal() as db:
        result = import_from_file(db, Path(path), provider=provider)
    print(json.dumps(result, indent=2))


def cve_import_fixtures() -> None:
    from app.services.cve_store import import_fixtures, stats
    initialize_database()
    with SessionLocal() as db:
        n = import_fixtures(db)
        print(json.dumps({"status": "COMPLETE", "imported": n, "note": "TEST_DATA", **stats(db)}, indent=2))


def cve_sync(keyword: str | None = None) -> None:
    from app.services.cve_store import sync_nvd
    initialize_database()
    with SessionLocal() as db:
        result = sync_nvd(db, keyword=keyword)
    print(json.dumps(result, indent=2))


def cve_search(args=None, as_json: bool = False) -> None:
    from app.intel.service import search

    # Backward-compatible: accepts an argparse Namespace, or a legacy (query, as_json).
    if isinstance(args, str) or args is None:
        query, provider, severity, ecosystem = args, None, None, None
        package = cpe = purl = min_cvss = None
        known_exploited = None
    else:
        query, provider, severity = args.query, args.provider, args.severity
        ecosystem, package, cpe, purl = args.ecosystem, args.package, args.cpe, args.purl
        known_exploited = True if args.known_exploited else None
        min_cvss = args.min_cvss
        as_json = args.as_json
    initialize_database()
    with SessionLocal() as db:
        rows = search(db, query=query, provider=provider, severity=severity, ecosystem=ecosystem,
                      package=package, cpe=cpe, purl=purl, known_exploited=known_exploited, min_cvss=min_cvss)
    if as_json:
        print(json.dumps(rows, indent=2)); return
    print(f"results={len(rows)}")
    for r in rows:
        tag = " [TEST_DATA]" if r["test_data"] else ""
        kev = " [KEV]" if r["known_exploited"] else ""
        print(f"  {r['cve_id']:<20} {r['severity'] or '-':<8} {r['provider']}{tag}{kev}  {r['summary'] or ''}")


def cve_show(cve_id: str, as_json: bool = False) -> None:
    from app.intel.service import show
    initialize_database()
    with SessionLocal() as db:
        data = show(db, cve_id)
        if data is None:
            raise ValueError(f"CVE not found: {cve_id}")
        if as_json:
            print(json.dumps(data, indent=2, default=str)); return
        can = data["canonical"]
        print(f"{data['cve_id']} canonical_severity={can['severity']} cvss={can['cvss_score']} "
              f"providers={data['providers']}" + (" [TEST_DATA]" if data["test_data"] else ""))
        print(f"  resolution: {can['reason']}")
        if data["disagreements"]:
            print(f"  provider disagreements: {data['disagreements']}")
        print(f"  aliases: {data['aliases']}")
        print(f"  external intelligence: KEV={data['external_intelligence']['known_exploited']} "
              f"EPSS={data['external_intelligence']['epss_score']}")
        print(f"  freshness: {data['freshness']['status']}")
        for i in data["identities"][:10]:
            print(f"  identity {i['identity_type']}={i['value']} [{i['confidence']}]")
        for s in data["signatures"][:10]:
            print(f"  signature {s['kind']} {s.get('class_name') or s.get('package') or s.get('native_symbol')}"
                  f".{s.get('method') or ''}")


def cve_providers(as_json: bool = False) -> None:
    from app.intel.service import providers
    data = providers()
    if as_json:
        print(json.dumps(data, indent=2)); return
    for p in data:
        print(f"  {p['name']:<10} import={p['import_supported']} sync={p['sync_supported']} "
              f"network={p['network']}  {p['note']}")


def cve_explain(analysis_id: UUID, match_id: UUID, as_json: bool = False) -> None:
    from app.intel.service import explain_match
    initialize_database()
    with SessionLocal() as db:
        data = explain_match(db, analysis_id, match_id)
        if data is None:
            raise ValueError("match not found for this analysis")
        if as_json:
            print(json.dumps(data, indent=2, default=str)); return
        print(f"{data['cve_id']} correlation={data['correlation_state']} version={data['version_state']} "
              f"reachability={data['reachability_state']} signature={data['signature_state']}")
        for step in data["chain"]:
            print(f"  [{step['step']:<15}] ({step['source']}/{step['confidence']}) {step['detail']}")
            print(f"        reason: {step['reason']}")
        print(f"  external intelligence: {data['external_intelligence']}")


def cve_identities(cve_id: str, as_json: bool = False) -> None:
    from app.intel.service import identities
    initialize_database()
    with SessionLocal() as db:
        data = identities(db, cve_id)
    if as_json:
        print(json.dumps(data, indent=2)); return
    print(f"identities={len(data)}")
    for i in data:
        print(f"  {i['identity_type']:<8} {i['value']} [{i['confidence']}] {i['ecosystem'] or ''}")


def cve_signatures(cve_id: str, as_json: bool = False) -> None:
    from app.intel.service import signatures
    initialize_database()
    with SessionLocal() as db:
        data = signatures(db, cve_id)
    if as_json:
        print(json.dumps(data, indent=2)); return
    print(f"signatures={len(data)}")
    for s in data:
        print(f"  {s['kind']:<14} {s.get('class_name') or s.get('package') or s.get('native_symbol') or ''}"
              f".{s.get('method') or ''} [{s['confidence']}] provider={s['provider']}")


def cve_freshness(as_json: bool = False) -> None:
    from app.intel.service import db_freshness
    initialize_database()
    with SessionLocal() as db:
        data = db_freshness(db)
    if as_json:
        print(json.dumps(data, indent=2)); return
    print(f"freshness={data['status']} total={data['total']} current={data['current']} "
          f"stale={data['stale']} unknown={data['unknown']} (stale_days={data['stale_days']})")
    print(f"  {data['note']}")


def cve_bundle(args) -> None:
    from datetime import datetime, timezone
    from app.intel import bundle as B
    sub = args.bundle_command
    if sub == "create" or sub == "export":
        initialize_database()
        with SessionLocal() as db:
            result = B.create_bundle(db, args.path, name=getattr(args, "name", "asf-intel"),
                                     include_test=True, now=datetime.now(timezone.utc))
        print(json.dumps(result, indent=2, default=str) if args.as_json else
              f"bundle {result['status']} at {result['path']} "
              f"vulns={result['vulnerabilities']} checksum={result['checksum'][:16]}")
    elif sub == "validate":
        result = B.validate_bundle(args.path)
        print(json.dumps({k: v for k, v in result.items() if k != "manifest"}, indent=2, default=str)
              if args.as_json else f"validation={result['status']} errors={result['errors']}")
    elif sub == "import":
        initialize_database()
        with SessionLocal() as db:
            result = B.import_bundle(db, args.path, now=datetime.now(timezone.utc))
        print(json.dumps(result, indent=2, default=str) if args.as_json else
              f"import={result['status']} imported={result['imported']} errors={result.get('errors', [])}")


def cve_analyze(analysis_id: UUID, as_json: bool = False) -> None:
    """(Re-)correlate an analysis against the current local CVE DB (offline)."""
    from app.analysis.cve import correlate_reachability, cve_findings, match_analysis
    from app.analysis.orchestrator import _finding_row

    db, analysis = _load_analysis(analysis_id)
    try:
        for match in list(analysis.vulnerability_matches):
            db.delete(match)
        for finding in [f for f in analysis.findings if f.category == "cve"]:
            db.delete(finding)
        db.flush()
        match_analysis(db, analysis)
        graph = _graph_from_db(analysis)
        counts = correlate_reachability(analysis, graph)
        findings = cve_findings(analysis)
        for finding in findings:
            analysis.findings.append(_finding_row(finding))
        db.flush()
        _recompute_unified(db, analysis)  # CVE findings changed -> refresh correlation/risk
        report = {
            "dependencies": len(analysis.dependencies),
            "matches": len(analysis.vulnerability_matches),
            "states": _match_state_counts(analysis),
            "reachability": counts,
            "findings": [{"rule_id": f.rule_id, "cve": f.title, "severity": f.severity} for f in findings],
        }
        if as_json:
            print(json.dumps(report, indent=2)); return
        print(f"dependencies={report['dependencies']} matches={report['matches']}")
        print(f"states={report['states']}")
        print(f"reachability={report['reachability']}")
        for m in analysis.vulnerability_matches:
            print(f"  {m.cve_id} {m.dependency.name} {m.version_state}/{m.correlation_state}/{m.reachability_state} "
                  f"[{m.match_method} sev={m.severity}]")
    finally:
        db.close()


def _match_state_counts(analysis) -> dict:
    from collections import Counter
    return dict(Counter(m.correlation_state for m in analysis.vulnerability_matches))


def _recompute_unified(db, analysis) -> None:
    """Rebuild correlation / root causes / attack surface / risk from current
    persisted findings (used after offline CVE re-correlation)."""
    from app.analysis import attack_surface as AS, correlation as C, risk as RK

    for collection in (analysis.finding_correlations, analysis.root_causes,
                       analysis.attack_surface_nodes, analysis.attack_surface_edges,
                       analysis.risk_assessments):
        for row in list(collection):
            db.delete(row)
    for finding in analysis.findings:
        finding.root_cause_id = None
    db.flush()
    C.deduplicate(analysis)
    C.correlate(analysis)
    C.build_root_causes(analysis)
    db.flush()
    C.link_root_cause_findings(analysis)
    AS.build_attack_surface(analysis)
    RK.assess_risk(analysis)
    db.commit()


def findings_list(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        rows = [
            {"id": str(f.id), "rule_id": f.rule_id, "category": f.category, "severity": f.severity,
             "confidence": f.confidence, "status": f.status, "component": f.component,
             "is_duplicate": f.is_duplicate, "root_cause": str(f.root_cause_id) if f.root_cause_id else None}
            for f in analysis.findings
        ]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"findings={len(rows)}")
        for r in rows:
            dup = " [dup]" if r["is_duplicate"] else ""
            print(f"  {r['severity'].upper():<8} {r['confidence']:<8} [{r['status']}] {r['rule_id']} {r['component'] or ''}{dup}")
    finally:
        db.close()


def findings_show(finding_id: UUID, as_json: bool = False) -> None:
    from app.models.analysis import FindingModel
    from app.analysis.correlation import fingerprint_finding
    initialize_database()
    db = SessionLocal()
    try:
        finding = db.get(FindingModel, finding_id)
        if finding is None:
            raise ValueError("Finding not found")
        data = {
            "id": str(finding.id), "rule_id": finding.rule_id, "category": finding.category,
            "severity": finding.severity, "confidence": finding.confidence, "status": finding.status,
            "component": finding.component, "description": finding.description, "remediation": finding.remediation,
            "references": finding.references, "fingerprint": finding.fingerprint or fingerprint_finding(finding),
            "is_duplicate": finding.is_duplicate, "root_cause": str(finding.root_cause_id) if finding.root_cause_id else None,
            "provenance": [{"source": e.source, "location": e.location, "detail": e.detail} for e in finding.evidence],
        }
        if as_json:
            print(json.dumps(data, indent=2)); return
        print(f"{finding.rule_id} {finding.severity}/{finding.confidence} [{finding.status}] {finding.component or ''}")
        print(f"  {finding.description}")
        print("  provenance chain:")
        for e in finding.evidence:
            print(f"    - {e.source} {e.location or ''}: {e.detail}")
    finally:
        db.close()


def findings_correlate(analysis_id: UUID, as_json: bool = False) -> None:
    from app.analysis.correlation import correlation_groups
    db, analysis = _load_analysis(analysis_id)
    try:
        groups = correlation_groups(analysis)
        if as_json:
            print(json.dumps(groups, indent=2)); return
        print(f"correlation_groups={len(groups)}")
        for key, ids in groups.items():
            print(f"  {key}: {len(ids)} findings")
    finally:
        db.close()


def findings_paths(analysis_id: UUID, as_json: bool = False) -> None:
    from app.analysis.correlation import summarize_path
    db, analysis = _load_analysis(analysis_id)
    try:
        paths = [summarize_path(p) for p in sorted(analysis.reachability_paths, key=lambda p: p.length)]
        if as_json:
            print(json.dumps(paths, indent=2)); return
        print(f"paths={len(paths)}")
        for p in paths:
            note = f" ({p['note']})" if p.get("note") else ""
            print(f"  [{p['status']}/{p['confidence']}] " + " -> ".join(p["chain"]) + note)
    finally:
        db.close()


def risk_summary(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        overall = next((r for r in analysis.risk_assessments if r.scope == "overall"), None)
        if overall is None:
            raise ValueError("No risk assessment (re-run analysis)")
        data = {"overall_score": overall.overall_score, "severity": overall.severity,
                "confidence": overall.confidence, "summary": overall.summary,
                "root_causes": len(analysis.root_causes),
                "attack_surface_nodes": len(analysis.attack_surface_nodes)}
        if as_json:
            print(json.dumps(data, indent=2)); return
        print(f"overall_risk={data['overall_score']}/100 severity={data['severity']} confidence={data['confidence']}")
        print(f"root_causes={data['root_causes']} attack_surface_nodes={data['attack_surface_nodes']}")
    finally:
        db.close()


def risk_entrypoints(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        entries = sorted((r for r in analysis.risk_assessments if r.scope != "overall"),
                         key=lambda r: -r.overall_score)
        rows = [{"scope": r.scope, "component": (r.summary or {}).get("component"),
                 "exposure": (r.summary or {}).get("exposure"), "score": r.overall_score, "severity": r.severity}
                for r in entries]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"entry_points={len(rows)}")
        for r in rows:
            print(f"  {r['score']:>3}/{r['severity']:<8} {r['component'] or r['scope']} ({r['exposure']})")
    finally:
        db.close()


def risk_explain(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        overall = next((r for r in analysis.risk_assessments if r.scope == "overall"), None)
        if overall is None:
            raise ValueError("No risk assessment (re-run analysis)")
        factors = [{"name": f.name, "weight": f.weight, "direction": f.direction, "evidence": f.evidence}
                   for f in overall.factors]
        if as_json:
            print(json.dumps({"score": overall.overall_score, "severity": overall.severity,
                              "confidence": overall.confidence, "factors": factors}, indent=2)); return
        print(f"Risk score: {overall.overall_score}  severity={overall.severity} confidence={overall.confidence}")
        print("Factors:")
        for f in factors:
            if f["direction"] == "positive":
                print(f"  +{f['weight']:<3} {f['name']}: {f['evidence']}")
        print("Mitigations:")
        for f in factors:
            if f["direction"] == "negative":
                print(f"  -{f['weight']:<3} {f['name']}: {f['evidence']}")
    finally:
        db.close()


def attack_surface_list(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        rows = [{"node_key": n.node_key, "type": n.node_type, "name": n.name, "exposure": n.exposure,
                 "component": n.component, "permission": n.permission, "risk_score": n.risk_score}
                for n in sorted(analysis.attack_surface_nodes, key=lambda n: -n.risk_score)]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"attack_surface_nodes={len(rows)}")
        for r in rows:
            print(f"  {r['risk_score']:>3} {r['type']:<20} {r['exposure']:<20} {r['name']}")
    finally:
        db.close()


def attack_surface_show(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        payload = [{"node_key": n.node_key, "type": n.node_type, "name": n.name, "exposure": n.exposure,
                    "component": n.component, "permission": n.permission, "risk_score": n.risk_score,
                    "evidence": n.evidence} for n in analysis.attack_surface_nodes]
        if as_json:
            print(json.dumps(payload, indent=2)); return
        for n in payload:
            print(f"{n['type']} {n['name']} exposure={n['exposure']} risk={n['risk_score']}")
            print(f"    evidence: {n['evidence']}")
    finally:
        db.close()


def attack_surface_paths(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        rows = [{"source": e.src_key, "target": e.dst_key, "type": e.edge_type,
                 "evidence": e.evidence, "confidence": e.confidence} for e in analysis.attack_surface_edges]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"attack_surface_edges={len(rows)}")
        for r in rows:
            print(f"  {r['type']:<10} {r['source']} -> {r['target']}")
    finally:
        db.close()


def root_causes_list(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        rows = [{"identifier": rc.identifier, "category": rc.category, "title": rc.title,
                 "severity": rc.severity, "confidence": rc.confidence, "findings": len(rc.findings),
                 "components": rc.affected_components} for rc in analysis.root_causes]
        if as_json:
            print(json.dumps(rows, indent=2)); return
        print(f"root_causes={len(rows)}")
        for r in rows:
            print(f"  {r['severity'].upper():<8} {r['category']:<28} {r['findings']} findings {r['components']}")
    finally:
        db.close()


def root_causes_show(analysis_id: UUID, as_json: bool = False) -> None:
    db, analysis = _load_analysis(analysis_id)
    try:
        payload = [{"identifier": rc.identifier, "category": rc.category, "title": rc.title,
                    "description": rc.description, "severity": rc.severity, "confidence": rc.confidence,
                    "affected_components": rc.affected_components, "affected_dependencies": rc.affected_dependencies,
                    "boundaries": rc.boundaries, "paths": rc.paths,
                    "findings": [{"finding_id": str(rcf.finding_id), "rule_id": rcf.rule_id} for rcf in rc.findings],
                    "evidence": [{"kind": e.kind, "detail": e.detail} for e in rc.evidence]}
                   for rc in analysis.root_causes]
        if as_json:
            print(json.dumps(payload, indent=2)); return
        for rc in payload:
            print(f"{rc['identifier']} [{rc['severity']}/{rc['confidence']}] {rc['title']}")
            print(f"    {rc['description']}")
            for e in rc["evidence"]:
                print(f"    - {e['kind']}: {e['detail']}")
    finally:
        db.close()


def graph_export(analysis_id: UUID, fmt: str = "json") -> None:
    from app.reports.graph_export import export_graph
    db, analysis = _load_analysis(analysis_id)
    try:
        print(export_graph(analysis, fmt))
    finally:
        db.close()


def kg_export(analysis_id: UUID, fmt: str = "json") -> None:
    """Export the projected knowledge graph (nodes + edges + provenance)."""
    from app.reports.investigation_report import graph_dot, graph_graphml, graph_json
    db, analysis = _load_analysis(analysis_id)
    try:
        print({"json": graph_json, "dot": graph_dot, "graphml": graph_graphml}[fmt](analysis))
    finally:
        db.close()


def show_artifact(artifact_id: UUID) -> None:
    """Show a stored APK artifact."""
    with SessionLocal() as db:
        artifact = get_artifact(artifact_id, db)
        if artifact is None:
            raise ValueError("APK artifact not found")
        print(f"{artifact.id} {artifact.original_filename} {artifact.sha256}")


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Start the AndroidSecForge FastAPI web service."""
    import uvicorn

    uvicorn.run("app.main:app", host=host, port=port)


def doctor(as_json: bool = False) -> None:
    """Report detected external tools and their capabilities."""
    from app.services.doctor import doctor_report

    report = doctor_report()
    if as_json:
        print(json.dumps(report, indent=2))
        return
    print(f"platform: {report['platform']}")
    for tool in report["tools"]:
        flag = "required" if tool["required"] else "optional"
        version = f" {tool['version']}" if tool.get("version") else ""
        path = tool["path"] or "-"
        capability = tool.get("capability", "UNAVAILABLE")
        print(f"  {tool['name']:<12} {tool['status']:<22} {capability:<12} ({flag}){version}  {path}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="androidsecforge")
    commands = parser.add_subparsers(dest="command", required=True)

    apk = commands.add_parser("apk", help="APK artifact operations")
    apk_commands = apk.add_subparsers(dest="apk_command", required=True)
    importer = apk_commands.add_parser("import")
    importer.add_argument("path", type=Path)

    analyzer = commands.add_parser("analyze", help="Run the static analysis pipeline")
    analyzer.add_argument("path", type=Path)
    analyzer.add_argument("--json", action="store_true", dest="as_json")

    analysis_cli = commands.add_parser("analysis", help="Inspect stored analyses")
    analysis_commands = analysis_cli.add_subparsers(dest="analysis_command", required=True)
    analysis_show = analysis_commands.add_parser("show")
    analysis_show.add_argument("analysis_id", type=UUID)
    analysis_show.add_argument("--json", action="store_true", dest="as_json")

    dex = commands.add_parser("dex", help="DEX inventory for an analysis")
    dex_commands = dex.add_subparsers(dest="dex_command", required=True)
    dex_inspector = dex_commands.add_parser("inspect")
    dex_inspector.add_argument("analysis_id", type=UUID)
    dex_inspector.add_argument("--json", action="store_true", dest="as_json")

    native = commands.add_parser("native", help="Native ELF / JNI analysis for an analysis")
    native_commands = native.add_subparsers(dest="native_command", required=True)
    for name in ("list", "inspect", "functions", "jni"):
        sub = native_commands.add_parser(name)
        sub.add_argument("analysis_id", type=UUID)
        sub.add_argument("--json", action="store_true", dest="as_json")

    graph = commands.add_parser("graph", help="Dataflow / reachability graph for an analysis")
    graph_commands = graph.add_subparsers(dest="graph_command", required=True)
    for name in ("build", "entrypoints", "sources", "sinks"):
        sub = graph_commands.add_parser(name)
        sub.add_argument("analysis_id", type=UUID)
        sub.add_argument("--json", action="store_true", dest="as_json")
    paths_cmd = graph_commands.add_parser("paths")
    paths_cmd.add_argument("analysis_id", type=UUID)
    paths_cmd.add_argument("--from", dest="from_query", default=None)
    paths_cmd.add_argument("--to", dest="to_query", default=None)
    paths_cmd.add_argument("--max-depth", dest="max_depth", type=int, default=50)
    paths_cmd.add_argument("--json", action="store_true", dest="as_json")
    export_cmd = graph_commands.add_parser("export")
    export_cmd.add_argument("analysis_id", type=UUID)
    export_cmd.add_argument("--format", dest="fmt", default="json", choices=["json", "graphml", "dot"])
    # Knowledge-graph queries + snapshots (prompt 14). `graph query NAME --analysis ID`.
    query_cmd = graph_commands.add_parser("query", help="Run a deterministic named graph query")
    query_cmd.add_argument("query_name")
    query_cmd.add_argument("--analysis", dest="analysis_id", type=UUID, required=True)
    query_cmd.add_argument("--min-confidence", dest="min_confidence", default=None)
    query_cmd.add_argument("--max-depth", dest="max_depth", type=int, default=None)
    query_cmd.add_argument("--component", dest="component", default=None)
    query_cmd.add_argument("--json", action="store_true", dest="as_json")
    queries_cmd = graph_commands.add_parser("queries", help="List available graph queries")
    queries_cmd.add_argument("--json", action="store_true", dest="as_json")
    kg_cmd = graph_commands.add_parser("kg", help="Export the projected knowledge graph")
    kg_cmd.add_argument("analysis_id", type=UUID)
    kg_cmd.add_argument("--format", dest="fmt", default="json", choices=["json", "graphml", "dot"])
    snap_cmd = graph_commands.add_parser("snapshot", help="Deterministic knowledge-graph snapshot")
    snap_cmd.add_argument("analysis_id", type=UUID)
    snap_cmd.add_argument("--json", action="store_true", dest="as_json")

    findings_cmd = commands.add_parser("findings", help="Findings, correlation, paths")
    findings_sub = findings_cmd.add_subparsers(dest="findings_command", required=True)
    fl = findings_sub.add_parser("list"); fl.add_argument("analysis_id", type=UUID); fl.add_argument("--json", action="store_true", dest="as_json")
    fs = findings_sub.add_parser("show"); fs.add_argument("finding_id", type=UUID); fs.add_argument("--json", action="store_true", dest="as_json")
    fc = findings_sub.add_parser("correlate"); fc.add_argument("analysis_id", type=UUID); fc.add_argument("--json", action="store_true", dest="as_json")
    fp = findings_sub.add_parser("paths"); fp.add_argument("analysis_id", type=UUID); fp.add_argument("--json", action="store_true", dest="as_json")

    risk_cmd = commands.add_parser("risk", help="Attack-surface risk")
    risk_sub = risk_cmd.add_subparsers(dest="risk_command", required=True)
    for name in ("summary", "entrypoints", "explain"):
        sub = risk_sub.add_parser(name); sub.add_argument("analysis_id", type=UUID); sub.add_argument("--json", action="store_true", dest="as_json")

    surface_cmd = commands.add_parser("attack-surface", help="Attack surface model")
    surface_sub = surface_cmd.add_subparsers(dest="surface_command", required=True)
    for name in ("list", "show", "paths"):
        sub = surface_sub.add_parser(name); sub.add_argument("analysis_id", type=UUID); sub.add_argument("--json", action="store_true", dest="as_json")

    rc_cmd = commands.add_parser("root-causes", help="Root causes")
    rc_sub = rc_cmd.add_subparsers(dest="rc_command", required=True)
    for name in ("list", "show"):
        sub = rc_sub.add_parser(name); sub.add_argument("analysis_id", type=UUID); sub.add_argument("--json", action="store_true", dest="as_json")

    from app.runtime.cli import add_parser as _add_runtime_parser
    _add_runtime_parser(commands)

    from app.analysis.investigation_cli import add_parser as _add_investigation_parser
    _add_investigation_parser(commands)

    from app.analysis.diff_cli import add_parser as _add_diff_parser
    _add_diff_parser(commands)

    from app.analysis.remediation_cli import add_parser as _add_remediation_parser
    _add_remediation_parser(commands)

    from app.analysis.validation_cli import add_parser as _add_validation_parser
    _add_validation_parser(commands)

    from app.analysis.obfuscation_cli import add_parser as _add_obfuscation_parser
    _add_obfuscation_parser(commands)

    from app.native.cli import add_parser as _add_native_deep_parser
    _add_native_deep_parser(commands)

    from app.assessment.cli import add_parser as _add_assessment_parser
    _add_assessment_parser(commands)

    semantic = commands.add_parser("semantic", help="Android semantic analysis for an analysis")
    semantic_commands = semantic.add_subparsers(dest="semantic_command", required=True)
    for name in ("entrypoints", "intents", "ipc", "deeplinks", "boundaries"):
        sub = semantic_commands.add_parser(name)
        sub.add_argument("analysis_id", type=UUID)
        sub.add_argument("--json", action="store_true", dest="as_json")

    dependency = commands.add_parser("dependency", help="Dependency inventory for an analysis")
    dependency_commands = dependency.add_subparsers(dest="dependency_command", required=True)
    for name in ("list", "inspect"):
        sub = dependency_commands.add_parser(name)
        sub.add_argument("analysis_id", type=UUID)
        sub.add_argument("--json", action="store_true", dest="as_json")

    cve = commands.add_parser("cve", help="Vulnerability intelligence (multi-provider, offline-first)")
    cve_commands = cve.add_subparsers(dest="cve_command", required=True)
    cve_import_cmd = cve_commands.add_parser("import")
    cve_import_cmd.add_argument("path")
    cve_import_cmd.add_argument("--provider", default=None, help="nvd|osv|ghsa (auto-detected if omitted)")
    cve_commands.add_parser("import-fixtures")
    cve_sync_cmd = cve_commands.add_parser("sync")
    cve_sync_cmd.add_argument("--keyword", default=None)
    cve_sync_cmd.add_argument("--provider", default="nvd")
    cve_search_cmd = cve_commands.add_parser("search")
    cve_search_cmd.add_argument("query", nargs="?", default=None)
    cve_search_cmd.add_argument("--provider", default=None)
    cve_search_cmd.add_argument("--severity", default=None)
    cve_search_cmd.add_argument("--ecosystem", default=None)
    cve_search_cmd.add_argument("--package", default=None)
    cve_search_cmd.add_argument("--cpe", default=None)
    cve_search_cmd.add_argument("--purl", default=None)
    cve_search_cmd.add_argument("--known-exploited", dest="known_exploited", action="store_true")
    cve_search_cmd.add_argument("--min-cvss", dest="min_cvss", type=float, default=None)
    cve_search_cmd.add_argument("--json", action="store_true", dest="as_json")
    cve_show_cmd = cve_commands.add_parser("show")
    cve_show_cmd.add_argument("cve_id")
    cve_show_cmd.add_argument("--json", action="store_true", dest="as_json")
    cve_analyze_cmd = cve_commands.add_parser("analyze")
    cve_analyze_cmd.add_argument("analysis_id", type=UUID)
    cve_analyze_cmd.add_argument("--json", action="store_true", dest="as_json")
    cve_commands.add_parser("providers").add_argument("--json", action="store_true", dest="as_json")
    cve_commands.add_parser("freshness").add_argument("--json", action="store_true", dest="as_json")
    cve_explain_cmd = cve_commands.add_parser("explain")
    cve_explain_cmd.add_argument("analysis_id", type=UUID)
    cve_explain_cmd.add_argument("match_id", type=UUID)
    cve_explain_cmd.add_argument("--json", action="store_true", dest="as_json")
    cve_ident_cmd = cve_commands.add_parser("identities"); cve_ident_cmd.add_argument("cve_id")
    cve_ident_cmd.add_argument("--json", action="store_true", dest="as_json")
    cve_sig_cmd = cve_commands.add_parser("signatures"); cve_sig_cmd.add_argument("cve_id")
    cve_sig_cmd.add_argument("--json", action="store_true", dest="as_json")
    cve_bundle_cmd = cve_commands.add_parser("bundle")
    bundle_sub = cve_bundle_cmd.add_subparsers(dest="bundle_command", required=True)
    for bname in ("create", "validate", "import", "export"):
        bp = bundle_sub.add_parser(bname)
        bp.add_argument("path")
        bp.add_argument("--name", default="asf-intel")
        bp.add_argument("--json", action="store_true", dest="as_json")

    viewer = commands.add_parser("show", help="Show a stored APK artifact")
    viewer.add_argument("artifact_id", type=UUID)

    server = commands.add_parser("serve", help="Start the web service")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", default=8000, type=int)

    doctor_cli = commands.add_parser("doctor", help="Report external tool capabilities")
    doctor_cli.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        if args.command == "apk":
            import_apk(args.path)
        elif args.command == "analyze":
            analyze(args.path, args.as_json)
        elif args.command == "analysis":
            show_analysis(args.analysis_id, args.as_json)
        elif args.command == "dex":
            inspect_dex(args.analysis_id, args.as_json)
        elif args.command == "native":
            {
                "list": native_list,
                "inspect": native_inspect,
                "functions": native_functions,
                "jni": native_jni,
            }[args.native_command](args.analysis_id, args.as_json)
        elif args.command == "graph":
            if args.graph_command == "paths":
                graph_paths(args.analysis_id, args.from_query, args.to_query, args.max_depth, args.as_json)
            elif args.graph_command == "export":
                graph_export(args.analysis_id, args.fmt)
            elif args.graph_command == "query":
                from app.analysis.investigation_cli import graph_query
                graph_query(args)
            elif args.graph_command == "queries":
                from app.analysis.investigation_cli import graph_queries_list
                graph_queries_list(args)
            elif args.graph_command == "kg":
                kg_export(args.analysis_id, args.fmt)
            elif args.graph_command == "snapshot":
                from app.analysis.investigation_cli import _snapshot
                _snapshot(args)
            else:
                {
                    "build": graph_build,
                    "entrypoints": graph_entrypoints,
                    "sources": graph_sources,
                    "sinks": graph_sinks,
                }[args.graph_command](args.analysis_id, args.as_json)
        elif args.command == "findings":
            if args.findings_command == "show":
                findings_show(args.finding_id, args.as_json)
            else:
                {"list": findings_list, "correlate": findings_correlate, "paths": findings_paths}[
                    args.findings_command](args.analysis_id, args.as_json)
        elif args.command == "risk":
            {"summary": risk_summary, "entrypoints": risk_entrypoints, "explain": risk_explain}[
                args.risk_command](args.analysis_id, args.as_json)
        elif args.command == "attack-surface":
            {"list": attack_surface_list, "show": attack_surface_show, "paths": attack_surface_paths}[
                args.surface_command](args.analysis_id, args.as_json)
        elif args.command == "root-causes":
            {"list": root_causes_list, "show": root_causes_show}[args.rc_command](args.analysis_id, args.as_json)
        elif args.command == "runtime":
            from app.runtime.cli import dispatch as _runtime_dispatch
            _runtime_dispatch(args)
        elif args.command == "investigate":
            from app.analysis.investigation_cli import dispatch as _investigation_dispatch
            _investigation_dispatch(args)
        elif args.command == "diff":
            from app.analysis.diff_cli import dispatch as _diff_dispatch
            _diff_dispatch(args)
        elif args.command == "remediation":
            from app.analysis.remediation_cli import dispatch as _remediation_dispatch
            _remediation_dispatch(args)
        elif args.command == "validation":
            from app.analysis.validation_cli import dispatch as _validation_dispatch
            _validation_dispatch(args)
        elif args.command == "obfuscation":
            from app.analysis.obfuscation_cli import dispatch as _obfuscation_dispatch
            _obfuscation_dispatch(args)
        elif args.command == "native-deep":
            from app.native.cli import dispatch as _native_deep_dispatch
            _native_deep_dispatch(args)
        elif args.command == "assess":
            from app.assessment.cli import dispatch as _assessment_dispatch
            _assessment_dispatch(args)
        elif args.command == "semantic":
            {
                "entrypoints": semantic_entrypoints,
                "intents": semantic_intents,
                "ipc": semantic_ipc,
                "deeplinks": semantic_deeplinks,
                "boundaries": semantic_boundaries,
            }[args.semantic_command](args.analysis_id, args.as_json)
        elif args.command == "dependency":
            {"list": dependency_list, "inspect": dependency_inspect}[args.dependency_command](
                args.analysis_id, args.as_json)
        elif args.command == "cve":
            if args.cve_command == "import":
                cve_import(args.path, getattr(args, "provider", None))
            elif args.cve_command == "import-fixtures":
                cve_import_fixtures()
            elif args.cve_command == "sync":
                cve_sync(args.keyword)
            elif args.cve_command == "search":
                cve_search(args)
            elif args.cve_command == "show":
                cve_show(args.cve_id, args.as_json)
            elif args.cve_command == "providers":
                cve_providers(args.as_json)
            elif args.cve_command == "freshness":
                cve_freshness(args.as_json)
            elif args.cve_command == "explain":
                cve_explain(args.analysis_id, args.match_id, args.as_json)
            elif args.cve_command == "identities":
                cve_identities(args.cve_id, args.as_json)
            elif args.cve_command == "signatures":
                cve_signatures(args.cve_id, args.as_json)
            elif args.cve_command == "bundle":
                cve_bundle(args)
            else:
                cve_analyze(args.analysis_id, args.as_json)
        elif args.command == "serve":
            serve(args.host, args.port)
        elif args.command == "doctor":
            doctor(args.as_json)
        else:
            show_artifact(args.artifact_id)
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()

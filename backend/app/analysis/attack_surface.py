"""Attack-surface model.

Builds a structured attack surface from existing manifest/semantic/native
evidence and classifies exposure deterministically (never guessed). Nodes and
edges are persisted; per-node risk is filled in by the risk engine.
"""

from __future__ import annotations

PUBLIC, PERMISSION_PROTECTED, INTERNAL, UNKNOWN = "PUBLIC", "PERMISSION_PROTECTED", "INTERNAL", "UNKNOWN"

_COMPONENT_NODE_TYPE = {
    "activity": "EXPORTED_ACTIVITY",
    "activity-alias": "EXPORTED_ACTIVITY",
    "service": "EXPORTED_SERVICE",
    "receiver": "EXPORTED_RECEIVER",
    "provider": "EXPORTED_PROVIDER",
}


def _component_exposure(component) -> str:
    if component.exposure == "UNKNOWN":
        return UNKNOWN
    if not component.effective_exported:
        return INTERNAL
    return PERMISSION_PROTECTED if component.permission else PUBLIC


def build_attack_surface(analysis):
    """Create AttackSurfaceNode/AttackSurfaceEdge rows on the analysis."""
    from app.models.correlation import AttackSurfaceEdge, AttackSurfaceNode

    nodes: dict[str, AttackSurfaceNode] = {}

    def add(node_key, node_type, name, exposure, component=None, permission=None, evidence=""):
        if node_key in nodes:
            return nodes[node_key]
        node = AttackSurfaceNode(node_key=node_key, node_type=node_type, name=name, exposure=exposure,
                                 component=component, permission=permission, evidence=evidence)
        analysis.attack_surface_nodes.append(node)
        nodes[node_key] = node
        return node

    # Components (exported / conditionally-exported / unknown-provider).
    for component in analysis.components:
        exposure = _component_exposure(component)
        if exposure == INTERNAL:
            continue  # internal-only components are not attack surface
        node_type = _COMPONENT_NODE_TYPE.get(component.kind, "EXPORTED_COMPONENT")
        add(f"surface:component:{component.name}", node_type, component.name or "", exposure,
            component=component.name, permission=component.permission,
            evidence=f"manifest exported={component.exported} exposure={component.exposure}")

    # Deep links (public by nature).
    for dl in analysis.deep_links:
        add(f"surface:deeplink:{dl.node_key}", "DEEP_LINK",
            f"{dl.scheme}://{dl.host or ''}{dl.path or ''}", PUBLIC, component=dl.component,
            evidence=dl.evidence)

    # Security boundaries (WebView JS bridge, Binder IPC, JNI).
    boundary_exposure = {"WEBVIEW_JS": UNKNOWN, "BINDER_IPC": UNKNOWN, "JNI": INTERNAL, "DEEP_LINK": PUBLIC,
                         "EXTERNAL_INTENT": PUBLIC}
    boundary_type_node = {"WEBVIEW_JS": "WEBVIEW_BRIDGE", "BINDER_IPC": "BINDER_ENTRY", "JNI": "JNI_BOUNDARY"}
    for boundary in analysis.security_boundaries:
        if boundary.boundary_type not in boundary_type_node:
            continue  # EXTERNAL_INTENT is already represented by the component node
        add(f"surface:boundary:{boundary.node_key}", boundary_type_node[boundary.boundary_type],
            boundary.node_key, boundary_exposure.get(boundary.boundary_type, UNKNOWN),
            component=boundary.component, evidence=boundary.evidence)

    # Bundled native libraries.
    for lib in analysis.native_libraries:
        if not lib.status == "COMPLETE":
            continue
        add(f"surface:native:{lib.filename}:{lib.abi}", "NATIVE_LIBRARY", lib.filename, INTERNAL,
            evidence=f"bundled {lib.archive_path}")

    # Edges: surface node -> root cause it contributes to (by shared component).
    for rc in analysis.root_causes:
        for node in analysis.attack_surface_nodes:
            if node.component and node.component in (rc.affected_components or []):
                analysis.attack_surface_edges.append(AttackSurfaceEdge(
                    src_key=node.node_key, dst_key=f"rootcause:{rc.identifier}", edge_type="LEADS_TO",
                    evidence=f"{node.node_type} contributes to {rc.category}", confidence=rc.confidence))

    # Edges: entry point -> reachable sink (from persisted reachability paths).
    for path in analysis.reachability_paths:
        if path.status != "REACHABLE" or not path.nodes:
            continue
        start = path.nodes[0].get("label")
        end = path.nodes[-1].get("label")
        for node in analysis.attack_surface_nodes:
            if node.name and (node.name == start or (node.component and node.component in str(start))):
                analysis.attack_surface_edges.append(AttackSurfaceEdge(
                    src_key=node.node_key, dst_key=f"sink:{end}", edge_type="REACHES",
                    evidence=" -> ".join(n.get("label", "?") for n in path.nodes),
                    confidence=path.confidence))
                break

    return list(nodes.values())

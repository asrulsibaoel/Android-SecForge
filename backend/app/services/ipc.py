from app.models.apk import APKArtifact


def analyze_ipc(artifact: APKArtifact) -> dict:
    """Derive IPC entry points from manifest components without claiming exploitability."""
    entries = []
    for component in artifact.framework.get("components", []):
        if not component.get("effective_exported"):
            continue
        entry = {
            "component": component.get("name"),
            "type": component.get("type"),
            "permission": component.get("permission"),
            "input": "Intent" if component.get("type") != "provider" else "Uri/ContentResolver",
            "entry_methods": component.get("entry_methods", []),
            "state": "POTENTIAL",
            "evidence": ["AndroidManifest.xml"],
        }
        entries.append(entry)
    relationships = [
        {"from": entry["component"], "type": "IPC_ENTRYPOINT", "to": method}
        for entry in entries
        for method in entry["entry_methods"]
    ]
    return {
        "status": "analyzed",
        "entries": entries,
        "relationships": relationships,
        "limitations": ["Code-level input validation and runtime reachability require DEX/runtime analysis."],
    }
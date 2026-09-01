from pathlib import Path
import zipfile

from app.analysis.manifest import parse_manifest, ParsedManifest
from app.models.apk import APKArtifact
from app.rules.engine import run_manifest_rules
from app.services.ipc import analyze_ipc


def read_manifest_bytes(archive: zipfile.ZipFile) -> bytes | None:
    """Return the AndroidManifest.xml bytes from an APK or bundle archive."""
    names = archive.namelist()
    candidates = [
        name
        for name in names
        if name == "AndroidManifest.xml" or name.endswith("/manifest/AndroidManifest.xml")
    ]
    if not candidates:
        return None
    return archive.read(candidates[0])


def inspect_artifact(source: Path, artifact: APKArtifact) -> APKArtifact:
    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        artifact.structure = {
            "entries": len(names),
            "manifest": "AndroidManifest.xml" in names,
            "dex": sorted(name for name in names if name.startswith("classes") and name.endswith(".dex")),
            "resources": sorted(name for name in names if name == "resources.arsc" or name.startswith("res/")),
            "assets": sorted(name for name in names if name.startswith("assets/")),
            "native": sorted(name for name in names if name.startswith("lib/") and name.endswith(".so")),
            "certificates": sorted(
                name for name in names if name.startswith("META-INF/") and name.endswith((".RSA", ".DSA", ".EC"))
            ),
        }
        raw = read_manifest_bytes(archive)

    if raw is None:
        parsed = ParsedManifest(status="missing", source_format="none")
    else:
        parsed = parse_manifest(raw)

    manifest = parsed.to_dict()
    findings = [finding.to_legacy_dict() for finding in run_manifest_rules(parsed)]
    artifact.manifest = manifest
    artifact.findings = findings

    framework_components = []
    for component in parsed.components:
        framework_components.append(
            {
                "type": component.kind,
                "name": component.name,
                "exported": component.exported,
                "permission": component.permission,
                "intent_filters": [
                    {
                        "actions": list(item.actions),
                        "categories": list(item.categories),
                        "data": list(item.data),
                    }
                    for item in component.intent_filters
                ],
                "explicit_exported": component.explicit_exported,
                "effective_exported": component.effective_exported,
                "exposure": "external" if component.effective_exported else "internal",
                "entry_methods": list(component.entry_methods),
            }
        )
    artifact.framework = {
        "primitives": ["Activity", "Service", "BroadcastReceiver", "ContentProvider", "Intent", "Permission", "Context"],
        "components": framework_components,
        "relationships": [
            {
                "from": component["name"],
                "type": "RECEIVES_INTENT",
                "to": method,
                "evidence": "manifest intent-filter",
            }
            for component in framework_components
            if component["intent_filters"]
            for method in component["entry_methods"][:1]
        ],
    }
    artifact.ipc = analyze_ipc(artifact)
    artifact.manifest_status = parsed.status
    artifact.package_name = parsed.package
    artifact.version_name = parsed.version_name
    artifact.version_code = parsed.version_code
    artifact.status = "COMPLETED" if parsed.status == "parsed" else "PARTIAL"
    return artifact

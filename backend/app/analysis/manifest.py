"""Manifest normalization into a canonical, typed model.

Accepts either binary AXML (real APKs) or plain XML (bundles, tests) and produces
a :class:`ParsedManifest`. Component exposure is computed with Android semantics
rather than a raw ``exported`` string match. Every field originates from
``AndroidManifest.xml`` (recorded as provenance on the model).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from app.analysis.axml import ANDROID_NS, AXMLElement, decode_axml, is_binary_axml, AXMLError

_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

# Exposure states.
INTERNAL = "INTERNAL"
EXPORTED = "EXPORTED"
CONDITIONALLY_EXPORTED = "CONDITIONALLY_EXPORTED"
UNKNOWN = "UNKNOWN"

_ENTRY_METHODS = {
    "activity": ("onCreate", "onNewIntent"),
    "activity-alias": ("onCreate", "onNewIntent"),
    "service": ("onCreate", "onStartCommand", "onBind"),
    "receiver": ("onReceive",),
    "provider": ("onCreate", "query", "insert", "update", "delete"),
}


@dataclass
class IntentFilter:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    data: list[dict[str, str]] = field(default_factory=list)


@dataclass
class Component:
    kind: str
    name: str | None
    exported: bool | None
    explicit_exported: bool
    permission: str | None
    authorities: str | None
    process: str | None
    enabled: bool | None
    intent_filters: list[IntentFilter] = field(default_factory=list)
    effective_exported: bool = False
    exposure: str = INTERNAL
    entry_methods: tuple[str, ...] = ()


@dataclass
class ParsedManifest:
    status: str  # parsed | unsupported_binary_xml | malformed_xml | missing
    source_format: str  # binary_axml | plain_xml | none
    package: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    compile_sdk: str | None = None
    debuggable: bool | None = None
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None
    network_security_config: str | None = None
    permissions: list[str] = field(default_factory=list)
    custom_permissions: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Legacy JSON shape used by the existing inspection/API surface."""
        return {
            "status": self.status,
            "source_format": self.source_format,
            "package": self.package,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "uses_cleartext_traffic": self.uses_cleartext_traffic,
            "permissions": list(self.permissions),
            "components": [
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
                }
                for component in self.components
            ],
        }


def _to_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.strip().lower() in {"true", "1"}


def parse_manifest(raw: bytes) -> ParsedManifest:
    """Normalize raw manifest bytes (AXML or plain XML) into a typed model."""
    if is_binary_axml(raw):
        try:
            root = _from_axml(decode_axml(raw))
        except AXMLError:
            return ParsedManifest(status="malformed_axml", source_format="binary_axml")
        return _finalize(root, "binary_axml")
    if raw.lstrip().startswith(b"<"):
        try:
            root = _from_plain_xml(raw)
        except ET.ParseError:
            return ParsedManifest(status="malformed_xml", source_format="plain_xml")
        return _finalize(root, "plain_xml")
    return ParsedManifest(status="unsupported_binary_xml", source_format="binary_axml")


class _Node:
    """Uniform accessor over AXML elements and ElementTree elements."""

    def __init__(self, tag: str, attrs: dict[tuple[str | None, str], str], children: list["_Node"]):
        self.tag = tag
        self._attrs = attrs
        self.children = children

    def android(self, name: str) -> str | None:
        return self._attrs.get((ANDROID_NS, name))

    def plain(self, name: str) -> str | None:
        return self._attrs.get((None, name))

    def findall(self, tag: str) -> list["_Node"]:
        return [child for child in self.children if child.tag == tag]

    def find(self, tag: str) -> "_Node | None":
        for child in self.children:
            if child.tag == tag:
                return child
        return None


def _from_axml(element: AXMLElement) -> _Node:
    children = [_from_axml(child) for child in element.children]
    return _Node(element.tag, dict(element.attributes), children)


def _from_plain_xml(raw: bytes) -> _Node:
    root = ET.fromstring(raw)

    def convert(node: ET.Element) -> _Node:
        attrs: dict[tuple[str | None, str], str] = {}
        for key, value in node.attrib.items():
            if key.startswith("{"):
                uri, local = key[1:].split("}", 1)
                attrs[(uri, local)] = value
            else:
                attrs[(None, key)] = value
        return _Node(node.tag, attrs, [convert(child) for child in node])

    return convert(root)


def _finalize(root: _Node, source_format: str) -> ParsedManifest:
    manifest = ParsedManifest(status="parsed", source_format=source_format)
    manifest.package = root.plain("package")
    manifest.version_name = root.android("versionName")
    manifest.version_code = root.android("versionCode")
    manifest.compile_sdk = root.android("compileSdkVersion")

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        manifest.min_sdk = uses_sdk.android("minSdkVersion")
        manifest.target_sdk = uses_sdk.android("targetSdkVersion")

    application = root.find("application")
    if application is not None:
        manifest.debuggable = _to_bool(application.android("debuggable"))
        manifest.allow_backup = _to_bool(application.android("allowBackup"))
        manifest.uses_cleartext_traffic = _to_bool(application.android("usesCleartextTraffic"))
        manifest.network_security_config = application.android("networkSecurityConfig")
        for kind in _COMPONENT_TAGS:
            for node in application.findall(kind):
                manifest.components.append(_component(kind, node))

    manifest.permissions = [
        node.android("name")
        for node in root.findall("uses-permission")
        if node.android("name")
    ]
    manifest.custom_permissions = [
        node.android("name")
        for node in root.findall("permission")
        if node.android("name")
    ]
    return manifest


def _component(kind: str, node: _Node) -> Component:
    exported = _to_bool(node.android("exported"))
    intent_filters = [_intent_filter(item) for item in node.findall("intent-filter")]
    component = Component(
        kind=kind,
        name=node.android("name"),
        exported=exported,
        explicit_exported=exported is not None,
        permission=node.android("permission"),
        authorities=node.android("authorities"),
        process=node.android("process"),
        enabled=_to_bool(node.android("enabled")),
        intent_filters=intent_filters,
        entry_methods=_ENTRY_METHODS.get(kind, ()),
    )
    _apply_exposure(component)
    return component


def _apply_exposure(component: Component) -> None:
    has_filter = bool(component.intent_filters)
    if component.exported is True:
        component.effective_exported = True
        component.exposure = EXPORTED
    elif component.exported is False:
        component.effective_exported = False
        component.exposure = INTERNAL
    elif has_filter and component.kind != "provider":
        # activity/service/receiver default to exported when they declare a filter.
        component.effective_exported = True
        component.exposure = CONDITIONALLY_EXPORTED
    elif component.kind == "provider":
        # Provider export default is target-SDK dependent and must be explicit
        # on modern platforms; without an explicit flag treat it as unknown.
        component.effective_exported = False
        component.exposure = UNKNOWN
    else:
        component.effective_exported = False
        component.exposure = INTERNAL


def _intent_filter(node: _Node) -> IntentFilter:
    return IntentFilter(
        actions=[item.android("name") for item in node.findall("action") if item.android("name")],
        categories=[item.android("name") for item in node.findall("category") if item.android("name")],
        data=[_intent_data(item) for item in node.findall("data")],
    )


def _intent_data(node: _Node) -> dict[str, str]:
    fields = ("scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType")
    return {name: node.android(name) for name in fields if node.android(name)}

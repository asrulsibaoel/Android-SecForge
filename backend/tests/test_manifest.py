from app.analysis.axml import encode_axml
from app.analysis.manifest import (
    CONDITIONALLY_EXPORTED,
    EXPORTED,
    INTERNAL,
    UNKNOWN,
    parse_manifest,
)
from app.analysis.permissions import DANGEROUS, NORMAL, classify_permission
from app.testapp.builder import manifest_spec

_PLAIN = (
    b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.plain">'
    b'<uses-sdk android:minSdkVersion="19" android:targetSdkVersion="30"/>'
    b'<uses-permission android:name="android.permission.READ_SMS"/>'
    b'<application android:debuggable="true">'
    b'<activity android:name=".A" android:exported="false"/>'
    b'<service android:name=".S"><intent-filter><action android:name="x"/></intent-filter></service>'
    b'<provider android:name=".P" android:authorities="a"/>'
    b'</application></manifest>'
)


def test_plain_xml_manifest_is_parsed():
    manifest = parse_manifest(_PLAIN)
    assert manifest.status == "parsed"
    assert manifest.source_format == "plain_xml"
    assert manifest.package == "com.plain"
    assert manifest.target_sdk == "30"
    assert manifest.debuggable is True


def test_binary_axml_manifest_is_parsed():
    manifest = parse_manifest(encode_axml(manifest_spec()))
    assert manifest.status == "parsed"
    assert manifest.source_format == "binary_axml"
    assert manifest.package == "com.androidsecforge.testapp"
    assert manifest.version_code == "3"
    assert len(manifest.components) == 6


def test_component_exposure_states():
    manifest = parse_manifest(_PLAIN)
    by_name = {component.name: component for component in manifest.components}
    assert by_name[".A"].exposure == INTERNAL  # explicit exported=false
    assert by_name[".S"].exposure == CONDITIONALLY_EXPORTED  # implicit via intent-filter
    assert by_name[".S"].effective_exported is True
    assert by_name[".P"].exposure == UNKNOWN  # provider default is version-dependent


def test_explicit_exported_true_is_exported():
    manifest = parse_manifest(encode_axml(manifest_spec()))
    activity = next(component for component in manifest.components if component.name == ".MainActivity")
    assert activity.exposure == EXPORTED
    assert activity.explicit_exported is True


def test_unsupported_binary_input_is_reported():
    manifest = parse_manifest(b"binary manifest")
    assert manifest.status == "unsupported_binary_xml"


def test_permission_classification():
    assert classify_permission("android.permission.CAMERA").protection_level == DANGEROUS
    assert classify_permission("android.permission.INTERNET").protection_level == NORMAL
    custom = classify_permission("com.vendor.CUSTOM")
    assert custom.protection_level == UNKNOWN
    assert custom.is_custom is True

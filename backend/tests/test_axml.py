import pytest

from app.analysis.axml import (
    ANDROID_NS,
    AXMLError,
    BuildAttr,
    BuildElement,
    decode_axml,
    encode_axml,
    is_binary_axml,
)


def _sample() -> BuildElement:
    return BuildElement(
        "manifest",
        attrs=[
            BuildAttr("package", "com.example.app", "string", namespace=None),
            BuildAttr("versionCode", "42", "int"),
            BuildAttr("versionName", "2.0.1"),
        ],
        children=[
            BuildElement(
                "uses-sdk",
                attrs=[BuildAttr("minSdkVersion", "21", "int"), BuildAttr("targetSdkVersion", "34", "int")],
            ),
            BuildElement("uses-permission", attrs=[BuildAttr("name", "android.permission.CAMERA")]),
            BuildElement(
                "application",
                attrs=[BuildAttr("debuggable", "true", "bool"), BuildAttr("allowBackup", "false", "bool")],
                children=[
                    BuildElement(
                        "activity",
                        attrs=[BuildAttr("name", ".Main"), BuildAttr("exported", "true", "bool")],
                        children=[
                            BuildElement(
                                "intent-filter",
                                children=[BuildElement("action", attrs=[BuildAttr("name", "a.b.VIEW")])],
                            )
                        ],
                    )
                ],
            ),
        ],
    )


def test_encode_produces_binary_axml():
    blob = encode_axml(_sample())
    assert is_binary_axml(blob)
    assert not is_binary_axml(b"<manifest/>")
    assert not is_binary_axml(b"")


def test_round_trip_attributes_and_types():
    root = decode_axml(encode_axml(_sample()))
    assert root.tag == "manifest"
    assert root.get("package", namespace=None) == "com.example.app"
    assert root.get("versionCode") == "42"
    assert root.get("versionName") == "2.0.1"
    sdk = root.find("uses-sdk")
    assert sdk.get("minSdkVersion") == "21"
    assert sdk.get("targetSdkVersion") == "34"


def test_round_trip_components_and_permissions():
    root = decode_axml(encode_axml(_sample()))
    perm = root.find("uses-permission")
    assert perm.get("name") == "android.permission.CAMERA"
    app = root.find("application")
    assert app.get("debuggable") == "true"
    assert app.get("allowBackup") == "false"
    activity = app.find("activity")
    assert activity.get("name") == ".Main"
    assert activity.get("exported") == "true"
    action = activity.find("intent-filter").find("action")
    assert action.get("name") == "a.b.VIEW"
    assert action.attributes[(ANDROID_NS, "name")] == "a.b.VIEW"


@pytest.mark.parametrize("data", [b"", b"not axml", b"\x03\x00\x08\x00", b"\x03\x00\x08\x00\x10\x00\x00\x00" + b"\xff" * 4])
def test_malformed_input_fails_safely(data):
    with pytest.raises(AXMLError):
        decode_axml(data)

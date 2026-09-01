"""Rule engine tests: every rule has a positive fixture, and negatives don't fire."""

from app.analysis.manifest import parse_manifest
from app.rules.engine import load_rules, run_code_rules, run_manifest_rules, ruleset_version


def _manifest(body: str) -> "ParsedManifest":  # noqa: F821 - forward ref for readability
    raw = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.t">'
        + body
        + "</manifest>"
    ).encode()
    return parse_manifest(raw)


def _ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}


def test_all_rules_have_required_metadata():
    for rule in load_rules():
        assert rule.id and rule.title and rule.category
        assert rule.severity in {"info", "low", "medium", "high", "critical"}
        assert rule.confidence in {"low", "medium", "high", "confirmed"}
        assert rule.type in {"manifest", "code", "native"}
        assert rule.description
        assert rule.remediation
        assert rule.references


def test_ruleset_version_is_stable():
    assert ruleset_version() == ruleset_version()
    assert len(ruleset_version()) == 16


def test_manifest_debuggable_positive_and_negative():
    positive = _manifest('<application android:debuggable="true"/>')
    assert "ANDROID-MANIFEST-001" in _ids(run_manifest_rules(positive))
    negative = _manifest('<application android:debuggable="false"/>')
    assert "ANDROID-MANIFEST-001" not in _ids(run_manifest_rules(negative))


def test_manifest_backup_and_cleartext():
    manifest = _manifest('<application android:allowBackup="true" android:usesCleartextTraffic="true"/>')
    ids = _ids(run_manifest_rules(manifest))
    assert {"ANDROID-MANIFEST-002", "ANDROID-MANIFEST-003"} <= ids


def test_exported_component_rules():
    manifest = _manifest(
        '<application>'
        '<activity android:name=".A" android:exported="true"/>'
        '<provider android:name=".P" android:exported="true" android:authorities="a"/>'
        '</application>'
    )
    findings = run_manifest_rules(manifest)
    assert "ANDROID-COMPONENT-001" in _ids(findings)
    assert "ANDROID-COMPONENT-002" in _ids(findings)
    # a permission-guarded exported component does not fire COMPONENT-001
    guarded = _manifest('<application><activity android:name=".A" android:exported="true" android:permission="p"/></application>')
    assert "ANDROID-COMPONENT-001" not in _ids(run_manifest_rules(guarded))


def test_code_rule_webview_javascript():
    findings = run_code_rules([("A.java", "s.setJavaScriptEnabled(true);")])
    assert "ANDROID-WEBVIEW-001" in _ids(findings)
    assert all(f.status == "POTENTIAL" for f in findings)


def test_code_rule_javascript_interface():
    findings = run_code_rules([("A.java", 'w.addJavascriptInterface(obj, "bridge");')])
    assert "ANDROID-WEBVIEW-002" in _ids(findings)


def test_code_rule_weak_crypto():
    findings = run_code_rules([("A.java", 'Cipher.getInstance("AES/ECB/PKCS5Padding");')])
    assert "ANDROID-CRYPTO-001" in _ids(findings)


def test_code_rule_hardcoded_secret_is_masked():
    findings = run_code_rules([("A.java", 'String apiKey = "SUPERSECRETVALUE123";')])
    secret = next(f for f in findings if f.rule_id == "ANDROID-SECRET-001")
    detail = secret.evidence[0].detail
    assert "SUPERSECRETVALUE123" not in detail
    assert "*" in detail


def test_code_rule_trustmanager_requires_all_patterns():
    # Only one of the two required patterns present -> no finding.
    partial = run_code_rules([("A.java", "class X implements X509TrustManager {}")])
    assert "ANDROID-TLS-001" not in _ids(partial)
    full = run_code_rules(
        [("A.java", "class X implements X509TrustManager { public void checkServerTrusted() {} }")]
    )
    assert "ANDROID-TLS-001" in _ids(full)


def test_code_rules_do_not_fire_on_clean_source():
    findings = run_code_rules([("A.java", "class Clean { int add(int a, int b) { return a + b; } }")])
    assert findings == []

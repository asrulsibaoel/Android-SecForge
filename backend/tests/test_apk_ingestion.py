import hashlib
import struct
import zipfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import Base
from app.services.apk_ingestion import ingest_apk


def test_ingestion_persists_fingerprints_and_does_not_modify_source(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "sample.apk"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"binary manifest")
        archive.writestr("classes.dex", b"dex fixture")
    original = source.read_bytes()
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path / "artifacts"))

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        artifact = ingest_apk(source, db)
        assert db.get(type(artifact), artifact.id) is not None

    assert source.read_bytes() == original
    assert artifact.sha256 == hashlib.sha256(original).hexdigest()
    assert artifact.manifest_status == "unsupported_binary_xml"
    assert Path(artifact.storage_path).read_bytes() == original


def test_analyze_command_reports_partial_capabilities(tmp_path: Path, monkeypatch, capsys) -> None:
    source = tmp_path / "module.apk"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("classes.dex", b"dex fixture")
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path / "artifacts"))
    monkeypatch.setattr(settings, "workspace_path", str(tmp_path / "workspace"))
    monkeypatch.setattr("app.analysis.jadx.jadx_executable", lambda: None)

    import app.models  # noqa: F401  register relational tables on Base.metadata
    from sqlalchemy.orm import sessionmaker

    from app.cli import analyze

    engine = create_engine(f"sqlite:///{tmp_path / 'analyze.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr("app.cli.SessionLocal", factory)
    monkeypatch.setattr("app.cli.initialize_database", lambda: None)
    analyze(source)

    output = capsys.readouterr().out
    assert "analysis_id=" in output
    assert "status=PARTIAL" in output
    assert "jadx=UNAVAILABLE" in output
    # No AndroidManifest.xml in this fixture -> manifest stage is skipped honestly.
    assert "manifest=SKIPPED" in output


@pytest.mark.parametrize("extension", ["aab", "apks", "apkm"])
def test_android_archive_ingestion_is_supported(
    tmp_path: Path, monkeypatch, extension: str
) -> None:
    source = tmp_path / f"module.{extension}"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("base/manifest/AndroidManifest.xml", b"bundle manifest")
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path / "artifacts"))

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        artifact = ingest_apk(source, db)

    assert artifact.artifact_type == extension
    assert artifact.storage_path.endswith(f"{artifact.sha256}.{extension}")


def test_xml_manifest_is_inspected_and_finding_is_evidence_backed(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "vulnerable.apk"
    manifest = b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test" android:versionName="1.2"><uses-sdk android:minSdkVersion="23" android:targetSdkVersion="28"/><uses-permission android:name="android.permission.INTERNET"/><application android:debuggable="true" android:usesCleartextTraffic="true"><activity android:name=".MainActivity" android:exported="true"/></application></manifest>'''
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", b"dex fixture")
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path / "artifacts"))

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        artifact = ingest_apk(source, db)

    assert artifact.manifest["package"] == "com.example.test"
    assert artifact.manifest["target_sdk"] == "28"
    assert {finding["id"] for finding in artifact.findings} == {
        "ANDROID-MANIFEST-001",
        "ANDROID-MANIFEST-003",
        "ANDROID-COMPONENT-001",
    }


def test_framework_model_links_exported_activity_to_entry_point(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "framework.apk"
    manifest = b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="demo"><application><activity android:name=".Entry"><intent-filter><action android:name="android.intent.action.VIEW"/></intent-filter></activity></application></manifest>'''
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path / "artifacts"))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        artifact = ingest_apk(source, db)

    component = artifact.framework["components"][0]
    assert component["effective_exported"] is True
    assert component["exposure"] == "external"
    assert "onCreate" in component["entry_methods"]
    assert artifact.framework["relationships"] == [{
        "from": ".Entry",
        "type": "RECEIVES_INTENT",
        "to": "onCreate",
        "evidence": "manifest intent-filter",
    }]


def test_multidex_inventory_extracts_valid_dex_headers(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "multidex.apk"
    dex = bytearray(112)
    dex[:8] = b"dex\n039\0"
    struct.pack_into("<I", dex, 32, 112)
    struct.pack_into("<I", dex, 36, 112)
    struct.pack_into("<I", dex, 56, 4)
    struct.pack_into("<I", dex, 88, 9)
    struct.pack_into("<I", dex, 96, 2)
    dex2 = bytes(dex).replace(b"039", b"035", 1)
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path / "artifacts"))
    monkeypatch.setattr(settings, "workspace_path", str(tmp_path / "workspace"))
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("classes.dex", bytes(dex))
        archive.writestr("classes2.dex", dex2)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        artifact = ingest_apk(source, db)

    assert len(artifact.dex) == 2
    assert all(record["valid"] for record in artifact.dex)
    assert {record["class_count"] for record in artifact.dex} == {2}
    assert Path(artifact.workspace_path, "dex", "classes.dex").exists()
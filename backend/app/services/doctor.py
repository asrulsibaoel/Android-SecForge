import os
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from app.core.config import settings


@dataclass(frozen=True)
class ToolStatus:
    name: str
    detected: bool
    path: str | None
    version: str | None
    status: str
    required: bool
    capabilities: tuple[str, ...]

    @property
    def capability(self) -> str:
        return "READY" if self.detected else "UNAVAILABLE"


# name, version-args, capabilities, required, config-path-attr
_TOOLS = (
    ("python", ("--version",), ("core runtime",), True, None),
    ("java", ("-version",), ("JADX decompilation", "Ghidra"), False, None),
    ("jadx", ("--version",), ("Java decompilation", "code index"), False, "jadx_path"),
    ("apktool", ("--version",), ("Smali and resource decoding",), False, "apktool_path"),
    ("adb", ("version",), ("Android runtime device control",), False, None),
    ("emulator", ("-version",), ("Android emulator runtime",), False, None),
    ("frida", ("--version",), ("Runtime instrumentation",), False, None),
)


def _version(path: str, arguments: tuple[str, ...]) -> str | None:
    try:
        result = subprocess.run([path, *arguments], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0] if output else None


def _resolve(name: str, config_attr: str | None) -> str | None:
    if config_attr:
        configured = getattr(settings, config_attr, "") or ""
        if configured and Path(configured).is_file():
            return configured
    return shutil.which(name)


def _detect_ghidra() -> ToolStatus:
    capabilities = ("Native ELF decompilation",)
    candidates: list[str] = []
    if settings.ghidra_path:
        candidates.append(settings.ghidra_path)
    for env in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        value = os.environ.get(env)
        if value:
            candidates.append(str(Path(value) / "support" / "analyzeHeadless"))
    headless = shutil.which("analyzeHeadless")
    if headless:
        candidates.append(headless)
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return ToolStatus("ghidra", True, candidate, None, "AVAILABLE", False, capabilities)
    return ToolStatus("ghidra", False, None, None, "CAPABILITY_UNAVAILABLE", False, capabilities)


def _detect_android_sdk() -> ToolStatus:
    capabilities = ("APK tooling", "emulator/device management")
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        value = os.environ.get(env)
        if value and Path(value).is_dir():
            return ToolStatus("android-sdk", True, value, None, "AVAILABLE", False, capabilities)
    adb = shutil.which("adb")
    if adb:
        root = str(Path(adb).resolve().parent.parent)
        return ToolStatus("android-sdk", True, root, None, "AVAILABLE", False, capabilities)
    return ToolStatus("android-sdk", False, None, None, "CAPABILITY_UNAVAILABLE", False, capabilities)


def discover_tools() -> list[dict]:
    statuses: list[ToolStatus] = []
    for name, arguments, capabilities, required, config_attr in _TOOLS:
        path = _resolve(name, config_attr)
        statuses.append(
            ToolStatus(
                name=name,
                detected=path is not None,
                path=path,
                version=_version(path, arguments) if path else None,
                status="AVAILABLE" if path else ("MISSING" if required else "CAPABILITY_UNAVAILABLE"),
                required=required,
                capabilities=capabilities,
            )
        )
    statuses.append(_detect_ghidra())
    statuses.append(_detect_android_sdk())
    return [{**asdict(status), "capability": status.capability} for status in statuses]


def graph_capabilities() -> list[dict]:
    """Knowledge-graph + investigation capabilities. These are built-in (no
    external tool required) and always available offline."""
    from app.analysis.graph_queries import available_queries

    return [
        {"name": "graph_database", "availability": "AVAILABLE",
         "reason": "relational store (SQLite default; PostgreSQL optional)"},
        {"name": "knowledge_graph", "availability": "AVAILABLE",
         "reason": "projection over canonical code graph + entities (no second graph)"},
        {"name": "investigation", "availability": "AVAILABLE",
         "reason": "persistent workspace: nodes/findings/notes/hypotheses/bookmarks/timeline"},
        {"name": "graph_queries", "availability": "AVAILABLE",
         "reason": f"{len(available_queries())} deterministic named queries"},
        {"name": "graph_export", "availability": "AVAILABLE", "reason": "JSON / GraphML / DOT / Markdown"},
        {"name": "runtime_correlation", "availability": "AVAILABLE",
         "reason": "static↔runtime correlation (observation-only; NOT_OBSERVED != SAFE)"},
        {"name": "apk_diff", "availability": "AVAILABLE",
         "reason": "comparative analysis A→B with conservative security-impact classification + snapshot integrity"},
        {"name": "remediation", "availability": "READY",
         "reason": "deterministic evidence-backed remediation planning; offline; no network required"},
        {"name": "validation", "availability": "READY",
         "reason": "security verification/validation intelligence; static validation works offline; "
                   "runtime corroboration is optional and never required (LIVE runtime = UNAVAILABLE without a device)"},
        {"name": "obfuscation", "availability": "READY",
         "reason": "obfuscation & anti-analysis intelligence; deterministic, offline, no external service; "
                   "describes analysis complexity, never vulnerability/exploitability"},
        {"name": "native_deep", "availability": "READY",
         "reason": "deep native / Ghidra correlation; ELF-only mode works offline; Ghidra optional "
                   "(see 'native_ghidra' capability); supplements ELF/JNI evidence, never exploitability"},
        {"name": "assessment", "availability": "READY",
         "reason": "security assessment & decision intelligence; deterministic offline projection over persisted "
                   "evidence; explicit decision states (never SAFE/UNSAFE, never exploitability)"},
        _ghidra_capability(),
    ]


def _ghidra_capability() -> dict:
    try:
        from app.native.ghidra_adapter import capability

        cap = capability()
        return {"name": "native_ghidra", "availability": cap["state"], "reason": cap["reason"],
                "version": cap.get("version"), "path": cap.get("path")}
    except Exception as error:  # detection must never break doctor
        return {"name": "native_ghidra", "availability": "UNAVAILABLE", "reason": str(error)}


def doctor_report() -> dict:
    report = {"platform": platform.platform(), "tools": discover_tools()}
    try:
        from app.runtime.capability import runtime_capabilities

        report["runtime"] = runtime_capabilities()
    except Exception as error:  # runtime detection must never break doctor
        report["runtime"] = [{"name": "runtime", "availability": "UNAVAILABLE", "reason": str(error)}]
    try:
        report["graph"] = graph_capabilities()
    except Exception as error:  # capability listing must never break doctor
        report["graph"] = [{"name": "graph", "availability": "UNAVAILABLE", "reason": str(error)}]
    try:
        report["intelligence"] = intelligence_status()
    except Exception as error:  # missing network/DB must never break doctor
        report["intelligence"] = {"providers": [], "error": str(error)}
    return report


def intelligence_status() -> dict:
    """Vulnerability-intelligence capability report. Missing network never makes
    offline analysis fail — providers are import-capable offline; live sync is
    best-effort and reported as UNKNOWN (never probed here)."""
    from app.intel.providers import providers_status
    from app.intel.freshness import db_freshness
    from app.db.session import SessionLocal, initialize_database
    from app.models.cve import IntelBundle, Vulnerability
    from sqlalchemy import func, select

    result: dict = {"providers": providers_status()}
    try:
        initialize_database()
        with SessionLocal() as db:
            total = db.scalar(select(func.count(Vulnerability.id))) or 0
            test = db.scalar(select(func.count(Vulnerability.id)).where(Vulnerability.is_test_data.is_(True))) or 0
            bundles = db.scalar(select(func.count(IntelBundle.id))) or 0
            result["local_database"] = {"status": "AVAILABLE" if total else "EMPTY",
                                        "total": total, "test_data": test, "production": total - test}
            result["bundles"] = {"imported": bundles}
            result["freshness"] = db_freshness(db)
    except Exception as error:
        result["local_database"] = {"status": "UNAVAILABLE", "reason": str(error)}
    result["nvd"] = "OFFLINE_IMPORT_OK (live sync best-effort, not probed)"
    result["osv"] = "OFFLINE_IMPORT_OK (live sync best-effort, not probed)"
    return result

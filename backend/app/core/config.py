from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "sqlite:///./androidsecforge.db"
    artifact_storage_path: str = "./artifacts"
    workspace_path: str = "./workspace"
    authorization_mode: str = "SAFE"

    # External-tool configuration. Paths are optional overrides; when empty the
    # tool is discovered on PATH. Never hardcode developer-specific paths here.
    jadx_path: str = ""
    jadx_timeout_seconds: int = 600
    ghidra_path: str = ""
    ghidra_enabled: bool = False
    ghidra_timeout_seconds: int = 900
    apktool_path: str = ""

    # Security limits for untrusted APK input.
    max_apk_size_bytes: int = 1024 * 1024 * 1024  # 1 GiB
    max_uncompressed_bytes: int = 4 * 1024 * 1024 * 1024  # 4 GiB (zip-bomb guard)

    # Reachability engine bounds (keep large APKs usable).
    reach_max_depth: int = 50
    reach_max_persisted_nodes: int = 60000
    reach_max_persisted_edges: int = 120000

    # Knowledge-graph projection + investigation traversal bounds (Phase 15).
    graph_max_projected_nodes: int = 40000
    graph_max_projected_edges: int = 120000
    graph_query_max_depth: int = 25
    graph_query_max_paths: int = 100
    graph_query_max_nodes: int = 200000
    graph_query_timeout_seconds: float = 15.0

    # APK-diff / comparison bounds (Phase 19: bounded, configurable reports).
    diff_max_changes_per_category: int = 5000

    # Vulnerability-intelligence (prompt 16). Freshness threshold + bounds.
    intel_stale_days: int = 30
    intel_bundle_max_raw_bytes: int = 4096

    # Obfuscation & anti-analysis intelligence (prompt 19). Bounded, single-pass.
    obfuscation_max_classes: int = 100000
    obfuscation_max_methods: int = 400000
    obfuscation_max_strings: int = 50000
    obfuscation_max_indicators: int = 5000

    # Deep native / Ghidra correlation (prompt 20). Ghidra optional + bounded.
    ghidra_deep_enabled: bool = False           # opt-in live Ghidra deep analysis
    native_max_binaries: int = 200
    native_max_functions_per_binary: int = 20000
    native_max_symbols: int = 50000
    native_max_strings: int = 20000
    native_max_call_edges: int = 100000
    native_max_jni_bindings: int = 20000
    native_max_path_results: int = 200
    native_path_max_depth: int = 25
    native_analysis_timeout_seconds: int = 900
    native_max_output_bytes: int = 64 * 1024 * 1024

    # Runtime Lab (ADB / Frida) — optional; explicit-action only.
    adb_path: str = ""
    frida_path: str = ""
    frida_server_path_on_device: str = "/data/local/tmp/frida-server"
    runtime_command_timeout_seconds: int = 60
    runtime_logcat_timeout_seconds: int = 15
    runtime_logcat_max_lines: int = 5000
    runtime_logcat_max_bytes: int = 2 * 1024 * 1024
    runtime_observation_limit: int = 10000
    runtime_session_timeout_seconds: int = 900
    runtime_artifact_max_bytes: int = 64 * 1024 * 1024
    # Live runtime validation safety bounds (prompt 21). Reaching a bound records
    # TRUNCATED explicitly; evidence is never silently discarded.
    runtime_max_session_duration_seconds: int = 900
    runtime_max_events: int = 20000
    runtime_max_processes: int = 5000
    runtime_max_hook_events: int = 20000
    runtime_max_artifacts: int = 200
    runtime_max_correlation_paths: int = 2000
    runtime_redaction_limit: int = 300
    runtime_validation_timeout_seconds: int = 900
    # Assessment / decision-intelligence bounds (prompt 24). This layer is a pure
    # projection over persisted evidence; bounds keep the synthesis deterministic
    # and cheap. Reaching a bound records TRUNCATED (evidence never silently lost).
    assessment_max_subjects: int = 50000
    assessment_max_conclusions: int = 50000
    assessment_max_evidence_per_conclusion: int = 200
    # Web intake & execution bounds (prompt 26). Backend validation is authoritative.
    upload_max_file_size: int = 512 * 1024 * 1024        # 512 MB per artifact
    upload_max_total_size: int = 1024 * 1024 * 1024       # 1 GB per intake batch
    upload_max_files: int = 20
    upload_allowed_extensions: str = ".apk,.aab,.apks,.apkm"
    analysis_max_concurrent_executions: int = 2
    analysis_history_limit: int = 200

    model_config = SettingsConfigDict(env_file=".env", env_prefix="ASF_", extra="ignore")


settings = Settings()

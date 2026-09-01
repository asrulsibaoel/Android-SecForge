from alembic import op
import sqlalchemy as sa

revision = "0019_deep_native"
down_revision = "0018_obfuscation_intelligence"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def _afk() -> sa.ForeignKey:
    return sa.ForeignKey("analyses.id", ondelete="CASCADE")


def upgrade() -> None:
    op.create_table(
        "native_analysis_runs",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _afk(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("mode", sa.String(24), nullable=False, server_default="ELF_ONLY"),
        sa.Column("ghidra_capability", sa.String(16), nullable=False, server_default="UNAVAILABLE"),
        sa.Column("ghidra_version", sa.String(32), nullable=True),
        sa.Column("binaries_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("functions_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("jni_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("call_edge_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("api_observation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unresolved_target_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_native_analysis_runs_analysis_id", "native_analysis_runs", ["analysis_id"])
    op.create_index("ix_native_analysis_runs_fingerprint", "native_analysis_runs", ["fingerprint"])
    op.create_index("ix_native_analysis_runs_mode", "native_analysis_runs", ["mode"])

    op.create_table(
        "native_binaries",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _afk(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("filename", sa.String(256), nullable=False),
        sa.Column("abi", sa.String(32), nullable=True),
        sa.Column("architecture", sa.String(32), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("soname", sa.String(256), nullable=True),
        sa.Column("stripped", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("symbols_available", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("source", sa.String(24), nullable=False, server_default="ELF"),
        sa.Column("evidence_json", sa.JSON(), nullable=True),
    )
    op.create_index("ix_native_binaries_analysis_id", "native_binaries", ["analysis_id"])
    op.create_index("ix_native_binaries_fingerprint", "native_binaries", ["fingerprint"])

    op.create_table(
        "native_deep_functions",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _afk(), nullable=False),
        sa.Column("binary_fp", sa.String(64), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("normalized_name", sa.String(512), nullable=False),
        sa.Column("entry_address", sa.String(32), nullable=True),
        sa.Column("size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("function_type", sa.String(24), nullable=False, server_default="UNKNOWN"),
        sa.Column("symbol_type", sa.String(24), nullable=True),
        sa.Column("is_exported", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_imported", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
        sa.Column("source", sa.String(24), nullable=False, server_default="ELF"),
        sa.Column("evidence_json", sa.JSON(), nullable=True),
    )
    op.create_index("ix_native_deep_functions_analysis_id", "native_deep_functions", ["analysis_id"])
    op.create_index("ix_native_deep_functions_binary_fp", "native_deep_functions", ["binary_fp"])
    op.create_index("ix_native_deep_functions_fingerprint", "native_deep_functions", ["fingerprint"])
    op.create_index("ix_native_deep_functions_normalized_name", "native_deep_functions", ["normalized_name"])
    op.create_index("ix_native_deep_functions_function_type", "native_deep_functions", ["function_type"])
    op.create_index("ix_native_deep_functions_source", "native_deep_functions", ["source"])
    op.create_index("ix_native_deep_functions_analysis_type", "native_deep_functions",
                    ["analysis_id", "function_type"])

    op.create_table(
        "native_deep_symbols",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _afk(), nullable=False),
        sa.Column("binary_fp", sa.String(64), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("symbol_type", sa.String(24), nullable=True),
        sa.Column("address", sa.String(32), nullable=True),
        sa.Column("kind", sa.String(16), nullable=False, server_default="local"),
        sa.Column("source", sa.String(24), nullable=False, server_default="ELF"),
    )
    op.create_index("ix_native_deep_symbols_analysis_id", "native_deep_symbols", ["analysis_id"])
    op.create_index("ix_native_deep_symbols_binary_fp", "native_deep_symbols", ["binary_fp"])
    op.create_index("ix_native_deep_symbols_fingerprint", "native_deep_symbols", ["fingerprint"])

    op.create_table(
        "native_strings",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _afk(), nullable=False),
        sa.Column("binary_fp", sa.String(64), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("value", sa.String(1024), nullable=False),
        sa.Column("address", sa.String(32), nullable=True),
        sa.Column("source", sa.String(24), nullable=False, server_default="GHIDRA"),
    )
    op.create_index("ix_native_strings_analysis_id", "native_strings", ["analysis_id"])
    op.create_index("ix_native_strings_binary_fp", "native_strings", ["binary_fp"])
    op.create_index("ix_native_strings_fingerprint", "native_strings", ["fingerprint"])

    op.create_table(
        "native_call_edges",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _afk(), nullable=False),
        sa.Column("binary_fp", sa.String(64), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("src_fp", sa.String(64), nullable=False),
        sa.Column("src_name", sa.String(512), nullable=False),
        sa.Column("dst_fp", sa.String(64), nullable=True),
        sa.Column("dst_name", sa.String(512), nullable=False),
        sa.Column("edge_type", sa.String(24), nullable=False, server_default="GHIDRA_CALLS"),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
        sa.Column("source", sa.String(24), nullable=False, server_default="GHIDRA"),
    )
    op.create_index("ix_native_call_edges_analysis_id", "native_call_edges", ["analysis_id"])
    op.create_index("ix_native_call_edges_binary_fp", "native_call_edges", ["binary_fp"])
    op.create_index("ix_native_call_edges_fingerprint", "native_call_edges", ["fingerprint"])
    op.create_index("ix_native_call_edges_src_fp", "native_call_edges", ["src_fp"])
    op.create_index("ix_native_call_edges_dst_fp", "native_call_edges", ["dst_fp"])
    op.create_index("ix_native_call_edges_analysis_src", "native_call_edges", ["analysis_id", "src_fp"])

    op.create_table(
        "native_references",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _afk(), nullable=False),
        sa.Column("binary_fp", sa.String(64), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("from_fp", sa.String(64), nullable=True),
        sa.Column("to_address", sa.String(32), nullable=True),
        sa.Column("ref_type", sa.String(24), nullable=False, server_default="DATA"),
        sa.Column("source", sa.String(24), nullable=False, server_default="GHIDRA"),
    )
    op.create_index("ix_native_references_analysis_id", "native_references", ["analysis_id"])
    op.create_index("ix_native_references_binary_fp", "native_references", ["binary_fp"])
    op.create_index("ix_native_references_fingerprint", "native_references", ["fingerprint"])

    op.create_table(
        "native_deep_jni_bindings",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _afk(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("java_class", sa.String(512), nullable=True),
        sa.Column("java_method", sa.String(256), nullable=True),
        sa.Column("java_signature", sa.Text(), nullable=True),
        sa.Column("native_symbol", sa.String(512), nullable=True),
        sa.Column("native_function_fp", sa.String(64), nullable=True),
        sa.Column("binary_fp", sa.String(64), nullable=True),
        sa.Column("registration_type", sa.String(24), nullable=False, server_default="STATIC_NAMING"),
        sa.Column("state", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
        sa.Column("source", sa.String(24), nullable=False, server_default="JNI"),
        sa.Column("evidence_json", sa.JSON(), nullable=True),
    )
    op.create_index("ix_native_deep_jni_bindings_analysis_id", "native_deep_jni_bindings", ["analysis_id"])
    op.create_index("ix_native_deep_jni_bindings_fingerprint", "native_deep_jni_bindings", ["fingerprint"])
    op.create_index("ix_native_deep_jni_bindings_native_function_fp", "native_deep_jni_bindings",
                    ["native_function_fp"])
    op.create_index("ix_native_deep_jni_bindings_state", "native_deep_jni_bindings", ["state"])

    op.create_table(
        "native_api_observations",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _afk(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("binary_fp", sa.String(64), nullable=True),
        sa.Column("function_fp", sa.String(64), nullable=True),
        sa.Column("api", sa.String(128), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="NATIVE_API_PRESENT"),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
        sa.Column("source", sa.String(24), nullable=False, server_default="ELF"),
        sa.Column("evidence_json", sa.JSON(), nullable=True),
    )
    op.create_index("ix_native_api_observations_analysis_id", "native_api_observations", ["analysis_id"])
    op.create_index("ix_native_api_observations_fingerprint", "native_api_observations", ["fingerprint"])
    op.create_index("ix_native_api_observations_api", "native_api_observations", ["api"])
    op.create_index("ix_native_api_observations_state", "native_api_observations", ["state"])
    op.create_index("ix_native_api_observations_analysis_state", "native_api_observations",
                    ["analysis_id", "state"])

    op.create_table(
        "native_deep_evidence",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _afk(), nullable=False),
        sa.Column("subject_fp", sa.String(64), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("source_type", sa.String(16), nullable=False),
        sa.Column("artifact", sa.String(1024), nullable=True),
        sa.Column("file", sa.String(1024), nullable=True),
        sa.Column("function", sa.String(512), nullable=True),
        sa.Column("address", sa.String(32), nullable=True),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_native_deep_evidence_analysis_id", "native_deep_evidence", ["analysis_id"])
    op.create_index("ix_native_deep_evidence_subject_fp", "native_deep_evidence", ["subject_fp"])
    op.create_index("ix_native_deep_evidence_source_type", "native_deep_evidence", ["source_type"])


def downgrade() -> None:
    for table in ("native_deep_evidence", "native_api_observations", "native_deep_jni_bindings",
                  "native_references", "native_call_edges", "native_strings", "native_deep_symbols",
                  "native_deep_functions", "native_binaries", "native_analysis_runs"):
        op.drop_table(table)

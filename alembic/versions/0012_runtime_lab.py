from alembic import op
import sqlalchemy as sa

revision = "0012_runtime_lab"
down_revision = "0011_correlation_risk"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def _session_fk() -> sa.ForeignKey:
    return sa.ForeignKey("runtime_sessions.id", ondelete="CASCADE")


def upgrade() -> None:
    op.create_table(
        "runtime_devices",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("serial", sa.String(128), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("model", sa.String(128), nullable=True),
        sa.Column("manufacturer", sa.String(128), nullable=True),
        sa.Column("android_version", sa.String(32), nullable=True),
        sa.Column("sdk_version", sa.String(16), nullable=True),
        sa.Column("architecture", sa.String(32), nullable=True),
        sa.Column("abi", sa.String(32), nullable=True),
        sa.Column("rooted", sa.Boolean(), nullable=True),
        sa.Column("is_emulator", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=True),
    )
    op.create_index("ix_runtime_devices_serial", "runtime_devices", ["serial"])

    op.create_table(
        "runtime_sessions",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", _uuid(), sa.ForeignKey("runtime_devices.id", ondelete="SET NULL"), nullable=True),
        sa.Column("device_serial", sa.String(128), nullable=True),
        sa.Column("package_name", sa.String(512), nullable=True),
        sa.Column("apk_sha256", sa.String(64), nullable=True),
        sa.Column("session_state", sa.String(24), nullable=False, server_default="CREATED"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_by", sa.String(128), nullable=False, server_default="cli"),
        sa.Column("instrumentation_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("launch_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("install_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("uninstall_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("workspace_path", sa.String(1024), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
    )
    op.create_index("ix_runtime_sessions_analysis_id", "runtime_sessions", ["analysis_id"])
    op.create_index("ix_runtime_sessions_state", "runtime_sessions", ["session_state"])

    op.create_table(
        "runtime_observations",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("session_id", _uuid(), _session_fk(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_type", sa.String(24), nullable=False),
        sa.Column("process_id", sa.Integer(), nullable=True),
        sa.Column("package_name", sa.String(512), nullable=True),
        sa.Column("class_name", sa.String(512), nullable=True),
        sa.Column("method_name", sa.String(256), nullable=True),
        sa.Column("native_library", sa.String(256), nullable=True),
        sa.Column("symbol", sa.String(512), nullable=True),
        sa.Column("arguments_summary", sa.Text(), nullable=True),
        sa.Column("return_summary", sa.Text(), nullable=True),
        sa.Column("stack_trace_summary", sa.Text(), nullable=True),
        sa.Column("source", sa.String(24), nullable=False, server_default="FRIDA"),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
        sa.Column("metadata", sa.JSON(), nullable=True),
    )
    op.create_index("ix_runtime_observations_session_id", "runtime_observations", ["session_id"])
    op.create_index("ix_runtime_observations_type", "runtime_observations", ["observation_type"])
    op.create_index("ix_runtime_observations_session_type", "runtime_observations", ["session_id", "observation_type"])

    op.create_table(
        "runtime_events",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("session_id", _uuid(), _session_fk(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(24), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("tag", sa.String(256), nullable=True),
        sa.Column("priority", sa.String(8), nullable=True),
        sa.Column("package_name", sa.String(512), nullable=True),
        sa.Column("message", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_runtime_events_session_id", "runtime_events", ["session_id"])
    op.create_index("ix_runtime_events_session_type", "runtime_events", ["session_id", "event_type"])

    op.create_table(
        "runtime_processes",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("session_id", _uuid(), _session_fk(), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("uid", sa.String(32), nullable=True),
        sa.Column("abi", sa.String(32), nullable=True),
        sa.Column("start_info", sa.String(256), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
    )
    op.create_index("ix_runtime_processes_session_id", "runtime_processes", ["session_id"])

    op.create_table(
        "runtime_artifacts",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("session_id", _uuid(), _session_fk(), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("path", sa.String(1024), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
    )
    op.create_index("ix_runtime_artifacts_session_id", "runtime_artifacts", ["session_id"])

    op.create_table(
        "runtime_hook_profiles",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("name", sa.String(48), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("targets", sa.JSON(), nullable=True),
        sa.Column("observation_only", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index("ix_runtime_hook_profiles_name", "runtime_hook_profiles", ["name"])

    op.create_table(
        "runtime_audit_events",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("session_id", _uuid(), _session_fk(), nullable=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=True),
        sa.Column("operation", sa.String(24), nullable=False),
        sa.Column("device_serial", sa.String(128), nullable=True),
        sa.Column("package_name", sa.String(512), nullable=True),
        sa.Column("requested_by", sa.String(128), nullable=False, server_default="cli"),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", sa.String(16), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("command", sa.Text(), nullable=True),
    )
    op.create_index("ix_runtime_audit_events_session_id", "runtime_audit_events", ["session_id"])
    op.create_index("ix_runtime_audit_events_operation", "runtime_audit_events", ["operation"])

    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("runtime_status", sa.String(32), nullable=True))
        batch.add_column(sa.Column("runtime_evidence_count", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("validation_state", sa.String(16), nullable=False, server_default="NOT_RUN"))


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        for col in ("validation_state", "runtime_evidence_count", "runtime_status"):
            batch.drop_column(col)
    for table in ("runtime_audit_events", "runtime_hook_profiles", "runtime_artifacts", "runtime_processes",
                  "runtime_events", "runtime_observations", "runtime_sessions", "runtime_devices"):
        op.drop_table(table)

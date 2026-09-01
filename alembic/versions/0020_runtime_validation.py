from alembic import op
import sqlalchemy as sa

revision = "0020_runtime_validation"
down_revision = "0019_deep_native"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def _afk() -> sa.ForeignKey:
    return sa.ForeignKey("analyses.id", ondelete="CASCADE")


def upgrade() -> None:
    op.create_table(
        "runtime_validation_runs",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _afk(), nullable=False),
        sa.Column("session_id", _uuid(), sa.ForeignKey("runtime_sessions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False, server_default="UNAVAILABLE"),
        sa.Column("device_serial", sa.String(128), nullable=True),
        sa.Column("apk_sha256", sa.String(64), nullable=True),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("process_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("artifact_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("correlation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("live_claim_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("corroborated_finding_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("truncated", sa.JSON(), nullable=True),
        sa.Column("blockers", sa.JSON(), nullable=True),
        sa.Column("summary", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_runtime_validation_runs_analysis_id", "runtime_validation_runs", ["analysis_id"])
    op.create_index("ix_runtime_validation_runs_fingerprint", "runtime_validation_runs", ["fingerprint"])

    op.create_table(
        "runtime_correlations",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _afk(), nullable=False),
        sa.Column("run_id", _uuid(), sa.ForeignKey("runtime_validation_runs.id", ondelete="CASCADE"), nullable=True),
        sa.Column("observation_id", _uuid(),
                  sa.ForeignKey("runtime_observations.id", ondelete="SET NULL"), nullable=True),
        sa.Column("session_id", _uuid(), sa.ForeignKey("runtime_sessions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("subject_type", sa.String(24), nullable=False),
        sa.Column("subject_ref", sa.String(1024), nullable=False),
        sa.Column("taxonomy", sa.String(40), nullable=True),
        sa.Column("correlation_type", sa.String(24), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False, server_default="MOCKED"),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
        sa.Column("provenance", sa.String(16), nullable=False, server_default="RUNTIME_FRIDA"),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_runtime_correlations_analysis_id", "runtime_correlations", ["analysis_id"])
    op.create_index("ix_runtime_correlations_run_id", "runtime_correlations", ["run_id"])
    op.create_index("ix_runtime_correlations_fingerprint", "runtime_correlations", ["fingerprint"])
    op.create_index("ix_runtime_correlations_subject_type", "runtime_correlations", ["subject_type"])
    op.create_index("ix_runtime_correlations_subject", "runtime_correlations",
                    ["analysis_id", "subject_type"])

    # Additive columns — runtime observation taxonomy + finding runtime-validation axis.
    op.add_column("runtime_observations", sa.Column("taxonomy", sa.String(40), nullable=True))
    op.add_column("runtime_observations", sa.Column("redacted", sa.Boolean(), nullable=False,
                                                    server_default=sa.false()))
    op.create_index("ix_runtime_observations_taxonomy", "runtime_observations", ["taxonomy"])
    op.add_column("findings", sa.Column("runtime_validation_state", sa.String(32), nullable=False,
                                        server_default="LIVE_UNAVAILABLE"))


def downgrade() -> None:
    op.drop_column("findings", "runtime_validation_state")
    op.drop_index("ix_runtime_observations_taxonomy", "runtime_observations")
    op.drop_column("runtime_observations", "redacted")
    op.drop_column("runtime_observations", "taxonomy")
    op.drop_table("runtime_correlations")
    op.drop_table("runtime_validation_runs")

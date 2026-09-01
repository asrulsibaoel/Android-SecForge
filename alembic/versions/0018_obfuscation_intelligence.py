from alembic import op
import sqlalchemy as sa

revision = "0018_obfuscation_intelligence"
down_revision = "0017_security_validation"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def _analysis_fk() -> sa.ForeignKey:
    return sa.ForeignKey("analyses.id", ondelete="CASCADE")


def upgrade() -> None:
    op.create_table(
        "obfuscation_observations",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _analysis_fk(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("finding_type", sa.String(32), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("indicator", sa.String(256), nullable=False),
        sa.Column("target_type", sa.String(24), nullable=False, server_default="APK"),
        sa.Column("target", sa.String(1024), nullable=True),
        sa.Column("state", sa.String(24), nullable=False, server_default="UNKNOWN"),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="LOW"),
        sa.Column("source_type", sa.String(24), nullable=False, server_default="STATIC_RULE"),
        sa.Column("source_id", sa.String(1024), nullable=True),
        sa.Column("evidence_json", sa.JSON(), nullable=True),
        sa.Column("uncertainties", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_obfuscation_observations_analysis_id", "obfuscation_observations", ["analysis_id"])
    op.create_index("ix_obfuscation_observations_fingerprint", "obfuscation_observations", ["fingerprint"])
    op.create_index("ix_obfuscation_observations_finding_type", "obfuscation_observations", ["finding_type"])
    op.create_index("ix_obfuscation_observations_category", "obfuscation_observations", ["category"])
    op.create_index("ix_obfuscation_observations_state", "obfuscation_observations", ["state"])
    op.create_index("ix_obf_observations_analysis_category", "obfuscation_observations",
                    ["analysis_id", "category"])

    op.create_table(
        "anti_analysis_indicators",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _analysis_fk(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("finding_type", sa.String(32), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("indicator", sa.String(256), nullable=False),
        sa.Column("target_type", sa.String(24), nullable=False, server_default="APK"),
        sa.Column("target", sa.String(1024), nullable=True),
        sa.Column("evidence_level", sa.String(20), nullable=False, server_default="INDICATOR"),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="LOW"),
        sa.Column("source_type", sa.String(24), nullable=False, server_default="STATIC_RULE"),
        sa.Column("source_id", sa.String(1024), nullable=True),
        sa.Column("evidence_json", sa.JSON(), nullable=True),
        sa.Column("uncertainties", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_anti_analysis_indicators_analysis_id", "anti_analysis_indicators", ["analysis_id"])
    op.create_index("ix_anti_analysis_indicators_fingerprint", "anti_analysis_indicators", ["fingerprint"])
    op.create_index("ix_anti_analysis_indicators_finding_type", "anti_analysis_indicators", ["finding_type"])
    op.create_index("ix_anti_analysis_indicators_category", "anti_analysis_indicators", ["category"])
    op.create_index("ix_anti_analysis_indicators_evidence_level", "anti_analysis_indicators", ["evidence_level"])
    op.create_index("ix_anti_analysis_analysis_category", "anti_analysis_indicators", ["analysis_id", "category"])

    op.create_table(
        "analysis_impacts",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _analysis_fk(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("impact_category", sa.String(40), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("affected_target", sa.String(1024), nullable=True),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("source_observation_fp", sa.String(64), nullable=True),
        sa.Column("evidence_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_analysis_impacts_analysis_id", "analysis_impacts", ["analysis_id"])
    op.create_index("ix_analysis_impacts_fingerprint", "analysis_impacts", ["fingerprint"])
    op.create_index("ix_analysis_impacts_impact_category", "analysis_impacts", ["impact_category"])
    op.create_index("ix_analysis_impacts_analysis_category", "analysis_impacts",
                    ["analysis_id", "impact_category"])


def downgrade() -> None:
    for table in ("analysis_impacts", "anti_analysis_indicators", "obfuscation_observations"):
        op.drop_table(table)

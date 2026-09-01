from alembic import op
import sqlalchemy as sa

revision = "0014_apk_diff"
down_revision = "0013_knowledge_graph"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def _cmp_fk() -> sa.ForeignKey:
    return sa.ForeignKey("analysis_comparisons.id", ondelete="CASCADE")


def upgrade() -> None:
    op.create_table(
        "analysis_comparisons",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("baseline_analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("candidate_analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("snapshot_a_id", _uuid(), sa.ForeignKey("graph_snapshots.id", ondelete="SET NULL"), nullable=True),
        sa.Column("snapshot_b_id", _uuid(), sa.ForeignKey("graph_snapshots.id", ondelete="SET NULL"), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="COMPLETE"),
        sa.Column("snapshot_mode", sa.String(16), nullable=False, server_default="RECONSTRUCTED"),
        sa.Column("security_impact", sa.String(32), nullable=False, server_default="NO_MATERIAL_SECURITY_CHANGE"),
        sa.Column("impact_confidence", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("requested_by", sa.String(128), nullable=False, server_default="cli"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("summary", sa.JSON(), nullable=True),
    )
    op.create_index("ix_analysis_comparisons_baseline", "analysis_comparisons", ["baseline_analysis_id"])
    op.create_index("ix_analysis_comparisons_candidate", "analysis_comparisons", ["candidate_analysis_id"])
    op.create_index("ix_analysis_comparisons_fingerprint", "analysis_comparisons", ["fingerprint"])
    op.create_index("ix_analysis_comparisons_status", "analysis_comparisons", ["status"])
    op.create_index("ix_analysis_comparisons_impact", "analysis_comparisons", ["security_impact"])
    op.create_index("ix_analysis_comparisons_pair", "analysis_comparisons",
                    ["baseline_analysis_id", "candidate_analysis_id"])

    op.create_table(
        "comparison_changes",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("comparison_id", _uuid(), _cmp_fk(), nullable=False),
        sa.Column("category", sa.String(24), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_identity", sa.String(1024), nullable=False),
        sa.Column("change_type", sa.String(16), nullable=False),
        sa.Column("baseline_value", sa.Text(), nullable=True),
        sa.Column("candidate_value", sa.Text(), nullable=True),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("security_relevant", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("provenance", sa.String(32), nullable=False, server_default="STATIC"),
        sa.Column("evidence", sa.JSON(), nullable=True),
    )
    op.create_index("ix_comparison_changes_comparison_id", "comparison_changes", ["comparison_id"])
    op.create_index("ix_comparison_changes_category", "comparison_changes", ["category"])
    op.create_index("ix_comparison_changes_entity_type", "comparison_changes", ["entity_type"])
    op.create_index("ix_comparison_changes_entity_identity", "comparison_changes", ["entity_identity"])
    op.create_index("ix_comparison_changes_change_type", "comparison_changes", ["change_type"])
    op.create_index("ix_comparison_changes_security_relevant", "comparison_changes", ["security_relevant"])
    op.create_index("ix_comparison_changes_cmp_cat", "comparison_changes", ["comparison_id", "category"])
    op.create_index("ix_comparison_changes_cmp_type", "comparison_changes", ["comparison_id", "change_type"])

    op.create_table(
        "comparison_findings",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("comparison_id", _uuid(), _cmp_fk(), nullable=False),
        sa.Column("change_type", sa.String(16), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("baseline_fingerprint", sa.String(64), nullable=True),
        sa.Column("candidate_fingerprint", sa.String(64), nullable=True),
        sa.Column("component", sa.String(1024), nullable=True),
        sa.Column("changed_dimensions", sa.JSON(), nullable=True),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("security_relevant", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("baseline_value", sa.JSON(), nullable=True),
        sa.Column("candidate_value", sa.JSON(), nullable=True),
    )
    op.create_index("ix_comparison_findings_comparison_id", "comparison_findings", ["comparison_id"])
    op.create_index("ix_comparison_findings_change_type", "comparison_findings", ["change_type"])
    op.create_index("ix_comparison_findings_rule_id", "comparison_findings", ["rule_id"])

    op.create_table(
        "comparison_risk_deltas",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("comparison_id", _uuid(), _cmp_fk(), nullable=False),
        sa.Column("baseline_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("candidate_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("delta", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("baseline_severity", sa.String(16), nullable=False, server_default="info"),
        sa.Column("candidate_severity", sa.String(16), nullable=False, server_default="info"),
        sa.Column("severity_transition", sa.String(48), nullable=False, server_default=""),
        sa.Column("baseline_confidence", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("candidate_confidence", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("confidence_transition", sa.String(48), nullable=False, server_default=""),
        sa.Column("factor_changes", sa.JSON(), nullable=True),
    )
    op.create_index("ix_comparison_risk_deltas_comparison_id", "comparison_risk_deltas", ["comparison_id"])

    op.create_table(
        "comparison_summaries",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("comparison_id", _uuid(), _cmp_fk(), nullable=False),
        sa.Column("category", sa.String(24), nullable=False),
        sa.Column("added", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("removed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("changed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unchanged", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("security_relevant", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_comparison_summaries_comparison_id", "comparison_summaries", ["comparison_id"])


def downgrade() -> None:
    for table in ("comparison_summaries", "comparison_risk_deltas", "comparison_findings",
                  "comparison_changes", "analysis_comparisons"):
        op.drop_table(table)

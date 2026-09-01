from alembic import op
import sqlalchemy as sa

revision = "0016_remediation"
down_revision = "0015_vuln_intel"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def _item_fk() -> sa.ForeignKey:
    return sa.ForeignKey("remediation_items.id", ondelete="CASCADE")


def upgrade() -> None:
    op.create_table(
        "remediation_plans",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="COMPLETE"),
        sa.Column("item_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("requested_by", sa.String(128), nullable=False, server_default="cli"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("priority_distribution", sa.JSON(), nullable=True),
        sa.Column("summary", sa.JSON(), nullable=True),
    )
    op.create_index("ix_remediation_plans_analysis_id", "remediation_plans", ["analysis_id"])
    op.create_index("ix_remediation_plans_fingerprint", "remediation_plans", ["fingerprint"])

    op.create_table(
        "remediation_items",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("plan_id", _uuid(), sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("priority", sa.String(16), nullable=False),
        sa.Column("priority_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("fixability", sa.String(24), nullable=False),
        sa.Column("source_category", sa.String(24), nullable=False),
        sa.Column("target", sa.String(1024), nullable=True),
        sa.Column("target_type", sa.String(24), nullable=False, server_default="FINDING"),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("current_state", sa.String(256), nullable=True),
        sa.Column("recommended_state", sa.String(512), nullable=True),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("uncertainties", sa.JSON(), nullable=True),
        sa.Column("priority_factors", sa.JSON(), nullable=True),
    )
    op.create_index("ix_remediation_items_plan_id", "remediation_items", ["plan_id"])
    op.create_index("ix_remediation_items_analysis_id", "remediation_items", ["analysis_id"])
    op.create_index("ix_remediation_items_fingerprint", "remediation_items", ["fingerprint"])
    op.create_index("ix_remediation_items_action", "remediation_items", ["action"])
    op.create_index("ix_remediation_items_status", "remediation_items", ["status"])
    op.create_index("ix_remediation_items_priority", "remediation_items", ["priority"])
    op.create_index("ix_remediation_items_fixability", "remediation_items", ["fixability"])
    op.create_index("ix_remediation_items_source_category", "remediation_items", ["source_category"])
    op.create_index("ix_remediation_items_plan_priority", "remediation_items", ["plan_id", "priority"])
    op.create_index("ix_remediation_items_analysis_action", "remediation_items", ["analysis_id", "action"])

    op.create_table(
        "remediation_evidence",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("item_id", _uuid(), _item_fk(), nullable=False),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("source_id", sa.String(1024), nullable=True),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence_json", sa.JSON(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_remediation_evidence_item_id", "remediation_evidence", ["item_id"])
    op.create_index("ix_remediation_evidence_source_type", "remediation_evidence", ["source_type"])

    op.create_table(
        "remediation_actions",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("item_id", _uuid(), _item_fk(), nullable=False),
        sa.Column("order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("target", sa.String(1024), nullable=True),
        sa.Column("recommended_state", sa.String(512), nullable=True),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_remediation_actions_item_id", "remediation_actions", ["item_id"])

    op.create_table(
        "remediation_dependencies",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("plan_id", _uuid(), sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("from_item_id", _uuid(), _item_fk(), nullable=False),
        sa.Column("to_item_id", _uuid(), _item_fk(), nullable=False),
        sa.Column("relation", sa.String(24), nullable=False, server_default="BLOCKED_BY"),
    )
    op.create_index("ix_remediation_dependencies_plan_id", "remediation_dependencies", ["plan_id"])


def downgrade() -> None:
    for table in ("remediation_dependencies", "remediation_actions", "remediation_evidence",
                  "remediation_items", "remediation_plans"):
        op.drop_table(table)

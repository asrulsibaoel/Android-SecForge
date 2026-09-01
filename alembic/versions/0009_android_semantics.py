from alembic import op
import sqlalchemy as sa

revision = "0009_android_semantics"
down_revision = "0008_reachability"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def _fk() -> sa.ForeignKey:
    return sa.ForeignKey("analyses.id", ondelete="CASCADE")


def upgrade() -> None:
    op.create_table(
        "android_entry_points",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("node_key", sa.String(1024), nullable=False),
        sa.Column("component", sa.String(512), nullable=False),
        sa.Column("component_type", sa.String(32), nullable=False),
        sa.Column("method", sa.String(128), nullable=False),
        sa.Column("lifecycle_event", sa.String(32), nullable=False),
        sa.Column("exported", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("permission", sa.String(512), nullable=True),
        sa.Column("intent_filters", sa.JSON(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="HIGH"),
    )
    op.create_index("ix_android_entry_points_analysis_id", "android_entry_points", ["analysis_id"])
    op.create_index("ix_android_entry_points_component", "android_entry_points", ["component"])

    op.create_table(
        "intents",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("operation", sa.String(32), nullable=False),
        sa.Column("action", sa.String(256), nullable=True),
        sa.Column("data_uri", sa.String(1024), nullable=True),
        sa.Column("categories", sa.JSON(), nullable=True),
        sa.Column("target_component", sa.String(512), nullable=True),
        sa.Column("target_package", sa.String(512), nullable=True),
        sa.Column("class_name", sa.String(512), nullable=True),
        sa.Column("method_name", sa.String(256), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_intents_analysis_id", "intents", ["analysis_id"])

    op.create_table(
        "deep_links",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("node_key", sa.String(1024), nullable=False),
        sa.Column("component", sa.String(512), nullable=False),
        sa.Column("scheme", sa.String(128), nullable=True),
        sa.Column("host", sa.String(256), nullable=True),
        sa.Column("port", sa.String(16), nullable=True),
        sa.Column("path", sa.String(512), nullable=True),
        sa.Column("path_prefix", sa.String(512), nullable=True),
        sa.Column("path_pattern", sa.String(512), nullable=True),
        sa.Column("mime_type", sa.String(256), nullable=True),
        sa.Column("action", sa.String(256), nullable=True),
        sa.Column("category", sa.String(256), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="HIGH"),
    )
    op.create_index("ix_deep_links_analysis_id", "deep_links", ["analysis_id"])

    op.create_table(
        "ipc_transactions",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("class_name", sa.String(512), nullable=True),
        sa.Column("method_name", sa.String(256), nullable=True),
        sa.Column("interface_name", sa.String(256), nullable=True),
        sa.Column("transaction_code", sa.String(256), nullable=True),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="LOW"),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_ipc_transactions_analysis_id", "ipc_transactions", ["analysis_id"])

    op.create_table(
        "security_boundaries",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("boundary_type", sa.String(32), nullable=False),
        sa.Column("component", sa.String(512), nullable=True),
        sa.Column("node_key", sa.String(1024), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
    )
    op.create_index("ix_security_boundaries_analysis_id", "security_boundaries", ["analysis_id"])
    op.create_index("ix_security_boundaries_type", "security_boundaries", ["boundary_type"])

    op.create_table(
        "semantic_edges",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("src_key", sa.String(1024), nullable=False),
        sa.Column("dst_key", sa.String(1024), nullable=False),
        sa.Column("edge_type", sa.String(32), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
    )
    op.create_index("ix_semantic_edges_analysis_id", "semantic_edges", ["analysis_id"])
    op.create_index("ix_semantic_edges_edge_type", "semantic_edges", ["edge_type"])


def downgrade() -> None:
    for table in (
        "semantic_edges",
        "security_boundaries",
        "ipc_transactions",
        "deep_links",
        "intents",
        "android_entry_points",
    ):
        op.drop_table(table)

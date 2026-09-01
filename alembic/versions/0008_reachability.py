from alembic import op
import sqlalchemy as sa

revision = "0008_reachability"
down_revision = "0007_native_analysis"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def _fk() -> sa.ForeignKey:
    return sa.ForeignKey("analyses.id", ondelete="CASCADE")


def upgrade() -> None:
    op.create_table(
        "code_nodes",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("node_key", sa.String(1024), nullable=False),
        sa.Column("node_type", sa.String(24), nullable=False),
        sa.Column("label", sa.String(512), nullable=False),
        sa.Column("class_name", sa.String(512), nullable=True),
        sa.Column("method_name", sa.String(256), nullable=True),
        sa.Column("source_file", sa.String(1024), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
    )
    op.create_index("ix_code_nodes_analysis_id", "code_nodes", ["analysis_id"])
    op.create_index("ix_code_nodes_node_key", "code_nodes", ["node_key"])
    op.create_index("ix_code_nodes_node_type", "code_nodes", ["node_type"])
    op.create_index("ix_code_nodes_analysis_type", "code_nodes", ["analysis_id", "node_type"])

    op.create_table(
        "code_edges",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("src_key", sa.String(1024), nullable=False),
        sa.Column("dst_key", sa.String(1024), nullable=False),
        sa.Column("edge_type", sa.String(24), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
    )
    op.create_index("ix_code_edges_analysis_id", "code_edges", ["analysis_id"])
    op.create_index("ix_code_edges_src_key", "code_edges", ["src_key"])
    op.create_index("ix_code_edges_dst_key", "code_edges", ["dst_key"])
    op.create_index("ix_code_edges_edge_type", "code_edges", ["edge_type"])
    op.create_index("ix_code_edges_analysis_src", "code_edges", ["analysis_id", "src_key"])

    op.create_table(
        "dataflow_sources",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("node_key", sa.String(1024), nullable=False),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("api", sa.String(128), nullable=False),
        sa.Column("class_name", sa.String(512), nullable=True),
        sa.Column("method_name", sa.String(256), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_dataflow_sources_analysis_id", "dataflow_sources", ["analysis_id"])

    op.create_table(
        "security_sinks",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("node_key", sa.String(1024), nullable=False),
        sa.Column("sink_type", sa.String(32), nullable=False),
        sa.Column("api", sa.String(128), nullable=False),
        sa.Column("category", sa.String(16), nullable=False, server_default="java"),
        sa.Column("class_name", sa.String(512), nullable=True),
        sa.Column("method_name", sa.String(256), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_security_sinks_analysis_id", "security_sinks", ["analysis_id"])

    op.create_table(
        "entry_points",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("node_key", sa.String(1024), nullable=False),
        sa.Column("component", sa.String(512), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("exported", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("permission", sa.String(512), nullable=True),
        sa.Column("intent_filters", sa.JSON(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_entry_points_analysis_id", "entry_points", ["analysis_id"])

    op.create_table(
        "reachability_paths",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=True),
        sa.Column("from_key", sa.String(1024), nullable=False),
        sa.Column("from_label", sa.String(512), nullable=False),
        sa.Column("to_key", sa.String(1024), nullable=False),
        sa.Column("to_label", sa.String(512), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("length", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("nodes", sa.JSON(), nullable=True),
        sa.Column("edges", sa.JSON(), nullable=True),
    )
    op.create_index("ix_reachability_paths_analysis_id", "reachability_paths", ["analysis_id"])
    op.create_index("ix_reachability_paths_rule_id", "reachability_paths", ["rule_id"])
    op.create_index("ix_reachability_paths_status", "reachability_paths", ["status"])


def downgrade() -> None:
    for table in (
        "reachability_paths",
        "entry_points",
        "security_sinks",
        "dataflow_sources",
        "code_edges",
        "code_nodes",
    ):
        op.drop_table(table)

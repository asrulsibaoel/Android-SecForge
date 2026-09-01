from alembic import op
import sqlalchemy as sa

revision = "0013_knowledge_graph"
down_revision = "0012_runtime_lab"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def _inv_fk() -> sa.ForeignKey:
    return sa.ForeignKey("investigations.id", ondelete="CASCADE")


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(256), nullable=False, server_default="Investigation"),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="cli"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_investigations_analysis_id", "investigations", ["analysis_id"])

    op.create_table(
        "investigation_nodes",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("investigation_id", _uuid(), _inv_fk(), nullable=False),
        sa.Column("node_ref", sa.String(1024), nullable=False),
        sa.Column("node_type", sa.String(32), nullable=False, server_default=""),
        sa.Column("label", sa.String(512), nullable=False, server_default=""),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_investigation_nodes_investigation_id", "investigation_nodes", ["investigation_id"])
    op.create_index("ix_investigation_nodes_node_ref", "investigation_nodes", ["node_ref"])
    op.create_index("ix_investigation_nodes_inv_ref", "investigation_nodes", ["investigation_id", "node_ref"])

    op.create_table(
        "investigation_edges",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("investigation_id", _uuid(), _inv_fk(), nullable=False),
        sa.Column("src_ref", sa.String(1024), nullable=False),
        sa.Column("dst_ref", sa.String(1024), nullable=False),
        sa.Column("edge_type", sa.String(32), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=True),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_investigation_edges_investigation_id", "investigation_edges", ["investigation_id"])
    op.create_index("ix_investigation_edges_fingerprint", "investigation_edges", ["fingerprint"])

    op.create_table(
        "investigation_findings",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("investigation_id", _uuid(), _inv_fk(), nullable=False),
        sa.Column("finding_id", _uuid(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_investigation_findings_investigation_id", "investigation_findings", ["investigation_id"])
    op.create_index("ix_investigation_findings_finding_id", "investigation_findings", ["finding_id"])

    op.create_table(
        "investigation_notes",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("investigation_id", _uuid(), _inv_fk(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False, server_default=""),
        sa.Column("author", sa.String(128), nullable=False, server_default="researcher"),
        sa.Column("target_ref", sa.String(1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_investigation_notes_investigation_id", "investigation_notes", ["investigation_id"])

    op.create_table(
        "investigation_hypotheses",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("investigation_id", _uuid(), _inv_fk(), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_investigation_hypotheses_investigation_id", "investigation_hypotheses", ["investigation_id"])

    op.create_table(
        "investigation_hypothesis_evidence",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("hypothesis_id", _uuid(),
                  sa.ForeignKey("investigation_hypotheses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ref_type", sa.String(24), nullable=False),
        sa.Column("ref_id", sa.String(1024), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_investigation_hypothesis_evidence_hypothesis_id",
                    "investigation_hypothesis_evidence", ["hypothesis_id"])

    op.create_table(
        "investigation_bookmarks",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("investigation_id", _uuid(), _inv_fk(), nullable=False),
        sa.Column("ref_type", sa.String(24), nullable=False),
        sa.Column("ref_id", sa.String(1024), nullable=False),
        sa.Column("label", sa.String(512), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_investigation_bookmarks_investigation_id", "investigation_bookmarks", ["investigation_id"])

    op.create_table(
        "investigation_timeline_events",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("investigation_id", _uuid(), _inv_fk(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("source", sa.String(24), nullable=False),
        sa.Column("entity_ref", sa.String(1024), nullable=True),
        sa.Column("evidence_ref", sa.String(1024), nullable=True),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("sequence", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_investigation_timeline_events_investigation_id",
                    "investigation_timeline_events", ["investigation_id"])
    op.create_index("ix_investigation_timeline_events_event_type",
                    "investigation_timeline_events", ["event_type"])
    op.create_index("ix_investigation_timeline_inv_seq",
                    "investigation_timeline_events", ["investigation_id", "sequence"])

    op.create_table(
        "graph_snapshots",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("graph_version", sa.String(32), nullable=False, server_default="kg/1"),
        sa.Column("node_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("edge_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("root_cause_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("runtime_observation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("node_type_counts", sa.JSON(), nullable=True),
        sa.Column("edge_type_counts", sa.JSON(), nullable=True),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_graph_snapshots_analysis_id", "graph_snapshots", ["analysis_id"])
    op.create_index("ix_graph_snapshots_digest", "graph_snapshots", ["digest"])
    op.create_index("ix_graph_snapshots_analysis_digest", "graph_snapshots", ["analysis_id", "digest"])


def downgrade() -> None:
    for table in ("graph_snapshots", "investigation_timeline_events", "investigation_bookmarks",
                  "investigation_hypothesis_evidence", "investigation_hypotheses", "investigation_notes",
                  "investigation_findings", "investigation_edges", "investigation_nodes", "investigations"):
        op.drop_table(table)

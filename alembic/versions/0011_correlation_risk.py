from alembic import op
import sqlalchemy as sa

revision = "0011_correlation_risk"
down_revision = "0010_dependency_cve"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def _fk() -> sa.ForeignKey:
    return sa.ForeignKey("analyses.id", ondelete="CASCADE")


def upgrade() -> None:
    # root_causes must exist before the findings FK is added.
    op.create_table(
        "root_causes",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("identifier", sa.String(128), nullable=False),
        sa.Column("category", sa.String(48), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("severity_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("confidence_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("affected_components", sa.JSON(), nullable=True),
        sa.Column("affected_code_nodes", sa.JSON(), nullable=True),
        sa.Column("affected_dependencies", sa.JSON(), nullable=True),
        sa.Column("boundaries", sa.JSON(), nullable=True),
        sa.Column("paths", sa.JSON(), nullable=True),
    )
    op.create_index("ix_root_causes_analysis_id", "root_causes", ["analysis_id"])
    op.create_index("ix_root_causes_identifier", "root_causes", ["identifier"])
    op.create_index("ix_root_causes_category", "root_causes", ["category"])

    # Extend findings with correlation/risk columns.
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("fingerprint", sa.String(64), nullable=True))
        batch.add_column(sa.Column("is_duplicate", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("primary_target", sa.String(1024), nullable=True))
        batch.add_column(sa.Column("severity_score", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("confidence_score", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("root_cause_id", _uuid(),
                                   sa.ForeignKey("root_causes.id", ondelete="SET NULL",
                                                 name="fk_findings_root_cause_id"), nullable=True))
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.create_index("ix_findings_root_cause_id", "findings", ["root_cause_id"])

    op.create_table(
        "finding_correlations",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("finding_id", _uuid(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("dimension", sa.String(32), nullable=False),
        sa.Column("correlation_key", sa.String(512), nullable=False),
    )
    op.create_index("ix_finding_correlations_analysis_id", "finding_correlations", ["analysis_id"])
    op.create_index("ix_finding_correlations_finding_id", "finding_correlations", ["finding_id"])
    op.create_index("ix_finding_correlations_dimension", "finding_correlations", ["dimension"])
    op.create_index("ix_finding_correlations_correlation_key", "finding_correlations", ["correlation_key"])
    op.create_index("ix_finding_correlations_dim_key", "finding_correlations",
                    ["analysis_id", "dimension", "correlation_key"])

    op.create_table(
        "root_cause_findings",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("root_cause_id", _uuid(), sa.ForeignKey("root_causes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", _uuid(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=False),
    )
    op.create_index("ix_root_cause_findings_rc", "root_cause_findings", ["root_cause_id"])
    op.create_index("ix_root_cause_findings_finding", "root_cause_findings", ["finding_id"])

    op.create_table(
        "root_cause_evidence",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("root_cause_id", _uuid(), sa.ForeignKey("root_causes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("reference", sa.String(1024), nullable=True),
    )
    op.create_index("ix_root_cause_evidence_rc", "root_cause_evidence", ["root_cause_id"])

    op.create_table(
        "attack_surface_nodes",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("node_key", sa.String(1024), nullable=False),
        sa.Column("node_type", sa.String(32), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("exposure", sa.String(24), nullable=False),
        sa.Column("component", sa.String(512), nullable=True),
        sa.Column("permission", sa.String(512), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_attack_surface_nodes_analysis_id", "attack_surface_nodes", ["analysis_id"])
    op.create_index("ix_attack_surface_nodes_node_key", "attack_surface_nodes", ["node_key"])
    op.create_index("ix_attack_surface_nodes_node_type", "attack_surface_nodes", ["node_type"])
    op.create_index("ix_attack_surface_nodes_exposure", "attack_surface_nodes", ["exposure"])
    op.create_index("ix_attack_surface_nodes_analysis_type", "attack_surface_nodes", ["analysis_id", "node_type"])

    op.create_table(
        "attack_surface_edges",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("src_key", sa.String(1024), nullable=False),
        sa.Column("dst_key", sa.String(1024), nullable=False),
        sa.Column("edge_type", sa.String(32), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
    )
    op.create_index("ix_attack_surface_edges_analysis_id", "attack_surface_edges", ["analysis_id"])

    op.create_table(
        "risk_assessments",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), _fk(), nullable=False),
        sa.Column("scope", sa.String(512), nullable=False, server_default="overall"),
        sa.Column("overall_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("severity_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("confidence_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary", sa.JSON(), nullable=True),
    )
    op.create_index("ix_risk_assessments_analysis_id", "risk_assessments", ["analysis_id"])
    op.create_index("ix_risk_assessments_scope", "risk_assessments", ["scope"])

    op.create_table(
        "risk_factors",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("assessment_id", _uuid(), sa.ForeignKey("risk_assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("weight", sa.Integer(), nullable=False),
        sa.Column("direction", sa.String(8), nullable=False),
        sa.Column("category", sa.String(32), nullable=False, server_default=""),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_risk_factors_assessment", "risk_factors", ["assessment_id"])


def downgrade() -> None:
    for table in ("risk_factors", "risk_assessments", "attack_surface_edges", "attack_surface_nodes",
                  "root_cause_evidence", "root_cause_findings", "finding_correlations"):
        op.drop_table(table)
    with op.batch_alter_table("findings") as batch:
        for col in ("root_cause_id", "confidence_score", "severity_score", "primary_target",
                    "is_duplicate", "fingerprint"):
            batch.drop_column(col)
    op.drop_table("root_causes")

from alembic import op
import sqlalchemy as sa

revision = "0021_assessment"
down_revision = "0020_runtime_validation"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def _cfk() -> sa.ForeignKey:
    return sa.ForeignKey("security_conclusions.id", ondelete="CASCADE")


def _akfk() -> sa.ForeignKey:
    return sa.ForeignKey("assessments.id", ondelete="CASCADE")


def upgrade() -> None:
    op.create_table(
        "assessments",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("status", sa.String(28), nullable=False, server_default="ASSESSMENT_INCONCLUSIVE"),
        sa.Column("subject_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("conclusion_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("blocker_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("truncated", sa.JSON(), nullable=True),
        sa.Column("summary", sa.JSON(), nullable=True),
        sa.Column("requested_by", sa.String(128), nullable=False, server_default="cli"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_assessments_analysis_id", "assessments", ["analysis_id"])
    op.create_index("ix_assessments_fingerprint", "assessments", ["fingerprint"])

    op.create_table(
        "assessment_subjects",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("assessment_id", _uuid(), _akfk(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("subject_type", sa.String(24), nullable=False),
        sa.Column("subject_ref", sa.String(1024), nullable=False),
        sa.Column("label", sa.String(512), nullable=False, server_default=""),
    )
    op.create_index("ix_assessment_subjects_assessment_id", "assessment_subjects", ["assessment_id"])
    op.create_index("ix_assessment_subjects_type", "assessment_subjects", ["subject_type"])
    op.create_index("ix_assessment_subjects_fingerprint", "assessment_subjects", ["fingerprint"])

    op.create_table(
        "security_conclusions",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("assessment_id", _uuid(), _akfk(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("subject_type", sa.String(24), nullable=False),
        sa.Column("subject_ref", sa.String(1024), nullable=False),
        sa.Column("conclusion_type", sa.String(48), nullable=False),
        sa.Column("decision_state", sa.String(28), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
        sa.Column("rule_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_security_conclusions_assessment_id", "security_conclusions", ["assessment_id"])
    op.create_index("ix_security_conclusions_fingerprint", "security_conclusions", ["fingerprint"])
    op.create_index("ix_security_conclusions_conclusion_type", "security_conclusions", ["conclusion_type"])
    op.create_index("ix_security_conclusions_decision_state", "security_conclusions", ["decision_state"])
    op.create_index("ix_security_conclusions_state", "security_conclusions", ["assessment_id", "decision_state"])

    op.create_table(
        "decision_evidence",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("conclusion_id", _uuid(), _cfk(), nullable=False),
        sa.Column("source_layer", sa.String(24), nullable=False),
        sa.Column("evidence_ref", sa.String(1024), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False, server_default="STATIC"),
        sa.Column("provenance", sa.String(32), nullable=False, server_default="STATIC"),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_decision_evidence_conclusion_id", "decision_evidence", ["conclusion_id"])
    op.create_index("ix_decision_evidence_source_layer", "decision_evidence", ["source_layer"])

    op.create_table(
        "decision_blockers",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("conclusion_id", _uuid(), _cfk(), nullable=False),
        sa.Column("blocker", sa.String(48), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("missing", sa.String(256), nullable=False, server_default=""),
    )
    op.create_index("ix_decision_blockers_conclusion_id", "decision_blockers", ["conclusion_id"])

    op.create_table(
        "decision_requirements",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("conclusion_id", _uuid(), _cfk(), nullable=False),
        sa.Column("requirement", sa.String(64), nullable=False),
        sa.Column("satisfied", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_decision_requirements_conclusion_id", "decision_requirements", ["conclusion_id"])

    op.create_table(
        "decision_dependencies",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("conclusion_id", _uuid(), _cfk(), nullable=False),
        sa.Column("depends_on", sa.String(1024), nullable=False),
        sa.Column("dependency_type", sa.String(32), nullable=False, server_default="CONCLUSION"),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_decision_dependencies_conclusion_id", "decision_dependencies", ["conclusion_id"])

    op.create_table(
        "assessment_transitions",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("assessment_id", _uuid(), _akfk(), nullable=False),
        sa.Column("subject_ref", sa.String(1024), nullable=False),
        sa.Column("transition", sa.String(48), nullable=False),
        sa.Column("from_state", sa.String(28), nullable=True),
        sa.Column("to_state", sa.String(28), nullable=True),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_assessment_transitions_assessment_id", "assessment_transitions", ["assessment_id"])

    op.create_table(
        "assessment_summaries",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("assessment_id", _uuid(), _akfk(), nullable=False),
        sa.Column("dimension", sa.String(32), nullable=False),
        sa.Column("counts", sa.JSON(), nullable=True),
    )
    op.create_index("ix_assessment_summaries_assessment_id", "assessment_summaries", ["assessment_id"])


def downgrade() -> None:
    for table in ("assessment_summaries", "assessment_transitions", "decision_dependencies",
                  "decision_requirements", "decision_blockers", "decision_evidence",
                  "security_conclusions", "assessment_subjects", "assessments"):
        op.drop_table(table)

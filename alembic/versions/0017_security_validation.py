from alembic import op
import sqlalchemy as sa

revision = "0017_security_validation"
down_revision = "0016_remediation"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def _claim_fk() -> sa.ForeignKey:
    return sa.ForeignKey("validation_claims.id", ondelete="CASCADE")


def upgrade() -> None:
    # --- additive finding columns (distinct from runtime validation_state) ---
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("security_validation_state", sa.String(28), nullable=False,
                                   server_default="UNVERIFIED"))
        batch.add_column(sa.Column("validation_confidence", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("validation_claim_count", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("validation_evidence_count", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("validation_blocker_count", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("validation_summary", sa.Text(), nullable=True))

    op.create_table(
        "validation_claims",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", _uuid(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=True),
        sa.Column("remediation_ref", sa.String(64), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("claim_type", sa.String(40), nullable=False),
        sa.Column("target_type", sa.String(24), nullable=False, server_default="FINDING"),
        sa.Column("target", sa.String(1024), nullable=True),
        sa.Column("current_state", sa.String(256), nullable=True),
        sa.Column("validation_state", sa.String(28), nullable=False, server_default="UNVERIFIED"),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evidence_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("independent_source_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source_families", sa.JSON(), nullable=True),
        sa.Column("required_capabilities", sa.JSON(), nullable=True),
        sa.Column("missing_evidence", sa.JSON(), nullable=True),
        sa.Column("uncertainty", sa.JSON(), nullable=True),
        sa.Column("provenance", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_validation_claims_analysis_id", "validation_claims", ["analysis_id"])
    op.create_index("ix_validation_claims_finding_id", "validation_claims", ["finding_id"])
    op.create_index("ix_validation_claims_fingerprint", "validation_claims", ["fingerprint"])
    op.create_index("ix_validation_claims_claim_type", "validation_claims", ["claim_type"])
    op.create_index("ix_validation_claims_validation_state", "validation_claims", ["validation_state"])
    op.create_index("ix_validation_claims_analysis_type", "validation_claims", ["analysis_id", "claim_type"])
    op.create_index("ix_validation_claims_analysis_state", "validation_claims", ["analysis_id", "validation_state"])

    op.create_table(
        "validation_evidence",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("claim_id", _uuid(), _claim_fk(), nullable=False),
        sa.Column("source_family", sa.String(28), nullable=False),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("source_id", sa.String(1024), nullable=True),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("live", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence_json", sa.JSON(), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
    )
    op.create_index("ix_validation_evidence_claim_id", "validation_evidence", ["claim_id"])
    op.create_index("ix_validation_evidence_source_family", "validation_evidence", ["source_family"])
    op.create_index("ix_validation_evidence_fingerprint", "validation_evidence", ["fingerprint"])

    op.create_table(
        "validation_blockers",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("claim_id", _uuid(), _claim_fk(), nullable=False),
        sa.Column("blocker", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("missing", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_validation_blockers_claim_id", "validation_blockers", ["claim_id"])
    op.create_index("ix_validation_blockers_blocker", "validation_blockers", ["blocker"])

    op.create_table(
        "validation_requirements",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("claim_id", _uuid(), _claim_fk(), nullable=False),
        sa.Column("requirement", sa.String(48), nullable=False),
        sa.Column("satisfied", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_validation_requirements_claim_id", "validation_requirements", ["claim_id"])

    op.create_table(
        "validation_transitions",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=True),
        sa.Column("comparison_id", _uuid(), sa.ForeignKey("analysis_comparisons.id", ondelete="CASCADE"),
                  nullable=True),
        sa.Column("claim_fingerprint", sa.String(64), nullable=False),
        sa.Column("baseline_state", sa.String(28), nullable=False),
        sa.Column("candidate_state", sa.String(28), nullable=False),
        sa.Column("transition", sa.String(48), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_validation_transitions_analysis_id", "validation_transitions", ["analysis_id"])
    op.create_index("ix_validation_transitions_comparison_id", "validation_transitions", ["comparison_id"])
    op.create_index("ix_validation_transitions_claim_fingerprint", "validation_transitions", ["claim_fingerprint"])


def downgrade() -> None:
    for table in ("validation_transitions", "validation_requirements", "validation_blockers",
                  "validation_evidence", "validation_claims"):
        op.drop_table(table)
    with op.batch_alter_table("findings") as batch:
        for col in ("validation_summary", "validation_blocker_count", "validation_evidence_count",
                    "validation_claim_count", "validation_confidence", "security_validation_state"):
            batch.drop_column(col)

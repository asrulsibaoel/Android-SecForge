from alembic import op
import sqlalchemy as sa

revision = "0006_relational_analysis"
down_revision = "0005_dex_inventory"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    # SQLAlchemy 2.0 Uuid renders as native UUID on Postgres and CHAR(32) on SQLite.
    return sa.Uuid()


def upgrade() -> None:
    op.create_table(
        "analyses",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("apk_id", _uuid(), sa.ForeignKey("apk_artifacts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("apk_sha256", sa.String(64), nullable=False),
        sa.Column("profile", sa.String(32), nullable=False, server_default="static"),
        sa.Column("status", sa.String(16), nullable=False, server_default="PARTIAL"),
        sa.Column("ruleset_version", sa.String(32), nullable=True),
        sa.Column("tool_versions", sa.JSON(), nullable=True),
        sa.Column("capabilities", sa.JSON(), nullable=True),
        sa.Column("stages", sa.JSON(), nullable=True),
        sa.Column("errors", sa.JSON(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_analyses_apk_id", "analyses", ["apk_id"])
    op.create_index("ix_analyses_apk_sha256", "analyses", ["apk_sha256"])

    op.create_table(
        "artifacts",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("path", sa.String(1024), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
    )
    op.create_index("ix_artifacts_analysis_id", "artifacts", ["analysis_id"])
    op.create_index("ix_artifacts_sha256", "artifacts", ["sha256"])

    op.create_table(
        "manifests",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("source_format", sa.String(16), nullable=False),
        sa.Column("package", sa.String(512), nullable=True),
        sa.Column("version_name", sa.String(256), nullable=True),
        sa.Column("version_code", sa.String(256), nullable=True),
        sa.Column("min_sdk", sa.String(16), nullable=True),
        sa.Column("target_sdk", sa.String(16), nullable=True),
        sa.Column("compile_sdk", sa.String(16), nullable=True),
        sa.Column("debuggable", sa.Boolean(), nullable=True),
        sa.Column("allow_backup", sa.Boolean(), nullable=True),
        sa.Column("uses_cleartext_traffic", sa.Boolean(), nullable=True),
        sa.Column("network_security_config", sa.String(512), nullable=True),
    )
    op.create_index("ix_manifests_analysis_id", "manifests", ["analysis_id"])

    op.create_table(
        "permissions",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("protection_level", sa.String(32), nullable=False),
        sa.Column("permission_group", sa.String(64), nullable=True),
        sa.Column("is_dangerous", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_custom", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_permissions_analysis_id", "permissions", ["analysis_id"])

    op.create_table(
        "components",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("name", sa.String(512), nullable=True),
        sa.Column("exported", sa.Boolean(), nullable=True),
        sa.Column("explicit_exported", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("effective_exported", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("exposure", sa.String(32), nullable=False, server_default="INTERNAL"),
        sa.Column("permission", sa.String(512), nullable=True),
        sa.Column("authorities", sa.String(512), nullable=True),
        sa.Column("intent_filters", sa.JSON(), nullable=True),
    )
    op.create_index("ix_components_analysis_id", "components", ["analysis_id"])

    op.create_table(
        "dex_artifacts",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("archive_path", sa.String(512), nullable=False),
        sa.Column("filename", sa.String(256), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("valid", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("class_count", sa.Integer(), nullable=True),
        sa.Column("method_count", sa.Integer(), nullable=True),
        sa.Column("field_count", sa.Integer(), nullable=True),
        sa.Column("string_count", sa.Integer(), nullable=True),
        sa.Column("workspace_path", sa.String(1024), nullable=True),
    )
    op.create_index("ix_dex_artifacts_analysis_id", "dex_artifacts", ["analysis_id"])
    op.create_index("ix_dex_artifacts_sha256", "dex_artifacts", ["sha256"])

    op.create_table(
        "code_entities",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entity_type", sa.String(16), nullable=False),
        sa.Column("package", sa.String(512), nullable=True),
        sa.Column("class_name", sa.String(512), nullable=True),
        sa.Column("name", sa.String(512), nullable=True),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("superclass", sa.String(512), nullable=True),
        sa.Column("interfaces", sa.JSON(), nullable=True),
        sa.Column("source_file", sa.String(1024), nullable=True),
    )
    op.create_index("ix_code_entities_analysis_id", "code_entities", ["analysis_id"])
    op.create_index("ix_code_entities_class_name", "code_entities", ["class_name"])
    op.create_index("ix_code_entities_name", "code_entities", ["name"])
    op.create_index("ix_code_entities_class_name_name", "code_entities", ["class_name", "name"])

    op.create_table(
        "findings",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("remediation", sa.Text(), nullable=False, server_default=""),
        sa.Column("references", sa.JSON(), nullable=True),
        sa.Column("component", sa.String(512), nullable=True),
    )
    op.create_index("ix_findings_analysis_id", "findings", ["analysis_id"])
    op.create_index("ix_findings_rule_id", "findings", ["rule_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_findings_severity_status", "findings", ["severity", "status"])

    op.create_table(
        "evidence",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("finding_id", _uuid(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("location", sa.String(1024), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("artifact", sa.String(1024), nullable=True),
        sa.Column("class_name", sa.String(512), nullable=True),
        sa.Column("method_name", sa.String(512), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
    )
    op.create_index("ix_evidence_finding_id", "evidence", ["finding_id"])


def downgrade() -> None:
    for table in (
        "evidence",
        "findings",
        "code_entities",
        "dex_artifacts",
        "components",
        "permissions",
        "manifests",
        "artifacts",
        "analyses",
    ):
        op.drop_table(table)

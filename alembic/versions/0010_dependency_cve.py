from alembic import op
import sqlalchemy as sa

revision = "0010_dependency_cve"
down_revision = "0009_android_semantics"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def upgrade() -> None:
    op.create_table(
        "vulnerabilities",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("cve_id", sa.String(64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("published_at", sa.String(32), nullable=True),
        sa.Column("modified_at", sa.String(32), nullable=True),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(128), nullable=True),
        sa.Column("cwe", sa.String(64), nullable=True),
        sa.Column("source", sa.String(32), nullable=False, server_default="local"),
        sa.Column("source_id", sa.String(128), nullable=True),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_test_data", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"])
    op.create_index("ix_vulnerabilities_source", "vulnerabilities", ["source"])
    op.create_index("ix_vulnerabilities_is_test_data", "vulnerabilities", ["is_test_data"])

    op.create_table(
        "vulnerability_references",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("vulnerability_id", _uuid(), sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("url", sa.String(1024), nullable=False),
        sa.Column("ref_type", sa.String(64), nullable=True),
    )
    op.create_index("ix_vulnerability_references_vuln", "vulnerability_references", ["vulnerability_id"])

    op.create_table(
        "affected_products",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("vulnerability_id", _uuid(), sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ecosystem", sa.String(32), nullable=False),
        sa.Column("vendor", sa.String(256), nullable=True),
        sa.Column("product", sa.String(256), nullable=False),
        sa.Column("cpe", sa.String(512), nullable=True),
        sa.Column("package_name", sa.String(512), nullable=True),
        sa.Column("version_strategy", sa.String(16), nullable=False, server_default="GENERIC"),
    )
    op.create_index("ix_affected_products_vuln", "affected_products", ["vulnerability_id"])
    op.create_index("ix_affected_products_ecosystem", "affected_products", ["ecosystem"])
    op.create_index("ix_affected_products_product", "affected_products", ["product"])
    op.create_index("ix_affected_products_package_name", "affected_products", ["package_name"])
    op.create_index("ix_affected_products_eco_product", "affected_products", ["ecosystem", "product"])

    op.create_table(
        "affected_version_ranges",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("product_id", _uuid(), sa.ForeignKey("affected_products.id", ondelete="CASCADE"), nullable=False),
        sa.Column("introduced", sa.String(64), nullable=True),
        sa.Column("fixed", sa.String(64), nullable=True),
        sa.Column("last_affected", sa.String(64), nullable=True),
        sa.Column("exact", sa.String(64), nullable=True),
        sa.Column("raw", sa.String(256), nullable=True),
    )
    op.create_index("ix_affected_version_ranges_product", "affected_version_ranges", ["product_id"])

    op.create_table(
        "dependencies",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("product", sa.String(256), nullable=True),
        sa.Column("package_prefix", sa.String(256), nullable=True),
        sa.Column("ecosystem", sa.String(32), nullable=False),
        sa.Column("version", sa.String(64), nullable=True),
        sa.Column("version_source", sa.String(64), nullable=True),
        sa.Column("version_strategy", sa.String(16), nullable=False, server_default="GENERIC"),
        sa.Column("architecture", sa.String(16), nullable=True),
        sa.Column("artifact", sa.String(1024), nullable=True),
        sa.Column("kind", sa.String(16), nullable=False, server_default="java"),
        sa.Column("bundled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("identity_confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
        sa.Column("version_confidence", sa.String(8), nullable=False, server_default="UNKNOWN"),
        sa.Column("cpe", sa.String(512), nullable=True),
    )
    op.create_index("ix_dependencies_analysis_id", "dependencies", ["analysis_id"])
    op.create_index("ix_dependencies_name", "dependencies", ["name"])
    op.create_index("ix_dependencies_ecosystem", "dependencies", ["ecosystem"])
    op.create_index("ix_dependencies_analysis_eco", "dependencies", ["analysis_id", "ecosystem"])

    op.create_table(
        "dependency_evidence",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("dependency_id", _uuid(), sa.ForeignKey("dependencies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("location", sa.String(1024), nullable=True),
    )
    op.create_index("ix_dependency_evidence_dependency", "dependency_evidence", ["dependency_id"])

    op.create_table(
        "vulnerability_matches",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("dependency_id", _uuid(), sa.ForeignKey("dependencies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vulnerability_id", _uuid(), sa.ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True),
        sa.Column("cve_id", sa.String(64), nullable=False),
        sa.Column("match_method", sa.String(16), nullable=False, server_default="EXACT"),
        sa.Column("match_confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
        sa.Column("version_state", sa.String(24), nullable=False),
        sa.Column("correlation_state", sa.String(32), nullable=False),
        sa.Column("reachability_state", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
    )
    op.create_index("ix_vulnerability_matches_analysis_id", "vulnerability_matches", ["analysis_id"])
    op.create_index("ix_vulnerability_matches_dependency", "vulnerability_matches", ["dependency_id"])
    op.create_index("ix_vulnerability_matches_cve_id", "vulnerability_matches", ["cve_id"])
    op.create_index("ix_vuln_matches_analysis_state", "vulnerability_matches", ["analysis_id", "correlation_state"])


def downgrade() -> None:
    for table in (
        "vulnerability_matches",
        "dependency_evidence",
        "dependencies",
        "affected_version_ranges",
        "affected_products",
        "vulnerability_references",
        "vulnerabilities",
    ):
        op.drop_table(table)

from alembic import op
import sqlalchemy as sa

revision = "0015_vuln_intel"
down_revision = "0014_apk_diff"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def _vuln_fk() -> sa.ForeignKey:
    return sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE")


def upgrade() -> None:
    # --- new columns on existing tables (named FKs not required: no FK added) ---
    with op.batch_alter_table("vulnerabilities") as batch:
        batch.add_column(sa.Column("withdrawn_at", sa.String(32), nullable=True))
        batch.add_column(sa.Column("provider_modified_at", sa.String(32), nullable=True))
        batch.add_column(sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("known_exploited", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("epss_score", sa.Float(), nullable=True))
        batch.add_column(sa.Column("epss_percentile", sa.Float(), nullable=True))
        batch.add_column(sa.Column("bundle_version", sa.String(64), nullable=True))
    op.create_index("ix_vulnerabilities_known_exploited", "vulnerabilities", ["known_exploited"])

    with op.batch_alter_table("affected_products") as batch:
        batch.add_column(sa.Column("purl", sa.String(512), nullable=True))

    with op.batch_alter_table("vulnerability_matches") as batch:
        batch.add_column(sa.Column("identity_confidence", sa.String(8), nullable=False, server_default="MEDIUM"))
        batch.add_column(sa.Column("signature_state", sa.String(24), nullable=False, server_default="NO_SIGNATURE"))
        batch.add_column(sa.Column("earliest_fixed_version", sa.String(64), nullable=True))
        batch.add_column(sa.Column("fixed_versions", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("providers", sa.JSON(), nullable=True))

    # --- new intelligence tables ---
    op.create_table(
        "vulnerability_aliases",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("vulnerability_id", _uuid(), _vuln_fk(), nullable=False),
        sa.Column("alias", sa.String(64), nullable=False),
    )
    op.create_index("ix_vulnerability_aliases_vulnerability_id", "vulnerability_aliases", ["vulnerability_id"])
    op.create_index("ix_vulnerability_aliases_alias", "vulnerability_aliases", ["alias"])

    op.create_table(
        "vulnerability_identities",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("vulnerability_id", _uuid(), _vuln_fk(), nullable=False),
        sa.Column("identity_type", sa.String(16), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("ecosystem", sa.String(32), nullable=True),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
    )
    op.create_index("ix_vulnerability_identities_vulnerability_id", "vulnerability_identities", ["vulnerability_id"])
    op.create_index("ix_vulnerability_identities_type", "vulnerability_identities", ["identity_type"])
    op.create_index("ix_vulnerability_identities_value", "vulnerability_identities", ["value"])
    op.create_index("ix_vuln_identities_type_value", "vulnerability_identities", ["identity_type", "value"])

    op.create_table(
        "vulnerability_signatures",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("vulnerability_id", _uuid(), _vuln_fk(), nullable=False),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("package", sa.String(512), nullable=True),
        sa.Column("class_name", sa.String(512), nullable=True),
        sa.Column("method", sa.String(256), nullable=True),
        sa.Column("descriptor", sa.String(512), nullable=True),
        sa.Column("field", sa.String(256), nullable=True),
        sa.Column("native_symbol", sa.String(512), nullable=True),
        sa.Column("api_sequence", sa.JSON(), nullable=True),
        sa.Column("provider", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("confidence", sa.String(8), nullable=False, server_default="MEDIUM"),
    )
    op.create_index("ix_vulnerability_signatures_vulnerability_id", "vulnerability_signatures", ["vulnerability_id"])
    op.create_index("ix_vulnerability_signatures_kind", "vulnerability_signatures", ["kind"])
    op.create_index("ix_vulnerability_signatures_package", "vulnerability_signatures", ["package"])
    op.create_index("ix_vulnerability_signatures_class_name", "vulnerability_signatures", ["class_name"])
    op.create_index("ix_vulnerability_signatures_native_symbol", "vulnerability_signatures", ["native_symbol"])
    op.create_index("ix_vuln_signatures_kind", "vulnerability_signatures", ["kind"])

    op.create_table(
        "vulnerability_scores",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("vulnerability_id", _uuid(), _vuln_fk(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("vector", sa.String(128), nullable=True),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("percentile", sa.Float(), nullable=True),
        sa.Column("extra", sa.JSON(), nullable=True),
    )
    op.create_index("ix_vulnerability_scores_vulnerability_id", "vulnerability_scores", ["vulnerability_id"])
    op.create_index("ix_vulnerability_scores_kind", "vulnerability_scores", ["kind"])
    op.create_index("ix_vuln_scores_kind", "vulnerability_scores", ["kind"])

    op.create_table(
        "vulnerability_provider_records",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("vulnerability_id", _uuid(), _vuln_fk(), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("provider_record_id", sa.String(128), nullable=True),
        sa.Column("modified_at", sa.String(32), nullable=True),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("raw_excerpt", sa.Text(), nullable=True),
    )
    op.create_index("ix_vulnerability_provider_records_vulnerability_id",
                    "vulnerability_provider_records", ["vulnerability_id"])
    op.create_index("ix_vulnerability_provider_records_provider", "vulnerability_provider_records", ["provider"])

    op.create_table(
        "intel_bundles",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("bundle_version", sa.String(64), nullable=False, server_default="1"),
        sa.Column("checksum", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="COMPLETE"),
        sa.Column("vulnerability_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("identity_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("signature_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("providers", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_intel_bundles_name", "intel_bundles", ["name"])


def downgrade() -> None:
    for table in ("intel_bundles", "vulnerability_provider_records", "vulnerability_scores",
                  "vulnerability_signatures", "vulnerability_identities", "vulnerability_aliases"):
        op.drop_table(table)
    with op.batch_alter_table("vulnerability_matches") as batch:
        for col in ("providers", "fixed_versions", "earliest_fixed_version", "signature_state", "identity_confidence"):
            batch.drop_column(col)
    with op.batch_alter_table("affected_products") as batch:
        batch.drop_column("purl")
    op.drop_index("ix_vulnerabilities_known_exploited", table_name="vulnerabilities")
    with op.batch_alter_table("vulnerabilities") as batch:
        for col in ("bundle_version", "epss_percentile", "epss_score", "known_exploited",
                    "last_seen", "first_seen", "provider_modified_at", "withdrawn_at"):
            batch.drop_column(col)

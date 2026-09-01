from alembic import op
import sqlalchemy as sa

revision = "0001_apk_artifacts"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "apk_artifacts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("original_filename", sa.String(512), nullable=False),
        sa.Column("storage_path", sa.String(1024), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("sha1", sa.String(40), nullable=False),
        sa.Column("md5", sa.String(32), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("package_name", sa.String(512)),
        sa.Column("version_name", sa.String(256)),
        sa.Column("version_code", sa.String(256)),
        sa.Column("manifest_status", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notes", sa.Text()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sha256"),
        sa.UniqueConstraint("storage_path"),
    )
    op.create_index("ix_apk_artifacts_sha256", "apk_artifacts", ["sha256"])


def downgrade() -> None:
    op.drop_index("ix_apk_artifacts_sha256", table_name="apk_artifacts")
    op.drop_table("apk_artifacts")
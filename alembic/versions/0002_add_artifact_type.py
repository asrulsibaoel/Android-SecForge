from alembic import op
import sqlalchemy as sa

revision = "0002_artifact_type"
down_revision = "0001_apk_artifacts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "apk_artifacts",
        sa.Column("artifact_type", sa.String(8), nullable=False, server_default="apk"),
    )


def downgrade() -> None:
    op.drop_column("apk_artifacts", "artifact_type")
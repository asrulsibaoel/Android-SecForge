from alembic import op
import sqlalchemy as sa

revision = "0003_inspection_data"
down_revision = "0002_artifact_type"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("apk_artifacts", sa.Column("structure", sa.JSON(), nullable=True))
    op.add_column("apk_artifacts", sa.Column("manifest", sa.JSON(), nullable=True))
    op.add_column("apk_artifacts", sa.Column("findings", sa.JSON(), nullable=True))
    op.add_column("apk_artifacts", sa.Column("framework", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("apk_artifacts", "findings")
    op.drop_column("apk_artifacts", "manifest")
    op.drop_column("apk_artifacts", "structure")
    op.drop_column("apk_artifacts", "framework")
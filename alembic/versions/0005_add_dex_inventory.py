from alembic import op
import sqlalchemy as sa

revision = "0005_dex_inventory"
down_revision = "0004_ipc_data"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("apk_artifacts", sa.Column("dex", sa.JSON(), nullable=True))
    op.add_column("apk_artifacts", sa.Column("workspace_path", sa.String(1024), nullable=True))


def downgrade() -> None:
    op.drop_column("apk_artifacts", "workspace_path")
    op.drop_column("apk_artifacts", "dex")
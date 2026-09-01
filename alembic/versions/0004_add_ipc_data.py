from alembic import op
import sqlalchemy as sa

revision = "0004_ipc_data"
down_revision = "0003_inspection_data"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("apk_artifacts", sa.Column("ipc", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("apk_artifacts", "ipc")
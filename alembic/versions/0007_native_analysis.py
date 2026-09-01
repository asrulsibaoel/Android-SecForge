from alembic import op
import sqlalchemy as sa

revision = "0007_native_analysis"
down_revision = "0006_relational_analysis"
branch_labels = None
depends_on = None


def _uuid() -> sa.types.TypeEngine:
    return sa.Uuid()


def upgrade() -> None:
    op.create_table(
        "native_libraries",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("archive_path", sa.String(512), nullable=False),
        sa.Column("abi", sa.String(32), nullable=False),
        sa.Column("filename", sa.String(256), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("elf_class", sa.String(8), nullable=True),
        sa.Column("architecture", sa.String(16), nullable=True),
        sa.Column("endianness", sa.String(8), nullable=True),
        sa.Column("elf_type", sa.String(16), nullable=True),
        sa.Column("entry_point", sa.BigInteger(), nullable=True),
        sa.Column("soname", sa.String(256), nullable=True),
        sa.Column("stripped", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("symbols_available", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("functions_truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("status", sa.String(16), nullable=False, server_default="COMPLETE"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("workspace_path", sa.String(1024), nullable=True),
    )
    op.create_index("ix_native_libraries_analysis_id", "native_libraries", ["analysis_id"])
    op.create_index("ix_native_libraries_abi", "native_libraries", ["abi"])
    op.create_index("ix_native_libraries_sha256", "native_libraries", ["sha256"])

    op.create_table(
        "native_functions",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("library_id", _uuid(), sa.ForeignKey("native_libraries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("address", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("symbol_type", sa.String(16), nullable=False, server_default="NOTYPE"),
        sa.Column("binding", sa.String(16), nullable=False, server_default="GLOBAL"),
        sa.Column("visibility", sa.String(16), nullable=False, server_default="DEFAULT"),
        sa.Column("size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("is_jni", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("source", sa.String(16), nullable=False, server_default="ELF"),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="HIGH"),
    )
    op.create_index("ix_native_functions_analysis_id", "native_functions", ["analysis_id"])
    op.create_index("ix_native_functions_library_id", "native_functions", ["library_id"])
    op.create_index("ix_native_functions_name", "native_functions", ["name"])
    op.create_index("ix_native_functions_kind", "native_functions", ["kind"])
    op.create_index("ix_native_functions_lib_kind", "native_functions", ["library_id", "kind"])

    op.create_table(
        "native_dependencies",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("library_id", _uuid(), sa.ForeignKey("native_libraries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("needed", sa.String(256), nullable=False),
    )
    op.create_index("ix_native_dependencies_library_id", "native_dependencies", ["library_id"])

    op.create_table(
        "jni_bindings",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("analysis_id", _uuid(), sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("java_class", sa.String(512), nullable=True),
        sa.Column("java_method", sa.String(256), nullable=True),
        sa.Column("java_signature", sa.Text(), nullable=True),
        sa.Column("library_id", _uuid(), sa.ForeignKey("native_libraries.id", ondelete="SET NULL"), nullable=True),
        sa.Column("library_name", sa.String(256), nullable=True),
        sa.Column("native_function_id", _uuid(), sa.ForeignKey("native_functions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("native_function", sa.String(512), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_jni_bindings_analysis_id", "jni_bindings", ["analysis_id"])
    op.create_index("ix_jni_bindings_java_class", "jni_bindings", ["java_class"])


def downgrade() -> None:
    for table in ("jni_bindings", "native_dependencies", "native_functions", "native_libraries"):
        op.drop_table(table)

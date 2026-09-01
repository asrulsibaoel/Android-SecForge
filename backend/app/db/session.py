from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    pass


connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def initialize_database() -> None:
    Base.metadata.create_all(bind=engine)
    columns = {column["name"] for column in inspect(engine).get_columns("apk_artifacts")}
    missing = {
        "artifact_type": "VARCHAR(8) DEFAULT 'apk'",
        "structure": "JSON",
        "manifest": "JSON",
        "findings": "JSON",
        "framework": "JSON",
        "ipc": "JSON",
        "dex": "JSON",
        "workspace_path": "VARCHAR(1024)",
    }
    with engine.begin() as connection:
        for name, definition in missing.items():
            if name not in columns:
                connection.execute(text(f"ALTER TABLE apk_artifacts ADD COLUMN {name} {definition}"))
        if "structure" in columns or "structure" in missing:
            connection.execute(text("UPDATE apk_artifacts SET structure = '{}' WHERE structure IS NULL"))
        if "manifest" in columns or "manifest" in missing:
            connection.execute(text("UPDATE apk_artifacts SET manifest = '{}' WHERE manifest IS NULL"))
        if "findings" in columns or "findings" in missing:
            connection.execute(text("UPDATE apk_artifacts SET findings = '[]' WHERE findings IS NULL"))
        if "framework" in columns or "framework" in missing:
            connection.execute(text("UPDATE apk_artifacts SET framework = '{}' WHERE framework IS NULL"))
        if "ipc" in columns or "ipc" in missing:
            connection.execute(text("UPDATE apk_artifacts SET ipc = '{}' WHERE ipc IS NULL"))
        if "dex" in columns or "dex" in missing:
            connection.execute(text("UPDATE apk_artifacts SET dex = '[]' WHERE dex IS NULL"))
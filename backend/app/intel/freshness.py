"""Intelligence freshness tracking (prompt 16).

Freshness is derived deterministically from the timestamps recorded at import.
Stale intelligence is never hidden — it is labelled STALE and still usable.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app.core.config import settings
from app.models.cve import Vulnerability

CURRENT, STALE, UNKNOWN = "CURRENT", "STALE", "UNKNOWN"


def _as_dt(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def freshness_status(vuln, now: datetime | None = None, stale_days: int | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    stale_days = stale_days if stale_days is not None else settings.intel_stale_days
    reference = _as_dt(vuln.last_seen) or _as_dt(vuln.retrieved_at)
    if reference is None:
        return UNKNOWN
    return CURRENT if (now - reference) <= timedelta(days=stale_days) else STALE


def db_freshness(db, now: datetime | None = None) -> dict:
    """Aggregate freshness across the local database (never probes the network)."""
    now = now or datetime.now(timezone.utc)
    total = db.scalar(select(func.count(Vulnerability.id))) or 0
    if total == 0:
        return {"status": UNKNOWN, "total": 0, "current": 0, "stale": 0, "unknown": 0,
                "latest_import": None, "stale_days": settings.intel_stale_days,
                "note": "no local vulnerability intelligence imported yet"}
    current = stale = unknown = 0
    latest = None
    for vuln in db.scalars(select(Vulnerability)):
        status = freshness_status(vuln, now)
        current += status == CURRENT
        stale += status == STALE
        unknown += status == UNKNOWN
        ref = _as_dt(vuln.last_seen) or _as_dt(vuln.retrieved_at)
        if ref and (latest is None or ref > latest):
            latest = ref
    overall = CURRENT if current and not stale else (STALE if stale else UNKNOWN)
    return {"status": overall, "total": total, "current": current, "stale": stale, "unknown": unknown,
            "latest_import": latest.isoformat() if latest else None, "stale_days": settings.intel_stale_days,
            "note": "stale intelligence remains usable and is never removed"}

from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import func, or_, select

from storage.database import CVERecord, Database


app = FastAPI(
    title="Security Pipeline API",
    description="Ежедневный сбор CVE из NVD с фильтрацией и хранением в SQLite",
    version="1.0",
)

_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index() -> str:
    """Landing page: зачем нужен пайплайн и как им пользоваться."""
    page = _STATIC_DIR / "index.html"
    if not page.exists():
        raise HTTPException(status_code=404, detail="Страница не найдена")
    return page.read_text(encoding="utf-8")


@app.get("/api/stats")
def stats():
    db = Database()
    with db.engine.connect() as conn:
        total = conn.scalar(select(func.count()).select_from(CVERecord)) or 0
        rows = conn.execute(
            select(CVERecord.severity, func.count()).group_by(CVERecord.severity)
        ).all()
    return {"total": total, "by_severity": {k or "UNKNOWN": v for k, v in rows}}


@app.get("/api/cves")
def list_cves(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: str | None = Query(None),
    q: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
):
    db = Database()
    stmt = select(CVERecord)

    if severity:
        sev = severity.strip().upper()
        if sev != "ALL":
            stmt = stmt.where(CVERecord.severity == sev)

    if q and q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(CVERecord.cve_id.ilike(like), CVERecord.description.ilike(like))
        )

    try:
        if date_from:
            stmt = stmt.where(
                CVERecord.published_date >= datetime.fromisoformat(date_from)
            )
        if date_to:
            end = datetime.fromisoformat(date_to)
            if "T" not in date_to:
                end = end + timedelta(days=1)  # включительно по день
            stmt = stmt.where(CVERecord.published_date < end)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Некорректная дата: {e}")

    total = db.count(stmt)
    stmt = (
        stmt.order_by(CVERecord.published_date.desc())
        .limit(limit)
        .offset(offset)
    )
    items = db.query(stmt)
    return {"total": total, "offset": offset, "limit": limit, "items": items}

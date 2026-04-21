from pydantic import BaseModel
from datetime import datetime


class CVEModel(BaseModel):
    cve_id: str
    description: str
    severity: str | None = None
    cvss_score: float | None = None
    published_date: datetime
    last_modified: datetime
    affected_products: list[str] = []
    references: list[str] = []

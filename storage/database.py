from sqlalchemy import create_engine, Column, String, Float, DateTime, JSON, func, select
from sqlalchemy.orm import DeclarativeBase, Session

from models.cve import CVEModel

class Base(DeclarativeBase):
    pass


class CVERecord(Base):
    __tablename__ = 'cves'

    cve_id = Column(String, primary_key=True)
    description = Column(String)
    severity = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    published_date = Column(DateTime)
    last_modified = Column(DateTime)
    affected_products = Column(JSON)
    references = Column(JSON)

class Database:
    def __init__(self, url: str = 'sqlite:///security.db'):
        self.engine = create_engine(url)
        Base.metadata.create_all(self.engine)

    def save_cves(self, cves: list[CVEModel]) -> int:
        saved = 0
        with Session(self.engine) as session:
            for cve in cves:
                exists = session.get(CVERecord, cve.cve_id)
                if not exists:
                    session.add(CVERecord(**cve.model_dump()))
                    saved += 1
            session.commit()
        return saved

    def get_all(self) -> list[CVERecord]:
        with Session(self.engine) as session:
            return list(session.scalars(select(CVERecord)).all())

    def get_by_severity(self, severity: str) -> list[CVERecord]:
        with Session(self.engine) as session:
            stmt = select(CVERecord).filter_by(severity=severity.upper())
            return list(session.scalars(stmt).all())

    def count(self, stmt) -> int:
        with Session(self.engine) as session:
            return session.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    def query(self, stmt) -> list[dict]:
        with Session(self.engine) as session:
            rows = session.scalars(stmt).all()
            return [self._to_dict(r) for r in rows]

    @staticmethod
    def _to_dict(r: CVERecord) -> dict:
        return {
            "cve_id": r.cve_id,
            "description": r.description,
            "severity": r.severity,
            "cvss_score": r.cvss_score,
            "published_date": r.published_date.isoformat() if r.published_date else None,
            "last_modified": r.last_modified.isoformat() if r.last_modified else None,
            "affected_products": r.affected_products or [],
            "references": r.references or [],
        }

from sqlalchemy import create_engine, Column, String, Float, DateTime, JSON
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy import select
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


"""Одноразовый бэкфилл: перечитывает записи без severity из NVD (с парсером CVSS v4)."""

import time

from sqlalchemy import select, update

from collectors.nvd_collector import NVDCollector
from storage.database import CVERecord, Database


def backfill() -> None:
    db = Database()
    with db.engine.connect() as conn:
        ids = [
            r.cve_id
            for r in conn.execute(
                select(CVERecord.cve_id).where(CVERecord.severity.is_(None))
            ).all()
        ]
    print(f"Записей без severity: {len(ids)}")

    collector = NVDCollector()
    updated = 0
    skipped = 0
    for i, cve_id in enumerate(ids, 1):
        parsed = None
        for attempt in range(4):
            try:
                parsed = collector.fetch_by_id(cve_id)
                break
            except Exception:
                # 429 / сетевая ошибка: ждём и пробуем снова
                time.sleep(30)
                if attempt == 3:
                    print(f"  {cve_id}: не удалось после 4 попыток, пропускаю")
        if parsed and parsed.severity:
            with db.engine.begin() as conn:
                conn.execute(
                    update(CVERecord)
                    .where(CVERecord.cve_id == cve_id)
                    .values(severity=parsed.severity, cvss_score=parsed.cvss_score)
                )
            updated += 1
        else:
            skipped += 1
        if i % 10 == 0 or i == len(ids):
            print(f"  {i}/{len(ids)} — обновлено {updated}, без метрик {skipped}")
        time.sleep(0.6)

    print(f"Готово: обновлено {updated}, без CVSS в NVD {skipped}")


if __name__ == "__main__":
    backfill()

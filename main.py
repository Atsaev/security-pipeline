from dotenv import load_dotenv
from collectors.nvd_collector import NVDCollector
from processors.cleaner import CVECleaner
from storage.database import Database

load_dotenv()


def run_pipeline(days: int = 7):
    print(f"▶ Запуск pipeline: последние {days} дней\n")

    # 1. Собираем данные
    collector = NVDCollector()
    cves = collector.fetch_recent(days=days)
    print(f"  Получено CVE: {len(cves)}\n")

    # 2. Чистим данные
    print("🧹 Очистка данных:")
    cleaner = CVECleaner()
    cves = cleaner.clean(cves)

    # 3. Статистика
    stats = cleaner.get_stats(cves)
    print(f"\n📊 Статистика:")
    print(f"  Всего: {stats['Всего']}")
    print(f"  Средний score: {stats['Средний балл']}")
    print(f"  Максимальный score: {stats['Максимальный балл']}")
    print(f"\n  По severity:")
    for severity, count in stats["По ур опасности"].items():
        print(f"    {severity}: {count}")

    # 4. Сохраняем в БД
    print(f"\n💾 Сохранение в БД:")
    db = Database()
    saved = db.save_cves(cves)
    print(f"  Сохранено новых: {saved}")
    print(f"  Дубликатов пропущено: {len(cves) - saved}")

    # 5. Топ критических
    critical = [c for c in cves if c.severity == "CRITICAL"]
    if critical:
        print(f"\n🔴 Топ 5 критических CVE:")
        for cve in critical[:5]:
            print(f"  {cve.cve_id} | score: {cve.cvss_score} | {cve.description[:80]}...")


if __name__ == "__main__":
    run_pipeline(days=30)
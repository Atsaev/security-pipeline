# Security CVE Pipeline

Автоматический пайплайн сбора уязвимостей из NVD API: ежедневный крон тянет новые CVE, чистит и нормализует данные, дедуплицирует по `cve_id` и хранит в SQLite. Веб-интерфейс с фильтрами по критичности, датам, поиском и лимитом вывода.

## Live Demo

- **UI (лаборатория):** https://atsaev-dev.ru/pipeline/
- **API docs:** https://atsaev-dev.ru/pipeline/docs

## Architecture

```
NVD API
   ↓
Collector    — запрос CVE за последние N дней (CVSS v3.1 → v4 → v2)
   ↓
Cleaner      — нормализация severity и описаний, отсев невалидных записей
   ↓
SQLite       — дедупликация по cve_id, файл на хосте (bind-mount)
   ↑
Scheduler    — ежедневно в 09:00 + мгновенный прогон при старте контейнера
```

## Stack

- Python 3.12
- httpx — клиент NVD API
- Pydantic — валидация данных
- SQLAlchemy — ORM
- SQLite — локальная БД
- schedule — планировщик
- FastAPI / uvicorn — REST API

## Quick Start

1. Clone the repository:
```bash
   git clone https://github.com/Atsaev/security-pipeline.git
   cd security-pipeline
```

2. Install dependencies:
```bash
   uv sync
```

3. Create `.env` file:
```bash
   NVD_TOKEN=your_api_key_here
```
   Get free API key: https://nvd.nist.gov/developers/request-an-api-key

4. Run the pipeline once:
```bash
   uv run main.py
```

5. Run the scheduler (daily updates):
```bash
   uv run scheduler.py
```

## API

### GET /api/cves

Фильтруемая выборка CVE, отсортированная от новых к старым по дате публикации.

Query-параметры:

| Параметр | Описание |
|---|---|
| `limit` | сколько записей вывести (1–500, по умолчанию 50) |
| `offset` | сдвиг для пагинации |
| `severity` | CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN |
| `q` | поиск по CVE ID или описанию |
| `date_from` / `date_to` | диапазон дат публикации (YYYY-MM-DD) |

Response:
```json
{
  "total": 220,
  "offset": 0,
  "limit": 50,
  "items": [
    {
      "cve_id": "CVE-2026-15980",
      "description": "...",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "published_date": "2026-08-30T05:16:58.407000",
      "affected_products": [],
      "references": ["https://..."]
    }
  ]
}
```

### GET /api/stats

Общее число записей и распределение по критичности:
```json
{"total": 220, "by_severity": {"CRITICAL": 40, "HIGH": 87, "MEDIUM": 79, "LOW": 7, "UNKNOWN": 7}}
```

## Features

- Ежедневный автосбор из NVD (крон 09:00) + прогон при старте контейнера
- Реальные метрики из NVD: CVSS v3.1 / v4 / v2 с severity и баллами
- Дедупликация по `cve_id` — каждая уязвимость в базе один раз
- UI с фильтрами: критичность, диапазон дат, поиск по ID/описанию, лимит вывода
- Сортировка от новых к старым + пагинация («Загрузить ещё»)
- Персистентность: SQLite на хосте (bind-mount) — данные переживают пересоздание контейнера

## Project Structure
```
security-pipeline/
├── api/
│   └── main.py           # FastAPI: /api/cves, /api/stats, UI
├── collectors/
│   └── nvd_collector.py  # NVD API клиент (v3.1/v4/v2, fetch_by_id)
├── processors/
│   └── cleaner.py        # очистка и нормализация
├── storage/
│   └── database.py       # SQLAlchemy: модели, запросы с фильтрами
├── models/
│   └── cve.py            # Pydantic-модели
├── static/
│   └── index.html        # landing page (UI)
├── main.py               # pipeline entry point
├── scheduler.py          # ежедневный планировщик
├── run.py                # API + планировщик в одном процессе
└── backfill_unknowns.py  # пересчёт записей без severity из NVD
```

## Example Output
```
▶ Запуск pipeline: последние 1 дней
Запрос к NVD API...
 Всего найдено в API: 83
 Получено CVE: 20
🧹 Очистка данных:
 До чистки: 20
 После чистки: 20
📊 Статистика:
  Всего: 20
  Средний score: 6.25
  Максимальный score: 9.8
  По severity:
    CRITICAL: 2
    HIGH: 2
    MEDIUM: 6
    LOW: 1
💾 Сохранение в БД:
  Сохранено новых: 0
  Дубликатов пропущено: 20
```

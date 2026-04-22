# Security CVE Pipeline

Automated pipeline for collecting, cleaning and storing CVE vulnerabilities from NVD (National Vulnerability Database).

## Description

This project automatically fetches recent CVE data from the NVD API, cleans and normalizes it, stores it in a database, and runs on a daily schedule.

## Architecture
## Stack

- **Python 3.12**
- **httpx** — async HTTP client
- **Pydantic** — data validation
- **SQLAlchemy** — ORM
- **SQLite** — local database
- **schedule** — task scheduler

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

4. Run pipeline:
```bash
   uv run main.py
```

5. Run scheduler (daily updates):
```bash
   uv run scheduler.py
```

## Features

- Fetches CVE data for the last N days from NVD API
- Cleans and normalizes data (fixes severity, trims descriptions)
- Filters invalid records
- Saves to SQLite database with deduplication
- Shows statistics by severity (LOW / MEDIUM / HIGH / CRITICAL)
- Runs automatically on a daily schedule

## Project Structure
```
security-pipeline/
├── collectors/
│   └── nvd_collector.py   # NVD API client
├── processors/
│   └── cleaner.py         # data cleaning and normalization
├── storage/
│   └── database.py        # SQLAlchemy models and DB operations
├── models/
│   └── cve.py             # Pydantic data models
├── main.py                # pipeline entry point
└── scheduler.py           # daily scheduler
```

## Example Output
▶ Запуск pipeline: последние 30 дней
Запрос к NVD API...
Всего найдено в API: 6204
Получено CVE: 20
🧹 Очистка данных:
До чистки: 20
После чистки: 20
📊 Статистика:
Всего: 20
Средний score: 6.25
Максимальный score: 9.8
По severity:
MEDIUM: 13
HIGH: 5
CRITICAL: 1
💾 Сохранение в БД:
Сохранено новых: 20
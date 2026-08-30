import threading

import uvicorn

from scheduler import run_scheduler


def main():
    thread = threading.Thread(target=run_scheduler, daemon=True)
    thread.start()
    print("▶ Запуск: API (uvicorn) + планировщик (фон)")
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()

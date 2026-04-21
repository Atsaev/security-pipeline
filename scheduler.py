import schedule
import time
from dotenv import load_dotenv
from main import run_pipeline


load_dotenv()

def job():
    print('\n запуск по расписанию...')
    run_pipeline(days=1)

# schedule.every().day.at('09:00').do(job)
schedule.every(5).minutes.do(job)
print("Планировщик запущен. Ожидаю расписания...")
print("   Следующий запуск:", schedule.next_run())
job()

while True:
    schedule.run_pending()
    time.sleep(60)

FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY . .

RUN pip install uv
RUN uv sync

CMD ["uv", "run", "scheduler.py"]

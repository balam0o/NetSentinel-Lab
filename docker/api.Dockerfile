FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN python -m pip install --upgrade pip

COPY pyproject.toml README.md ./
COPY app ./app

RUN python -m pip install .

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.api.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
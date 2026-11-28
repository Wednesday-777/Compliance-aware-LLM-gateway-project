FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts
COPY policy.yaml .


RUN useradd --create-home appuser && mkdir -p /data && chown appuser /data
USER appuser

ENV AUDIT_DB_PATH=/data/audit.db
EXPOSE 8000

# Hosting platforms set PORT; default to 8000 locally
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
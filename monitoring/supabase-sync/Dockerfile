FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY supabase_sync.py .

ENV SESSIONS_DIR=/sessions \
    IOCS_DIR=/iocs \
    LOGS_DIR=/logs \
    PCAPS_DIR=/pcaps

CMD ["python", "supabase_sync.py"]

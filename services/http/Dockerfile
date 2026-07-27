FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /var/log/honeypot /sessions

EXPOSE 8080

# Production: Use gunicorn; fallback to flask dev server if unavailable
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8080", "--timeout", "30", "http_honeypot:app"]





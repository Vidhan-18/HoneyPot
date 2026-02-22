FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /var/log/honeypot /sessions

EXPOSE 5432 3306

CMD ["python", "db_api_honeypot.py"]





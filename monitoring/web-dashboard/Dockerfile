FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all Python files
COPY *.py ./
COPY templates/ ./templates/

RUN mkdir -p /logs /sessions /iocs /pcaps

EXPOSE 5000

CMD ["python", "web_dashboard.py"]



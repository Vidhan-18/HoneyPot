FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    tcpdump \
    tshark \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /pcaps /logs

CMD ["python", "packet_capture.py"]





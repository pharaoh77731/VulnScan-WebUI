FROM python:3.11-slim

LABEL maintainer="Bhupendra Singh"
LABEL description="VulnScan Pro v3.0 — Vulnerability Assessment Platform"

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

EXPOSE 5000

CMD ["python", "backend/app.py"]

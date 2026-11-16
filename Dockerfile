FROM python:3.12-slim

# Nmap (scan), Chromium (génération PDF), polices pour le rapport
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap chromium fonts-noto-core fonts-dejavu-core ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY run.py .

ENV AUDIT_HOST=0.0.0.0 AUDIT_PORT=8090 AUDIT_DATA=/data CHROME_PATH=/usr/bin/chromium PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8090
CMD ["python", "run.py"]

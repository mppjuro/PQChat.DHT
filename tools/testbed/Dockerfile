# Dockerfile for Isolated BEP 5 / BEP 44 DHT Testbed & Correlation Suite
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY tools/threat_sim/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy testbed source code and tools
COPY tools/testbed /app/tools/testbed
COPY tools/threat_sim /app/tools/threat_sim
COPY docs /app/docs

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "tools.testbed.testbed_runner", "--runs", "100", "--nodes", "150"]

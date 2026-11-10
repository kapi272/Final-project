FROM python:3.11-slim

# Install system dependencies: iptables for firewall rule enforcement and curl for healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PYTHONUNBUFFERED=1

# Install Python requirements
COPY controller/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY controller/ controller/

# Expose FastAPI SOC web dashboard port
EXPOSE 8000

CMD ["python", "-m", "controller.main"]


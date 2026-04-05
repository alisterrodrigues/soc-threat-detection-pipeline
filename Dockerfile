# syntax=docker/dockerfile:1

FROM python:3.11-slim

LABEL maintainer="alisterrodrigues"
LABEL description="SOC Threat Detection Pipeline — Sysmon behavioral detection engine"

WORKDIR /app

# Install dependencies first so this layer is cached independently of source changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project source
COPY . .

# Create output directory for reports and exports
RUN mkdir -p output

# Default: show CLI help. Override with docker run ... --input /data/logs.xml
ENTRYPOINT ["python", "-m", "cli.main"]
CMD ["--help"]

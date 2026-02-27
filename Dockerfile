FROM python:3.12-slim

LABEL org.label-schema.name="PegaProx"
LABEL org.label-schema.description="Modern Multi-Cluster Management for Proxmox VE"
LABEL org.label-schema.vendor="PegaProx"
LABEL org.label-schema.url="https://pegaprox.com"
LABEL org.label-schema.vcs-url="https://github.com/PegaProx/project-pegaprox"
LABEL maintainer="support@pegaprox.com"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r pegaprox && useradd -r -g pegaprox -d /app -s /bin/false pegaprox

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=pegaprox:pegaprox pegaprox_multi_cluster.py .
COPY --chown=pegaprox:pegaprox pegaprox/ pegaprox/
COPY --chown=pegaprox:pegaprox web/ web/
COPY --chown=pegaprox:pegaprox static/ static/
COPY --chown=pegaprox:pegaprox images/ images/
COPY --chown=pegaprox:pegaprox version.json .
COPY --chown=pegaprox:pegaprox requirements.txt .
COPY --chown=pegaprox:pegaprox update.sh .

# Create runtime directories
RUN mkdir -p /app/config /app/logs /app/backups \
    && chown -R pegaprox:pegaprox /app

# Persistent volumes for config and logs
VOLUME ["/app/config", "/app/logs"]

# Switch to non-root user
USER pegaprox

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('https://localhost:5000/api/auth/check', context=__import__('ssl')._create_unverified_context())" || exit 1

ENTRYPOINT ["python3", "pegaprox_multi_cluster.py"]

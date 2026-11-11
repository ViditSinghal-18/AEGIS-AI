# ==============================================================================
# AEGIS-AI Container Runtime
# Secure, non-root Debian-slim container with active network reconnaissance support
# ==============================================================================

FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AEGIS_HOST=0.0.0.0 \
    AEGIS_PORT=5000 \
    AEGIS_DATA_DIR=/app/data

# Install system dependencies: nmap for verified active scans, ca-certificates, curl for healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user
RUN groupadd -g 1001 aegisgroup && \
    useradd -u 1001 -g aegisgroup -m -s /bin/bash aegis

WORKDIR /app

# Copy dependency definition and install
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . /app/

# Create runtime data directory and grant permissions to non-root user
RUN mkdir -p /app/data && chown -R aegis:aegisgroup /app

# Switch to unprivileged user
USER aegis

# Expose HTTP port
EXPOSE 5000

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Launch AEGIS application
CMD ["python", "app.py"]

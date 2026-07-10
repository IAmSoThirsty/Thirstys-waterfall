# Production Dockerfile for Thirstys-Waterfall Web Interface
# Single-stage build for simplicity and reliability
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    THIRSTYS_ENV=production

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libssl-dev \
    libffi-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy the locked deployment dependency set first for better layer caching
COPY requirements-deploy.lock .
RUN pip install --no-cache-dir -r requirements-deploy.lock

# Copy application code
COPY . .

# Normalize shell scripts copied from Windows worktrees.
RUN sed -i 's/\r$//' /app/web/start.sh && chmod +x /app/web/start.sh

# Install the Thirstys-Waterfall package. This must fail closed in production.
RUN pip install --no-cache-dir .

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash thirsty && \
    mkdir -p /home/thirsty/.thirstys_waterfall && \
    chown -R thirsty:thirsty /home/thirsty /app

# Switch to non-root user
USER thirsty

# Set working directory to web interface
WORKDIR /app/web

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Start the web server
CMD ["bash", "/app/web/start.sh"]

# Multi-stage Docker build for enterprise authentication backend
# Stage 1: Base Python image with security updates
FROM python:3.11-slim-bullseye as base

# Set security labels
LABEL maintainer="Enterprise Auth Team"
LABEL version="1.0.0"
LABEL security.scan="enabled"

# Install system dependencies and security updates
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    ca-certificates \
    gnupg \
    && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Create non-root user for security
RUN groupadd -r appuser --gid=1000 && useradd -r -g appuser --uid=1000 appuser

# Set working directory
WORKDIR /app

# Set security-focused environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Stage 2: Dependencies installation
FROM base as dependencies

# Copy requirements first for better caching
COPY requirements.txt requirements/
COPY requirements/ requirements/

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements/production.txt

# Stage 3: Application build
FROM dependencies as application

# Copy application code
COPY . .

# Set proper ownership
RUN chown -R appuser:appuser /app

# Create necessary directories
RUN mkdir -p /app/logs /app/media /app/static && \
    chown -R appuser:appuser /app/logs /app/media /app/static

# Collect static files
RUN python manage.py collectstatic --noinput --settings=enterprise_auth.settings.production

# Stage 4: Production image
FROM python:3.11-slim-bullseye as production

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set working directory
WORKDIR /app

# Copy Python dependencies from dependencies stage
COPY --from=dependencies /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=dependencies /usr/local/bin /usr/local/bin

# Copy application from application stage
COPY --from=application --chown=appuser:appuser /app /app

# Switch to non-root user
USER appuser

# Health check with comprehensive checks
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health/ || exit 1

# Expose port
EXPOSE 8000

# Set final security permissions
RUN chmod -R 755 /app && \
    chmod -R 644 /app/logs /app/media /app/static

# Default command with production-ready settings
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--worker-class", "gevent", \
     "--worker-connections", "1000", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--timeout", "30", \
     "--keep-alive", "5", \
     "--preload", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "enterprise_auth.wsgi:application"]
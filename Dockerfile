# Build stage - install dependencies that require compilation
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Runtime stage - minimal slim image
FROM python:3.11-slim

WORKDIR /app

# Install only runtime dependencies (cryptography needs libffi and openssl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi8 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Copy application files
COPY . .

# Ensure local packages are in PATH
ENV PATH=/root/.local/bin:$PATH

# Expose port
EXPOSE 8000

# Use gunicorn with production-tuned settings
# --workers: Number of worker processes for isolation between users
# --max-requests: Restart workers periodically to clear memory
# --max-requests-jitter: Stagger worker restarts
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--worker-class", "sync", "--timeout", "600", "--max-requests", "1000", "--max-requests-jitter", "100", "--preload", "app:app"]


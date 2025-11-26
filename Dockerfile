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

# Use gunicorn to run the application directly (Alpine doesn't have bash)
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--timeout", "600", "app:app"]


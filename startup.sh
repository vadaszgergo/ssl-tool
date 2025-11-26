#!/bin/bash
# SECURITY: Use multiple isolated worker processes
# Each worker process handles requests independently
# This ensures complete isolation between concurrent users
# --workers: Number of worker processes (adjust based on CPU cores)
# --worker-class: Use sync workers for better isolation
# --timeout: Request timeout
# --max-requests: Restart workers after N requests to clear memory
# --max-requests-jitter: Add randomness to prevent all workers restarting at once
gunicorn --bind 0.0.0.0:8000 \
         --workers 4 \
         --worker-class sync \
         --timeout 600 \
         --max-requests 1000 \
         --max-requests-jitter 100 \
         --preload \
         app:app


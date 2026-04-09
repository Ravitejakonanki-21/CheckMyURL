#!/bin/bash
set -e

# Start Celery worker in the background
celery -A tasks.celery_app.celery_app worker --loglevel=INFO --concurrency=2 &

# Start Flask with Gunicorn in the foreground
# Render sets PORT env var; default to 10000 if not set
exec gunicorn --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 8 --timeout 0 app:app

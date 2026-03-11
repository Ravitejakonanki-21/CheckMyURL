#!/bin/bash
set -e

# Start Celery worker in the background
celery -A tasks.celery_app.celery_app worker --loglevel=INFO --concurrency=2 &

# Start Flask in the foreground
exec python app.py

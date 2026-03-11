import os
from pathlib import Path

from dotenv import load_dotenv
from celery import Celery

# Load .env from the project root (two levels up from this file:
# tasks/celery_app.py -> backend/ -> project root)
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent.parent / ".env")


def make_celery() -> Celery:
    broker_url = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
    result_backend = os.getenv("CELERY_RESULT_BACKEND", broker_url)

    app = Celery(
        "url_checker",
        broker=broker_url,
        backend=result_backend,
    )
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_acks_late=True,
        worker_prefetch_multiplier=int(
            os.getenv("CELERY_PREFETCH_MULTIPLIER", "4")
        ),
        task_time_limit=int(os.getenv("CELERY_TASK_TIME_LIMIT", "120")),
        task_soft_time_limit=int(os.getenv("CELERY_TASK_SOFT_TIME_LIMIT", "90")),
    )
    return app


celery_app = make_celery()

# Ensure task modules are imported so Celery registers them.
# This keeps runtime behavior explicit and avoids relying on implicit autodiscovery.
from . import scan_tasks  # noqa: F401


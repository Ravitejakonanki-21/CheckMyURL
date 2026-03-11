import os
from pathlib import Path

from dotenv import load_dotenv
from celery import Celery

# Load .env from the project root (two levels up from this file:
# tasks/celery_app.py -> backend/ -> project root)
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent.parent / ".env")


def _fix_rediss_url(url: str) -> str:
    """Celery requires ssl_cert_reqs param for rediss:// URLs (Upstash/Redis TLS)."""
    url = url.strip()  # Remove hidden \n from env vars
    if url.startswith("rediss://") and "ssl_cert_reqs" not in url:
        # CERT_REQUIRED for production; CERT_NONE for providers like Upstash
        cert_reqs = os.getenv("REDIS_SSL_CERT_REQS", "CERT_REQUIRED")
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}ssl_cert_reqs={cert_reqs}"
    return url


def make_celery() -> Celery:
    broker_url = _fix_rediss_url(os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0"))
    result_backend = _fix_rediss_url(os.getenv("CELERY_RESULT_BACKEND", broker_url))

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


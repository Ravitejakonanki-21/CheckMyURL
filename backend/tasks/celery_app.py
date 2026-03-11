import os
import ssl
from pathlib import Path
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from dotenv import load_dotenv
from celery import Celery

# Load .env from the project root (two levels up from this file:
# tasks/celery_app.py -> backend/ -> project root)
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent.parent / ".env")


def _fix_rediss_url(url: str) -> str:
    """Celery requires ssl_cert_reqs param for rediss:// URLs (Upstash/Redis TLS)."""
    url = url.strip()
    if not url.startswith("rediss://") or "ssl_cert_reqs" in url:
        return url
    cert_reqs = os.getenv("REDIS_SSL_CERT_REQS", "CERT_NONE")
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query["ssl_cert_reqs"] = [cert_reqs]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _ssl_cert_reqs_value() -> int:
    """Map REDIS_SSL_CERT_REQS env to ssl constant."""
    v = os.getenv("REDIS_SSL_CERT_REQS", "CERT_NONE").upper()
    if v == "CERT_REQUIRED":
        return ssl.CERT_REQUIRED
    if v == "CERT_OPTIONAL":
        return ssl.CERT_OPTIONAL
    return ssl.CERT_NONE


def make_celery() -> Celery:
    broker_url = _fix_rediss_url(os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0"))
    result_backend = _fix_rediss_url(os.getenv("CELERY_RESULT_BACKEND", broker_url))

    # Override env so any Celery/kombu code reading from env gets the fixed URLs
    os.environ["CELERY_BROKER_URL"] = broker_url
    os.environ["CELERY_RESULT_BACKEND"] = result_backend

    app = Celery(
        "url_checker",
        broker=broker_url,
        backend=result_backend,
    )
    ssl_opts = {"ssl_cert_reqs": _ssl_cert_reqs_value()}
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
        broker_use_ssl=ssl_opts if broker_url.startswith("rediss://") else False,
        redis_backend_use_ssl=ssl_opts if result_backend.startswith("rediss://") else False,
    )
    return app


celery_app = make_celery()

# Ensure task modules are imported so Celery registers them.
# This keeps runtime behavior explicit and avoids relying on implicit autodiscovery.
from . import scan_tasks  # noqa: F401


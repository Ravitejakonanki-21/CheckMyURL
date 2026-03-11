import os
from typing import Any

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.collection import Collection


_MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/url_checker")
_MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "url_checker")

_client: MongoClient | None = None
_client_pid: int | None = None


def _get_client() -> MongoClient:
    """
    Lazily create a MongoClient per-process.
    This avoids PyMongo fork-safety issues with Celery prefork workers.
    """
    global _client, _client_pid
    pid = os.getpid()
    if _client is None or _client_pid != pid:
        # Use a longer timeout in production (Atlas can be slow on cold start)
        timeout_ms = int(os.getenv("MONGO_SERVER_SELECTION_TIMEOUT_MS", "30000"))
        kwargs: dict = dict(
            maxPoolSize=int(os.getenv("MONGO_MAX_POOL_SIZE", "10")),
            serverSelectionTimeoutMS=timeout_ms,
        )
        # Atlas (mongodb+srv) requires TLS. The Python 3.11 slim image's OpenSSL
        # can trigger TLSV1_ALERT_INTERNAL_ERROR; bypass cert verification to fix.
        if _MONGO_URI.startswith("mongodb+srv"):
            kwargs["tlsAllowInvalidCertificates"] = True
        _client = MongoClient(_MONGO_URI, **kwargs)
        _client_pid = pid
    return _client


def get_db() -> Any:
    return _get_client()[_MONGO_DB_NAME]


def get_collection(name: str) -> Collection:
    return get_db()[name]


def ensure_indexes() -> None:
    """
    Idempotent index creation for all core collections.
    Safe to call on every app startup.
    """
    users = get_collection("users")
    users.create_index([("email", ASCENDING)], unique=True, name="uniq_email")
    users.create_index([("role", ASCENDING)], name="idx_role")

    scans = get_collection("scans")
    scans.create_index(
        [("submitted_by", ASCENDING), ("submitted_at", DESCENDING)],
        name="idx_scans_user_time",
    )
    scans.create_index(
        [("state", ASCENDING), ("risk.severity_level", DESCENDING)],
        name="idx_scans_state_severity",
    )
    scans.create_index(
        [("risk.total_score", DESCENDING)], name="idx_scans_risk_score"
    )

    audit_logs = get_collection("audit_logs")
    audit_logs.create_index(
        [("scan_id", ASCENDING), ("timestamp", DESCENDING)],
        name="idx_audit_scan_time",
    )
    audit_logs.create_index(
        [("actor_id", ASCENDING), ("timestamp", DESCENDING)],
        name="idx_audit_actor_time",
    )


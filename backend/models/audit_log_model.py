from datetime import datetime
from typing import Any, Dict

from bson import ObjectId
from flask import Request

from .mongo_client import get_collection


def _audit_logs_col(): return get_collection("audit_logs")


def _actor_from_request(request: Request) -> Dict[str, Any]:
    # Request may or may not have JWT context; we log whatever is available.
    from flask_jwt_extended import get_jwt, get_jwt_identity

    actor_email = None
    actor_role = None
    try:
        actor_email = get_jwt_identity()
        claims = get_jwt()
        actor_role = claims.get("role")
    except Exception:
        pass

    return {
        "actor_email": actor_email,
        "actor_role": actor_role,
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get("User-Agent"),
    }


def log_state_transition(
    scan_id: ObjectId,
    actor: Any,
    from_state: str,
    to_state: str,
    reason: str,
) -> None:
    base = _actor_from_request(actor) if hasattr(actor, "remote_addr") else {}
    doc: Dict[str, Any] = {
        "scan_id": scan_id,
        "timestamp": datetime.utcnow(),
        "action": "STATE_TRANSITION",
        "details": {
            "from_state": from_state,
            "to_state": to_state,
            "reason": reason,
        },
        **base,
    }
    _audit_logs_col().insert_one(doc)


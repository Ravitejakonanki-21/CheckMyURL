from datetime import datetime
from typing import Optional, Dict, Any

from bson import ObjectId

from .mongo_client import get_collection


def _users_col():
    """Return the users collection lazily — avoids DNS on import."""
    return get_collection("users")


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    return _users_col().find_one({"email": email.lower()})


def get_user_by_id(user_id: ObjectId) -> Optional[Dict[str, Any]]:
    return _users_col().find_one({"_id": user_id})


def create_user(email: str, password_hash: str, role: str = "USER") -> ObjectId:
    doc = {
        "email": email.lower(),
        "password_hash": password_hash,
        "role": role,
        "credits": 10,
        "subscription_level": "free",
        "created_at": datetime.utcnow(),
        "status": "active",
    }
    result = _users_col().insert_one(doc)
    return result.inserted_id


def update_last_login(user_id: ObjectId) -> None:
    _users_col().update_one(
        {"_id": user_id},
        {"$set": {"last_login_at": datetime.utcnow()}},
    )


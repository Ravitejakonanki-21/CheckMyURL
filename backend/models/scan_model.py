from datetime import datetime
from typing import Any, Dict, Optional, List

from bson import ObjectId

from .mongo_client import get_collection


_scans = get_collection("scans")


def create_scan(url: str, user_id: ObjectId) -> ObjectId:
    now = datetime.utcnow()
    doc: Dict[str, Any] = {
        "url": url,
        "submitted_by": user_id,
        "submitted_at": now,
        "state": "SUBMITTED",
        "celery_task_id": None,
        "risk": None,
        "raw_results": None,
        "soc": {},
        "tags": [],
        "created_at": now,
        "updated_at": now,
    }
    result = _scans.insert_one(doc)
    return result.inserted_id


def update_scan_state(
    scan_id: ObjectId, new_state: str, extra_fields: Optional[Dict[str, Any]] = None
) -> None:
    update: Dict[str, Any] = {"state": new_state, "updated_at": datetime.utcnow()}
    if extra_fields:
        update.update(extra_fields)
    _scans.update_one({"_id": scan_id}, {"$set": update})


def save_scan_results(
    scan_id: ObjectId, risk: Dict[str, Any], raw_results: Dict[str, Any]
) -> None:
    _scans.update_one(
        {"_id": scan_id},
        {
            "$set": {
                "risk": risk,
                "raw_results": raw_results,
                "updated_at": datetime.utcnow(),
            }
        },
    )


def get_scan_for_user(
    scan_id: ObjectId, user_id: ObjectId
) -> Optional[Dict[str, Any]]:
    return _scans.find_one({"_id": scan_id, "submitted_by": user_id})


def list_scans_for_user(user_id: ObjectId, limit: int = 50) -> List[Dict[str, Any]]:
    cursor = (
        _scans.find({"submitted_by": user_id})
        .sort("submitted_at", -1)
        .limit(limit)
    )
    return list(cursor)


def get_scan_by_id(scan_id: ObjectId) -> Optional[Dict[str, Any]]:
    return _scans.find_one({"_id": scan_id})


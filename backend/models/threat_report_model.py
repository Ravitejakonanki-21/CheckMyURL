"""
Threat Report model — stores confirmed phishing verdicts from SOC analysts.
Collection: threat_reports
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from bson import ObjectId

from .mongo_client import get_collection

def _reports_col(): return get_collection("threat_reports")


def create_threat_report(
    scan_id: ObjectId,
    analyst_email: str,
    verdict: str,           # "CONFIRMED_PHISHING" | "FALSE_POSITIVE"
    notes: str = "",
) -> ObjectId:
    """Insert a new threat report and return its id."""
    doc: Dict[str, Any] = {
        "scan_id": scan_id,
        "analyst_email": analyst_email,
        "verdict": verdict,
        "notes": notes,
        "created_at": datetime.utcnow(),
    }
    result = _reports_col().insert_one(doc)
    return result.inserted_id


def list_threat_reports(limit: int = 100) -> List[Dict[str, Any]]:
    """Return most recent threat reports, most recent first."""
    cursor = _reports_col().find({}).sort("created_at", -1).limit(limit)
    docs = list(cursor)
    for d in docs:
        d["_id"] = str(d["_id"])
        d["scan_id"] = str(d["scan_id"])
        if hasattr(d.get("created_at"), "isoformat"):
            d["created_at"] = d["created_at"].isoformat()
    return docs


def get_report_for_scan(scan_id: ObjectId) -> Optional[Dict[str, Any]]:
    return _reports_col().find_one({"scan_id": scan_id})

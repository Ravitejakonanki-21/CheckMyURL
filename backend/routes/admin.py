"""
Admin API routes — all endpoints require the ADMIN role.
Blueprint prefix: /api/admin
"""
from datetime import datetime

from bson import ObjectId
from flask import Blueprint, jsonify, request

from models.audit_log_model import _audit_logs_col
from models.mongo_client import get_collection
from models.threat_report_model import list_threat_reports
from utils.rbac import roles_required


bp = Blueprint("admin", __name__, url_prefix="/api/admin")

def _get_users(): return get_collection("users")
def _get_scans(): return get_collection("scans")

VALID_ROLES = {"GUEST", "USER", "ADMIN"}


@bp.get("/users")
@roles_required(["ADMIN"])
def list_users():
    """Return all users (admin only)."""
    docs = list(_get_users().find({}, {"password_hash": 0}))
    for d in docs:
        d["_id"] = str(d["_id"])
    return jsonify(docs), 200


@bp.patch("/users/<user_id>/role")
@roles_required(["ADMIN"])
def update_user_role(user_id: str):
    """Change a user's role (admin only)."""
    payload = request.get_json(force=True) or {}
    new_role = (payload.get("role") or "").upper()
    if new_role not in VALID_ROLES:
        return jsonify({"error": "invalid_role", "valid": sorted(VALID_ROLES)}), 400

    result = _get_users().update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"role": new_role, "updated_at": datetime.utcnow()}},
    )
    if result.matched_count == 0:
        return jsonify({"error": "user_not_found"}), 404

    return jsonify({"user_id": user_id, "role": new_role}), 200


@bp.get("/logs")
@roles_required(["ADMIN"])
def get_audit_logs():
    """Return the most recent 200 audit log entries (admin only)."""
    cursor = _audit_logs_col().find({}).sort("timestamp", -1).limit(200)
    docs = list(cursor)
    for d in docs:
        d["_id"] = str(d["_id"])
        if "scan_id" in d:
            d["scan_id"] = str(d["scan_id"])
    return jsonify(docs), 200


@bp.get("/threat-reports")
@roles_required(["ADMIN"])
def get_threat_reports():
    """Return all threat reports (admin only)."""
    return jsonify(list_threat_reports(limit=200)), 200


@bp.get("/stats")
@roles_required(["ADMIN"])
def get_system_stats():
    """High-level system statistics for the admin dashboard."""
    total_users = _get_users().count_documents({})
    total_scans = _get_scans().count_documents({})
    scans_by_state = list(
        _get_scans().aggregate([{"$group": {"_id": "$state", "count": {"$sum": 1}}}])
    )
    return jsonify({
        "total_users": total_users,
        "total_scans": total_scans,
        "scans_by_state": {r["_id"]: r["count"] for r in scans_by_state},
    }), 200


@bp.get("/history")
@roles_required(["ADMIN"])
def get_all_history():
    """Return ALL users' scan history (admin only), with user email attached."""
    # Build a user_id -> email lookup
    all_users = {u["_id"]: u["email"] for u in _get_users().find({}, {"email": 1})}

    docs = list(_get_scans().find({}).sort("submitted_at", -1).limit(500))
    serialised = []
    for d in docs:
        user_email = all_users.get(d.get("submitted_by"), "unknown")
        risk = d.get("risk") or {}
        serialised.append({
            "scanId":         str(d["_id"]),
            "url":            d.get("url", ""),
            "riskScore":      risk.get("total_score", 0),
            "classification": risk.get("severity_level", "UNKNOWN"),
            "scannedAt":      d.get("submitted_at", "").isoformat() if hasattr(d.get("submitted_at", ""), "isoformat") else str(d.get("submitted_at", "")),
            "state":          d.get("state", "SCANNED"),
            "userEmail":      user_email,
            "tools": {
                "SSL":      1 if (d.get("raw_results") or {}).get("ssl", {}).get("https_ok") else 0,
                "WHOIS":    1 if (d.get("raw_results") or {}).get("whois", {}).get("age_days") else 0,
                "Headers":  len(((d.get("raw_results") or {}).get("headers") or {}).get("security_headers") or {}),
                "Keywords": len(((d.get("raw_results") or {}).get("keyword") or {}).get("keywords_found") or []),
                "Ports":    0,
                "ML":       1 if (d.get("raw_results") or {}).get("ml") else 0,
            },
        })
    return jsonify(serialised), 200


@bp.get("/history/<user_id>")
@roles_required(["ADMIN"])
def get_user_history(user_id: str):
    """Return scan history for a specific user (admin only)."""
    try:
        uid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "invalid_user_id"}), 400

    user_doc = _get_users().find_one({"_id": uid}, {"email": 1})
    user_email = user_doc["email"] if user_doc else "unknown"

    docs = list(_get_scans().find({"submitted_by": uid}).sort("submitted_at", -1).limit(100))
    serialised = []
    for d in docs:
        risk = d.get("risk") or {}
        serialised.append({
            "scanId":         str(d["_id"]),
            "url":            d.get("url", ""),
            "riskScore":      risk.get("total_score", 0),
            "classification": risk.get("severity_level", "UNKNOWN"),
            "scannedAt":      d.get("submitted_at", "").isoformat() if hasattr(d.get("submitted_at", ""), "isoformat") else str(d.get("submitted_at", "")),
            "state":          d.get("state", "SCANNED"),
            "userEmail":      user_email,
            "tools": {
                "SSL":      1 if (d.get("raw_results") or {}).get("ssl", {}).get("https_ok") else 0,
                "WHOIS":    1 if (d.get("raw_results") or {}).get("whois", {}).get("age_days") else 0,
                "Headers":  len(((d.get("raw_results") or {}).get("headers") or {}).get("security_headers") or {}),
                "Keywords": len(((d.get("raw_results") or {}).get("keyword") or {}).get("keywords_found") or []),
                "Ports":    0,
                "ML":       1 if (d.get("raw_results") or {}).get("ml") else 0,
            },
        })
    return jsonify(serialised), 200

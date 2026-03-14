"""
Admin API routes — all endpoints require the ADMIN role.
Blueprint prefix: /api/admin
"""
from datetime import datetime

from bson import ObjectId
from flask import Blueprint, jsonify, request

from models.audit_log_model import _audit_logs
from models.mongo_client import get_collection
from models.threat_report_model import list_threat_reports
from utils.rbac import roles_required


bp = Blueprint("admin", __name__, url_prefix="/api/admin")

_users = get_collection("users")
_scans = get_collection("scans")

VALID_ROLES = {"GUEST", "USER", "ADMIN"}


@bp.get("/users")
@roles_required(["ADMIN"])
def list_users():
    """Return all users (admin only)."""
    docs = list(_users.find({}, {"password_hash": 0}))
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

    result = _users.update_one(
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
    cursor = _audit_logs.find({}).sort("timestamp", -1).limit(200)
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
    total_users = _users.count_documents({})
    total_scans = _scans.count_documents({})
    scans_by_state = list(
        _scans.aggregate([{"$group": {"_id": "$state", "count": {"$sum": 1}}}])
    )
    return jsonify({
        "total_users": total_users,
        "total_scans": total_scans,
        "scans_by_state": {r["_id"]: r["count"] for r in scans_by_state},
    }), 200

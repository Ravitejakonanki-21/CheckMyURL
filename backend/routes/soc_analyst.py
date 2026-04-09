"""
SOC Analyst routes — state machine for suspicious URL review workflow.
Blueprint prefix: /api/soc
"""
from datetime import datetime

from bson import ObjectId
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity

from models.audit_log_model import log_state_transition
from models.mongo_client import get_collection
from models.threat_report_model import create_threat_report
from utils.rbac import roles_required


bp = Blueprint("soc", __name__, url_prefix="/api/soc")

def _scans_col(): return get_collection("scans")


def _transition_scan(scan_id: ObjectId, from_states, to_state: str, reason: str, actor_req):
    doc = _scans_col().find_one({"_id": scan_id})
    if not doc:
        return None, ("scan_not_found", 404)
    if doc.get("state") not in from_states:
        return None, ("invalid_state_transition", 409)

    _scans_col().update_one(
        {"_id": scan_id},
        {"$set": {"state": to_state, "updated_at": datetime.utcnow()}},
    )
    log_state_transition(
        scan_id=scan_id,
        actor=actor_req,
        from_state=doc.get("state"),
        to_state=to_state,
        reason=reason,
    )
    return _scans_col().find_one({"_id": scan_id}), None


@bp.get("/queue")
@roles_required(["ADMIN"])
def analyst_queue():
    """
    Returns scans in SCANNED or UNDER_REVIEW states,
    ordered by severity and age — for the SOC analyst dashboard.
    """
    cursor = (
        _scans_col().find({"state": {"$in": ["SCANNED", "UNDER_REVIEW", "ESCALATED"]}})
        .sort([("risk.severity_level", -1), ("submitted_at", 1)])
        .limit(100)
    )
    docs = list(cursor)
    for d in docs:
        d["_id"] = str(d["_id"])
        if "submitted_by" in d:
            d["submitted_by"] = str(d["submitted_by"])
    return jsonify(docs), 200


@bp.post("/scans/<scan_id>/review")
@roles_required(["ADMIN"])
def review_scan(scan_id: str):
    payload = request.get_json(force=True) or {}
    notes = (payload.get("notes") or "").strip()

    doc, err = _transition_scan(
        ObjectId(scan_id),
        from_states=["SCANNED"],
        to_state="UNDER_REVIEW",
        reason=notes or "Analyst review started",
        actor_req=request,
    )
    if err:
        code, status = err
        return jsonify({"error": code}), status

    return jsonify({"scan_id": scan_id, "state": doc["state"]}), 200


@bp.post("/scans/<scan_id>/escalate")
@roles_required(["ADMIN"])
def escalate_scan(scan_id: str):
    payload = request.get_json(force=True) or {}
    reason = (payload.get("reason") or "").strip()

    doc, err = _transition_scan(
        ObjectId(scan_id),
        from_states=["UNDER_REVIEW"],
        to_state="ESCALATED",
        reason=reason or "Escalated by analyst",
        actor_req=request,
    )
    if err:
        code, status = err
        return jsonify({"error": code}), status

    return jsonify({"scan_id": scan_id, "state": doc["state"]}), 200


@bp.post("/scans/<scan_id>/close")
@roles_required(["ADMIN"])
def close_scan(scan_id: str):
    payload = request.get_json(force=True) or {}
    reason = (payload.get("reason") or "").strip()

    doc, err = _transition_scan(
        ObjectId(scan_id),
        from_states=["UNDER_REVIEW", "ESCALATED"],
        to_state="CLOSED",
        reason=reason or "Closed by manager",
        actor_req=request,
    )
    if err:
        code, status = err
        return jsonify({"error": code}), status

    return jsonify({"scan_id": scan_id, "state": doc["state"]}), 200


@bp.post("/scans/<scan_id>/report")
@roles_required(["ADMIN"])
def report_threat(scan_id: str):
    """
    Analyst submits a confirmed threat verdict (CONFIRMED_PHISHING or FALSE_POSITIVE).
    Persists a threat_report document and updates the scan state.
    """
    payload = request.get_json(force=True) or {}
    verdict = (payload.get("verdict") or "").upper()
    notes = (payload.get("notes") or "").strip()

    if verdict not in ("CONFIRMED_PHISHING", "FALSE_POSITIVE"):
        return jsonify({"error": "verdict must be CONFIRMED_PHISHING or FALSE_POSITIVE"}), 400

    analyst_email = get_jwt_identity()
    report_id = create_threat_report(
        scan_id=ObjectId(scan_id),
        analyst_email=analyst_email,
        verdict=verdict,
        notes=notes,
    )

    new_state = "CONFIRMED_PHISHING" if verdict == "CONFIRMED_PHISHING" else "FALSE_POSITIVE"
    _scans_col().update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {"state": new_state, "updated_at": datetime.utcnow()}},
    )

    return jsonify({"report_id": str(report_id), "verdict": verdict, "scan_id": scan_id}), 201


@bp.post("/scans/<scan_id>/false-positive")
@roles_required(["ADMIN"])
def mark_false_positive(scan_id: str):
    """Shortcut: mark a scan FALSE_POSITIVE without writing a full report."""
    payload = request.get_json(force=True) or {}
    notes = (payload.get("notes") or "").strip()

    doc, err = _transition_scan(
        ObjectId(scan_id),
        from_states=["SCANNED", "UNDER_REVIEW", "ESCALATED"],
        to_state="FALSE_POSITIVE",
        reason=notes or "Marked as false positive",
        actor_req=request,
    )
    if err:
        code, status = err
        return jsonify({"error": code}), status

    return jsonify({"scan_id": scan_id, "state": doc["state"]}), 200

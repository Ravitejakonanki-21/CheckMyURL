from bson import ObjectId
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity

from models.scan_model import create_scan, list_scans_for_user
from models.user_model import get_user_by_email
from tasks.scan_tasks import enqueue_scan_task
from utils.validation import validate_url_input


bp = Blueprint("scans", __name__, url_prefix="/api/scans")


@bp.post("")
@jwt_required()
def submit_scan():
    """
    Submit a URL for asynchronous scanning.
    State flow: SUBMITTED -> SCANNING -> SCANNED (by Celery worker).
    """
    payload = request.get_json(force=True) or {}
    raw_url = (payload.get("url") or "").strip()

    ok, err = validate_url_input(raw_url)
    if not ok:
        return jsonify({"error": "invalid_url", "detail": err}), 400

    email = get_jwt_identity()
    user = get_user_by_email(email)
    if not user:
        return jsonify({"error": "user_not_found"}), 404

    scan_id = create_scan(raw_url, user["_id"])
    task_id = enqueue_scan_task(str(scan_id))

    # Mark as SCANNING and attach task ID
    from models.scan_model import update_scan_state

    update_scan_state(ObjectId(scan_id), "SCANNING", {"celery_task_id": task_id})

    return (
        jsonify(
            {
                "scan_id": str(scan_id),
                "task_id": task_id,
                "state": "SCANNING",
            }
        ),
        202,
    )


@bp.get("/<scan_id>")
@jwt_required()
def get_scan(scan_id: str):
    """
    Return a single scan by ID for the current user.
    Useful for polling async scan status after submission.
    """
    email = get_jwt_identity()
    user = get_user_by_email(email)
    if not user:
        return jsonify({"error": "user_not_found"}), 404

    from models.scan_model import get_scan_for_user

    doc = get_scan_for_user(ObjectId(scan_id), user["_id"])
    if not doc:
        return jsonify({"error": "scan_not_found"}), 404

    doc["_id"] = str(doc["_id"])
    doc["submitted_by"] = str(doc["submitted_by"])
    return jsonify(doc), 200


@bp.get("/mine")
@jwt_required()
def get_my_scans():
    """
    Return scans submitted by the current user, most recent first.
    """
    email = get_jwt_identity()
    user = get_user_by_email(email)
    if not user:
        return jsonify({"error": "user_not_found"}), 404

    docs = list_scans_for_user(user["_id"])
    for d in docs:
        d["_id"] = str(d["_id"])
        d["submitted_by"] = str(d["submitted_by"])
    return jsonify(docs), 200



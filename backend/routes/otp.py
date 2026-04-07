"""
OTP-based registration routes.
Blueprint prefix: /api
"""
import os
import random
import string
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request, current_app
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer

from models.mongo_client import get_collection
from models.user_model import get_user_by_email

bp = Blueprint("otp", __name__, url_prefix="/api")

_otp_tokens = get_collection("otp_tokens")

# Ensure TTL index so expired OTPs auto-delete after 15 minutes
try:
    _otp_tokens.create_index("created_at", expireAfterSeconds=900)
except Exception:
    pass  # index may already exist


def _generate_otp(length: int = 6) -> str:
    return "".join(random.choices(string.digits, k=length))


@bp.post("/send-otp")
def send_otp():
    """Send a 6-digit OTP to the provided email for registration."""
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Check if user already exists
    if get_user_by_email(email):
        return jsonify({"error": "Email is already registered. Please log in instead."}), 409

    # Check mail configuration
    mail_user = os.getenv("MAIL_USERNAME", "")
    mail_pass = os.getenv("MAIL_PASSWORD", "")
    if not mail_user or not mail_pass:
        return jsonify({"error": "Email service is not configured. Please contact the administrator."}), 503

    # Rate limit: max 3 OTPs per email in 10 minutes
    recent_count = _otp_tokens.count_documents({
        "email": email,
        "created_at": {"$gte": datetime.utcnow() - timedelta(minutes=10)},
    })
    if recent_count >= 3:
        return jsonify({"error": "Too many OTP requests. Please wait before trying again."}), 429

    otp_code = _generate_otp()

    # Store OTP in MongoDB
    _otp_tokens.insert_one({
        "email": email,
        "otp": otp_code,
        "verified": False,
        "created_at": datetime.utcnow(),
    })

    # Send OTP email
    from flask_mail import Mail
    mail = Mail(current_app)

    msg = Message("Your CYBERSHIELD Registration OTP", recipients=[email])
    msg.body = f"Your OTP for CYBERSHIELD registration is: {otp_code}\n\nThis code expires in 10 minutes."
    msg.html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:auto">
      <h2 style="color:#0891b2">CYBERSHIELD Registration</h2>
      <p>Your one-time password (OTP) is:</p>
      <div style="font-size:32px;font-weight:bold;letter-spacing:8px;color:#0891b2;
                  background:#f0fdfa;padding:16px 24px;border-radius:12px;text-align:center;
                  margin:16px 0;border:2px dashed #0891b2">
        {otp_code}
      </div>
      <p>This code expires in <strong>10 minutes</strong>.</p>
      <p style="margin-top:24px;color:#6b7280;font-size:13px">
        If you didn't request this, you can safely ignore this email.
      </p>
    </div>
    """

    try:
        mail.send(msg)
    except Exception as e:
        current_app.logger.error(f"Failed to send OTP email to {email}: {e}")
        return jsonify({"error": f"Failed to send OTP email. Please check server mail configuration. Details: {str(e)}"}), 500

    return jsonify({"message": f"OTP sent to {email}. Please check your inbox."}), 200


@bp.post("/verify-otp")
def verify_otp():
    """Verify the OTP provided by the user."""
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    otp_input = (data.get("otp") or "").strip()

    if not email or not otp_input:
        return jsonify({"error": "Email and OTP are required"}), 400

    # Find the most recent unverified OTP for this email (within 10 min)
    otp_doc = _otp_tokens.find_one(
        {
            "email": email,
            "verified": False,
            "created_at": {"$gte": datetime.utcnow() - timedelta(minutes=10)},
        },
        sort=[("created_at", -1)],
    )

    if not otp_doc:
        return jsonify({"error": "No valid OTP found. It may have expired. Please request a new one."}), 400

    if otp_doc["otp"] != otp_input:
        return jsonify({"error": "Invalid OTP. Please check and try again."}), 400

    # Mark as verified
    _otp_tokens.update_one({"_id": otp_doc["_id"]}, {"$set": {"verified": True}})

    # Generate a short-lived verification token
    serializer = URLSafeTimedSerializer(current_app.config["JWT_SECRET_KEY"])
    verification_token = serializer.dumps(email, salt="otp-verified")

    return jsonify({
        "message": "OTP verified successfully!",
        "verification_token": verification_token,
    }), 200


@bp.post("/register-with-otp")
def register_with_otp():
    """Complete registration using a verified OTP token."""
    data = request.get_json() or {}
    token = data.get("verification_token", "")
    password = data.get("password", "")

    if not token or not password:
        return jsonify({"error": "Verification token and password are required"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    # Verify the token (valid for 15 minutes)
    serializer = URLSafeTimedSerializer(current_app.config["JWT_SECRET_KEY"])
    try:
        from itsdangerous import BadSignature, SignatureExpired
        email = serializer.loads(token, salt="otp-verified", max_age=900)
    except SignatureExpired:
        return jsonify({"error": "Verification expired. Please start over."}), 400
    except BadSignature:
        return jsonify({"error": "Invalid verification token."}), 400

    # Check if user already exists (race condition guard)
    if get_user_by_email(email):
        return jsonify({"error": "Email is already registered."}), 409

    # Create the user
    from flask_bcrypt import Bcrypt
    bcrypt = Bcrypt(current_app)
    hashed = bcrypt.generate_password_hash(password).decode("utf-8")

    from models.user_model import create_user
    create_user(email, hashed, role="USER")

    # Clean up OTP tokens for this email
    _otp_tokens.delete_many({"email": email})

    return jsonify({"message": "Registration successful! Please log in."}), 201

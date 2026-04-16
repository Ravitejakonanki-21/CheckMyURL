"""
OTP-based registration routes.
Blueprint prefix: /api
"""
import os
import random
import string
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request, current_app
from itsdangerous import URLSafeTimedSerializer

from models.mongo_client import get_collection
from models.user_model import get_user_by_email

bp = Blueprint("otp", __name__, url_prefix="/api")

_otp_col_instance = None

def _otp_col():
    """Lazy getter — defers DNS/SRV resolution until first request."""
    global _otp_col_instance
    if _otp_col_instance is None:
        _otp_col_instance = get_collection("otp_tokens")
        # Ensure TTL index so expired OTPs auto-delete after 15 minutes
        try:
            _otp_col_instance.create_index("created_at", expireAfterSeconds=900)
        except Exception:
            pass  # index may already exist
    return _otp_col_instance



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

    # Rate limit: max 3 OTPs per email in 10 minutes
    recent_count = _otp_col().count_documents({

        "email": email,
        "created_at": {"$gte": datetime.utcnow() - timedelta(minutes=10)},
    })
    if recent_count >= 3:
        return jsonify({"error": "Too many OTP requests. Please wait before trying again."}), 429

    otp_code = _generate_otp()

    # Store OTP in MongoDB
    _otp_col().insert_one({

        "email": email,
        "otp": otp_code,
        "verified": False,
        "created_at": datetime.utcnow(),
    })

    # Send OTP email via SendGrid
    mail_user = current_app.config.get("MAIL_USERNAME") or ""
    current_app.logger.info(f"[OTP] Sending to {email}, MAIL_USERNAME={mail_user}")

    if not mail_user:
        current_app.logger.error("[OTP] MAIL_USERNAME not set!")
        return jsonify({"error": "Email service is not configured. Please set MAIL_USERNAME on the server."}), 503

    body_text = f"Hello,\n\nYour one-time password (OTP) for CheckMyURL registration is: {otp_code}\n\nThis code is valid for 10 minutes.\n\nIf you did not request this code, please ignore this email.\n\nBest regards,\nThe CheckMyURL Team"
    body_html = f"""
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 550px; margin: 0 auto; color: #1f2937; border: 1px solid #e5e7eb; border-radius: 12px; overflow: hidden;">
      <div style="background-color: #0891b2; padding: 24px; text-align: center;">
        <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 600;">CheckMyURL</h1>
      </div>
      <div style="padding: 32px; text-align: center; line-height: 1.6;">
        <h2 style="color: #0891b2; margin-top: 0; font-size: 20px;">Verify Your Email</h2>
        <p>Use the following one-time password (OTP) to complete your registration. This code is valid for <strong>10 minutes</strong>.</p>
        <div style="font-size: 36px; font-weight: 700; letter-spacing: 6px; color: #0891b2; background-color: #f0fdfa; padding: 20px; border-radius: 12px; margin: 24px 0; border: 2px dashed #0891b2; display: inline-block;">
          {otp_code}
        </div>
        <p style="font-size: 14px; color: #6b7280;">If you didn't request this, you can safely ignore this email.</p>
        <hr style="border: 0; border-top: 1px solid #e5e7eb; margin: 32px 0;" />
        <p style="font-size: 13px; color: #0891b2; font-weight: 600;">Stay Secure. Always Check the URL.</p>
      </div>
      <div style="background-color: #f9fafb; padding: 20px; text-align: center; font-size: 12px; color: #9ca3af;">
        <p style="margin: 0;">&copy; {datetime.utcnow().year} CheckMyURL Security. All rights reserved.</p>
        <p style="margin: 4px 0 0;">This is an automated security notification.</p>
      </div>
    </div>
    """

    try:
        from utils.mailer import send_email
        send_email(
            subject="[OTP] Verify your CheckMyURL registration",
            to_email=email,
            body_text=body_text,
            body_html=body_html,
            mail_username=mail_user,
            from_name="CheckMyURL Security"
        )

    except Exception as e:
        current_app.logger.error(f"Failed to send OTP email to {email}: {e}")
        return jsonify({"error": f"Failed to send OTP: {str(e)}"}), 500

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
    otp_doc = _otp_col().find_one(

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
    _otp_col().update_one({"_id": otp_doc["_id"]}, {"$set": {"verified": True}})


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
    _otp_col().delete_many({"email": email})


    return jsonify({"message": "Registration successful! Please log in."}), 201

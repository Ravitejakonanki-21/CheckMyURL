from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import logging
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_mail import Mail, Message

# === Load environment variables from .env ===
load_dotenv()

# === Utility, Risk, Analyzer Services ===
from services.ssl_check import check_ssl
from services.whois_check import check_whois
from services.unicode_idn import check_unicode_domain
from services.content_rules import check_keywords
from services.headers_check import check_headers
from services.risk_engine import compute_risk
from services.simple_cache import cache
from services.utils import timed_call

# === Auth/Database ===
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from pymongo import MongoClient

app = Flask(__name__)
CORS(app)
app.logger.setLevel(logging.INFO)

# === All Configurations ===
app.config['DEBUG'] = True
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Securely loaded from .env
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Securely loaded from .env
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@checkmyurl.com'

jwt = JWTManager(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'])

# === MongoDB Connection ===
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["url_checker"]
users = db.users


# === Feature gating function ===
def is_feature_unlocked(user, feature):
    if feature == "export_logs" and user["subscription_level"] == "free":
        return False, "Upgrade to Pro or Enterprise to export logs."
    if feature == "ml_scan" and user["subscription_level"] != "enterprise":
        return False, "Upgrade to Enterprise for AI-powered scanning."
    # Add more feature checks as needed
    return True, ""


# === Logging ===
@app.before_request
def _log_request():
    app.logger.info(f"{datetime.utcnow().isoformat()}Z {request.method} {request.path}")


# === Serve Home ===
@app.get("/")
def home():
    return send_from_directory(os.path.join(app.root_path, "static"), "index.html")


# === URL Analysis ===
@app.post("/analyze")
def analyze():
    data = request.get_json(force=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400

    cache_key = url.lower()
    cached = cache.get(cache_key)
    if cached:
        return jsonify(cached)

    parsed = urlparse(url if "://" in url else "https://" + url)
    hostname = parsed.hostname or url

    ssl_info, t_ssl, e_ssl = timed_call(check_ssl, hostname)
    whois_info, t_whois, e_whois = timed_call(check_whois, hostname)
    idn_info, t_idn, e_idn = timed_call(check_unicode_domain, hostname)
    rules_info, t_rules, e_rules = timed_call(check_keywords, url)
    headers_info, t_head, e_head = timed_call(check_headers, url)

    timings = {
        "ssl_ms": int(t_ssl * 1000),
        "whois_ms": int(t_whois * 1000),
        "idn_ms": int(t_idn * 1000),
        "rules_ms": int(t_rules * 1000),
        "headers_ms": int(t_head * 1000)
    }
    errors = {
        "ssl": e_ssl, "whois": e_whois, "idn": e_idn, "rules": e_rules, "headers": e_head
    }

    results = {
        "ssl": ssl_info,
        "whois": whois_info,
        "idn": idn_info,
        "rules": rules_info,
        "headers": headers_info,
        "timings": timings,
        "errors": errors
    }

    risk_score, label, reasons = compute_risk(results)

    response = {
        "url": url,
        "results": results,
        "reasons": reasons,
        "risk_score": risk_score,
        "label": label
    }
    cache.set(cache_key, response)
    return jsonify(response)


# === WHOIS Endpoint ===
@app.post("/whois_check")
def whois_check_endpoint():
    data = request.get_json(force=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"errors": ["url required"]}), 400
    try:
        whois_info = check_whois(url)
        return jsonify(whois_info)
    except Exception as e:
        app.logger.error(f"WHOIS check failed for {url}: {str(e)}")
        return jsonify({
            "errors": [f"WHOIS lookup failed: {str(e)}"],
            "domain": url,
            "risk_score": 0,
            "classification": "Error",
            "risk_factors": []
        }), 500


# === Health Endpoint ===
@app.get("/health")
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat() + "Z"})


# === Static Files ===
@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(os.path.join(app.root_path, "static"), path)


# =========================
#    AUTHENTICATION ROUTES
# =========================


@app.post('/register')
def register():
    data = request.get_json()
    email = (data.get('email') or "").lower()
    password = data.get('password')

    if users.find_one({'email': email}):
        return jsonify({'error': 'Email already registered'}), 409

    hashed = bcrypt.generate_password_hash(password).decode('utf-8')
    users.insert_one({
        'email': email,
        'password_hash': hashed,
        'credits': 10,
        'subscription_level': 'free',
        'created_at': datetime.utcnow()
    })
    return jsonify({'message': 'Registration successful!'}), 201


@app.post('/login')
def login():
    data = request.get_json()
    email = (data.get('email') or "").lower()
    password = data.get('password')

    user = users.find_one({'email': email})
    if (not user) or (not bcrypt.check_password_hash(user['password_hash'], password)):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = create_access_token(identity=email)
    return jsonify({
        'token': token,
        'email': user['email'],
        'credits': user['credits'],
        'subscription_level': user['subscription_level']
    })


# === Export Logs Route with Feature Gate ===
@app.post('/export-logs')
@jwt_required()
def export_logs():
    email = get_jwt_identity()
    user = users.find_one({"email": email})
    
    allowed, note = is_feature_unlocked(user, "export_logs")
    if not allowed:
        return jsonify({"error": "Feature locked!", "note": note}), 403
    
    # Your export logic here
    return jsonify({"message": "Exported logs successfully."})


# === Forgot Password ===
@app.post("/forgot-password")
def forgot_password():
    data = request.get_json()
    email = data.get("email", "").lower()

    user = users.find_one({"email": email})
    if not user:
        return jsonify({"message": "If the email exists, instructions have been sent."}), 200

    token = serializer.dumps(email, salt="password-reset")
    reset_link = f"http://192.168.56.1:3000/reset-password/{token}"

    msg = Message("Password Reset Request", recipients=[email])
    msg.body = f"To reset your password, click the link: {reset_link}"
    msg.html = f"<p>Click <a href='{reset_link}'>here</a> to reset your password.</p>"
    mail.send(msg)

    return jsonify({"message": f"Reset instructions sent to {email}."}), 200


# === Reset Password ===
@app.post("/reset-password")
def reset_password():
    data = request.get_json()
    token = data.get("token")
    new_password = data.get("password")

    try:
        email = serializer.loads(token, salt="password-reset", max_age=3600)
    except SignatureExpired:
        return jsonify({"error": "Reset link expired"}), 400
    except BadSignature:
        return jsonify({"error": "Invalid or tampered link"}), 400

    hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
    users.update_one({"email": email}, {"$set": {"password_hash": hashed_pw}})

    return jsonify({"message": "Password reset successful!"}), 200


# === Protected Profile ===
@app.get('/profile')
@jwt_required()
def profile():
    email = get_jwt_identity()
    user = users.find_one({'email': email})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'email': user['email'],
        'credits': user['credits'],
        'subscription_level': user['subscription_level'],
        'created_at': user['created_at']
    })

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import logging
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_mail import Mail, Message

load_dotenv()

from services.ssl_check import check_ssl
from services.whois_check import check_whois
from services.unicode_idn import check_unicode_domain
from services.keyword_check import check_url_for_keywords
from services.content_rules import check_keywords
from services.headers_check import check_headers
from services.risk_engine import compute_risk
from services.simple_cache import cache
from services.utils import timed_call

from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from pymongo import MongoClient

app = Flask(__name__)
CORS(app)
app.logger.setLevel(logging.INFO)

app.config['DEBUG'] = True
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@checkmyurl.com'

jwt = JWTManager(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'])

mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["url_checker"]
users = db.users

@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Expect-CT'] = 'max-age=86400, enforce, report-uri="https://example.com/report"'
    response.headers['Report-To'] = '{"group":"default","max_age":10886400,"endpoints":[{"url":"https://example.com/reports"}],"include_subdomains":true}'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'"
    return response

def is_feature_unlocked(user, feature):
    if feature == "export_logs" and user["subscription_level"] == "free":
        return False, "Upgrade to Pro or Enterprise to export logs."
    if feature == "ml_scan" and user["subscription_level"] != "enterprise":
        return False, "Upgrade to Enterprise for AI-powered scanning."
    return True, ""

@app.before_request
def _log_request():
    app.logger.info(f"{datetime.utcnow().isoformat()}Z {request.method} {request.path}")

@app.get("/")
def home():
    return send_from_directory(os.path.join(app.root_path, "static"), "index.html")

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
    keyword_info, t_keyword, e_keyword = timed_call(check_url_for_keywords, url)
    rules_info, t_rules, e_rules = timed_call(check_keywords, url)
    headers_info, t_head, e_head = timed_call(check_headers, url)

    whois_info = ensure_whois_fields_complete(whois_info)

    timings = {
        "ssl_ms": int(t_ssl * 1000),
        "whois_ms": int(t_whois * 1000),
        "idn_ms": int(t_idn * 1000),
        "keyword_ms": int(t_keyword * 1000),
        "rules_ms": int(t_rules * 1000),
        "headers_ms": int(t_head * 1000),
    }
    errors = {
        "ssl": e_ssl,
        "whois": e_whois,
        "idn": e_idn,
        "keyword": e_keyword,
        "rules": e_rules,
        "headers": e_head,
    }

    results = {
        "ssl": ssl_info,
        "whois": whois_info,
        "idn": idn_info,
        "keyword": keyword_info,
        "rules": rules_info,
        "headers": headers_info,
        "timings": timings,
        "errors": errors,
    }

    risk_score, label, reasons = compute_risk(results)

    response = {
        "url": url,
        "results": results,
        "reasons": reasons,
        "risk_score": risk_score,
        "label": label,
    }
    cache.set(cache_key, response)
    return jsonify(response)

def ensure_whois_fields_complete(whois_info):
    expected_fields = {
        "domain": None,
        "registrar": None,
        "creation_date": None,
        "updated_date": None,
        "expiration_date": None,
        "age_days": None,
        "privacy_protected": False,
        "registrant": None,
        "admin_email": None,
        "tech_email": None,
        "name_servers": [],
        "country": None,
        "statuses": [],
        "risk_score": 0,
        "classification": "Unknown",
        "risk_factors": [],
        "errors": [],
        "registrant_organization": None,
        "registrant_country": None,
        "registry_domain_id": None,
        "registrar_iana_id": None,
        "registrar_abuse_email": None,
        "registrar_abuse_phone": None,
        "dnssec": None
    }

    for field, default in expected_fields.items():
        if field not in whois_info or whois_info[field] is None:
            whois_info[field] = default

    # Warranty: Extract fallback values from alt keys for old data
    # (add this block for extra robustness, in case parser misspells a field)
    alt_keys = {
        "registrar_iana_id": ["registrarinaid", "registrarianaid"],
        "registrar_abuse_email": ["registrarabuseemail", "registrarabuse_email"],
        "registrar_abuse_phone": ["registrarabusephone", "registrarabuse_phone"],
    }
    for main, alts in alt_keys.items():
        for alt in alts:
            if not whois_info.get(main) and whois_info.get(alt):
                whois_info[main] = whois_info[alt]

    if whois_info.get("name_servers") is None:
        whois_info["name_servers"] = []
    if whois_info.get("statuses") is None:
        whois_info["statuses"] = []
    if whois_info.get("risk_factors") is None:
        whois_info["risk_factors"] = []
    if whois_info.get("errors") is None:
        whois_info["errors"] = []
    return whois_info

@app.post("/api/check-headers")
def api_check_headers():
    data = request.get_json(force=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    try:
        headers_info = check_headers(url)
        return jsonify(headers_info)
    except Exception as e:
        app.logger.error(f"Header check failed for {url}: {str(e)}")
        return jsonify({
            "errors": [f"Header check failed: {str(e)}"]
        }), 500

@app.post("/whois_check")
def whois_check_endpoint():
    data = request.get_json(force=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"errors": ["url required"]}), 400
    try:
        whois_info = check_whois(url)
        whois_info = ensure_whois_fields_complete(whois_info)
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

@app.get("/health")
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat() + "Z"})

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(os.path.join(app.root_path, "static"), path)

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

@app.post('/export-logs')
@jwt_required()
def export_logs():
    email = get_jwt_identity()
    user = users.find_one({"email": email})
    allowed, note = is_feature_unlocked(user, "export_logs")
    if not allowed:
        return jsonify({"error": "Feature locked!", "note": note}), 403
    return jsonify({"message": "Exported logs successfully."})

@app.post("/forgot-password")
def forgot_password():
    data = request.get_json()
    email = data.get("email", "").lower()
    user = users.find_one({"email": email})
    if not user:
        return jsonify({"message": "If the email exists, instructions have been sent."}), 200
    token = serializer.dumps(email, salt="password-reset")
    reset_link = f"http://localhost:3000/reset-password/{token}"
    msg = Message("Password Reset Request", recipients=[email])
    msg.body = f"To reset your password, click the link: {reset_link}"
    msg.html = f"<p>Click <a href='{reset_link}'>here</a> to reset your password.</p>"
    mail.send(msg)
    return jsonify({"message": f"Reset instructions sent to {email}."}), 200

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
    app.run(debug=True, host="0.0.0.0", port=5000)

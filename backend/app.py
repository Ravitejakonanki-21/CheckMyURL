from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()  # tries CWD and walks up
# Also try loading from parent directory explicitly (for when CWD is backend/)
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.env'))

from services.ssl_check import check_ssl
from services.whois_check import check_whois
from services.unicode_idn import check_unicode_domain
from services.keyword_check import check_url_for_keywords
from services.content_rules import check_keywords
from services.headers_check import check_headers
from services.risk_engine import compute_risk
from services.ml_scoring import _extract_feature_values
from services.ascii_unicode_check import validate_ascii_unicode
from services.simple_cache import cache
from services.utils import timed_call
from utils.ml_predictor import load_production_model, predict_url_risk

from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)

from models.mongo_client import ensure_indexes, get_collection
from models.user_model import get_user_by_email, create_user
from routes import all_blueprints

app = Flask(__name__)
CORS(app)
app.logger.setLevel(logging.INFO)

app.config["DEBUG"] = True
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "super-secret-key")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(
    seconds=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", "1800"))
)
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
# Gmail SMTP requires the sender to match the authenticated account
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME", "noreply@checkmyurl.com")

# Log mail config status at startup
if app.config["MAIL_USERNAME"]:
    print(f"[MAIL] Configured with sender: {app.config['MAIL_USERNAME']}")
else:
    print("[MAIL] WARNING: MAIL_USERNAME not set — email features (OTP, password reset) will not work!")

jwt = JWTManager(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config["JWT_SECRET_KEY"])

# Global thread pool for I/O tasks (parallelizing scans and background DB saves)
executor = ThreadPoolExecutor(max_workers=20)

# Load production ML model once at startup
MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "phishing_rf_production.pkl")
META_PATH = os.path.join(os.path.dirname(__file__), "models", "model_metadata.json")

try:
    model, metadata = load_production_model(MODEL_PATH, META_PATH)
    app.logger.info(f"Production ML model loaded from {MODEL_PATH}")
except Exception as e:
    app.logger.error(f"Failed to load production ML model: {e}")
    model, metadata = None, None

# Rate limiter — uses Redis when available, falls back to in-memory
_redis_url = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
# rediss:// URLs require ssl_cert_reqs param (CERT_REQUIRED or none/optional)
if _redis_url.startswith("rediss://"):
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    parsed = urlparse(_redis_url)
    query = parse_qs(parsed.query)
    if "ssl_cert_reqs" in query:
        _cert_reqs = query["ssl_cert_reqs"][0].lower()
    else:
        _cert_reqs = os.getenv("REDIS_SSL_CERT_REQS", "none").lower()
        
    if _cert_reqs in ("cert_none", "none"): _cert_reqs = "none"
    elif _cert_reqs in ("cert_required", "required"): _cert_reqs = "required"
    elif _cert_reqs in ("cert_optional", "optional"): _cert_reqs = "optional"
        
    query["ssl_cert_reqs"] = [_cert_reqs]
    new_query = urlencode(query, doseq=True)
    _redis_url = urlunparse(parsed._replace(query=new_query))

# Simple check to see if we should fallback to memory://
storage_uri = _redis_url
if "localhost" in _redis_url or "127.0.0.1" in _redis_url:
    try:
        import socket
        # Quick check if something is on 6379
        with socket.create_connection(("localhost", 6379), timeout=0.1):
            pass
    except (ConnectionRefusedError, socket.timeout, OSError):
        storage_uri = "memory://"
        app.logger.warning("Redis not found on localhost, falling back to in-memory rate limiting")

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=storage_uri,
    default_limits=["200/minute"],
)

# Use the shared MongoDB client from models layer (respects MONGO_URI env var)
_users_col = get_collection("users")

# Ensure DB indexes for SOC collections
try:
    ensure_indexes()
    app.logger.info("MongoDB indexes ensured")
except Exception as e:
    app.logger.error(f"MongoDB index creation failed: {e}")

# Register SOC-related blueprints (scans, analyst workflow)
for bp in all_blueprints:
    app.register_blueprint(bp)

@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'
    response.headers['Cross-Origin-Embedder-Policy'] = 'unsafe-none'
    response.headers['Cross-Origin-Resource-Policy'] = 'cross-origin'
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



@app.post("/analyze")
@limiter.limit("30/minute")
def analyze():
    data = request.get_json(force=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400

    try:
        cache_key = url.lower()
        cached = cache.get(cache_key)
        if cached:
            return jsonify(cached)

        parsed = urlparse(url if "://" in url else "https://" + url)
        hostname = parsed.hostname or url
        is_http_url = parsed.scheme == "http"

        # Parallelize all independent service checks
        future_ssl = executor.submit(timed_call, check_ssl, hostname)
        future_whois = executor.submit(timed_call, check_whois, hostname)
        future_idn = executor.submit(timed_call, check_unicode_domain, hostname, url)
        future_ascii = executor.submit(timed_call, validate_ascii_unicode, url)
        future_keyword = executor.submit(timed_call, check_url_for_keywords, url)
        future_rules = executor.submit(timed_call, check_keywords, url)
        future_headers = executor.submit(timed_call, check_headers, url)

        # Harvest results (wait for all to complete in parallel)
        ssl_info, t_ssl, e_ssl = future_ssl.result()
        whois_info, t_whois, e_whois = future_whois.result()
        idn_info, t_idn, e_idn = future_idn.result()
        ascii_unicode_info, t_ascii, e_ascii = future_ascii.result()
        keyword_info, t_keyword, e_keyword = future_keyword.result()
        rules_info, t_rules, e_rules = future_rules.result()
        headers_info, t_head, e_head = future_headers.result()

        if ssl_info and is_http_url:
            # URL was explicitly submitted as http:// — treat as no secure channel,
            # regardless of what is reachable on port 443.
            ssl_info["https_ok"] = False
            ssl_info["is_http_only"] = True
            ssl_info.setdefault("errors", []).append("url_scheme_is_http_not_https")

        whois_info = ensure_whois_fields_complete(whois_info)

        timings = {
            "ssl_ms": int(t_ssl * 1000),
            "whois_ms": int(t_whois * 1000),
            "idn_ms": int(t_idn * 1000),
            "ascii_unicode_ms": int(t_ascii * 1000),
            "keyword_ms": int(t_keyword * 1000),
            "rules_ms": int(t_rules * 1000),
            "headers_ms": int(t_head * 1000),
        }
        errors = {
            "ssl": e_ssl,
            "whois": e_whois,
            "idn": e_idn,
            "ascii_unicode": e_ascii,
            "keyword": e_keyword,
            "rules": e_rules,
            "headers": e_head,
        }

        results = {
            "ssl": ssl_info,
            "whois": whois_info,
            "idn": idn_info,
            "ascii_unicode": ascii_unicode_info,
            "keyword": keyword_info,
            "rules": rules_info,
            "headers": headers_info,
            "timings": timings,
            "errors": errors,
        }

        heuristic_score, heuristic_label, heuristic_reasons = compute_risk(results)

        ml_output = None
        if model and metadata:
            try:
                # Extract features using existing service logic
                features = _extract_feature_values(url, results)
                # Predict using production model
                ml_result = predict_url_risk(features, model, metadata)
                
                # Map new output to existing API format (internal compatibility)
                ml_output = {
                    "ml_probability": ml_result["ml_probability"],
                    "ml_score": ml_result["ml_score"],
                    "is_phishing": ml_result["is_phishing"],
                    "score": ml_result["ml_score"],
                    "probability": ml_result["ml_probability"],
                    "label": "High Risk" if ml_result["is_phishing"] else ("Medium Risk" if ml_result["ml_score"] >= 40 else "Low Risk"),
                    "reasons": ["Production ML model analysis complete"]
                }
                
                if ml_result["is_phishing"]:
                    ml_output["reasons"].append(f"ML model predicts high probability of phishing ({ml_result['ml_probability']})")
                
                app.logger.info(f"ML Analysis for {url}: score={ml_result['ml_score']}, is_phishing={ml_result['is_phishing']}")
            except Exception as e:
                app.logger.exception(f"ML scoring critically failed for {url}: {e}")
                ml_output = None
        else:
            app.logger.warning("ML model or metadata not loaded, skipping prediction")

        # Compute weightages and averaged risk score. Safe handling of missing ML results.
        ml_weightage = ml_output.get("score") if ml_output else None
        checks_weightage = heuristic_score

        scores_for_average = [checks_weightage]
        if ml_weightage is not None:
            scores_for_average.append(ml_weightage)

        # Average the scores (heuristic vs ML)
        averaged_risk_score = int(round(sum(scores_for_average) / len(scores_for_average)))

        def label_from_score(score: int) -> str:
            if score >= 70:
                return "High Risk"
            if score >= 40:
                return "Medium Risk"
            return "Low Risk"

        label = label_from_score(averaged_risk_score)

        combined_reasons = []
        if ml_output:
            combined_reasons.extend(ml_output.get("reasons") or [])
        combined_reasons.extend(heuristic_reasons)

        response = {
            "url": url,
            "results": results,
            "heuristic": {
                "risk_score": heuristic_score,
                "label": heuristic_label,
                "reasons": heuristic_reasons,
            },
            "ml": ml_output,
            "weightages": {
                "ml_score": ml_weightage,
                "checks_score": checks_weightage,
                "average_score": averaged_risk_score,
            },
            "reasons": combined_reasons,
            "risk_score": averaged_risk_score,
            "label": label,
        }
        cache.set(cache_key, response)

        # Persist scan result to MongoDB for authenticated users in background
        email = None
        try:
            from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
            verify_jwt_in_request(optional=True)
            email = get_jwt_identity()
        except Exception:
            pass
    
        executor.submit(_persist_scan_result, url, response, email)

        return jsonify(response)
    except Exception as e:
        app.logger.exception(f"Fatal error during /analyze for {url}: {e}")
        return jsonify({
            "url": url,
            "error": "Internal analysis error",
            "risk_score": 0,
            "label": "Error",
            "reasons": [f"An unexpected error occurred: {str(e)}"]
        }), 500

def _persist_scan_result(url: str, response: dict, email: str | None = None) -> None:
    """
    Save the scan result to MongoDB in the background.
    """
    try:
        if not email:
            return
        from models.user_model import get_user_by_email
        from models.scan_model import create_scan, save_scan_results
        from utils.risk_explainable import build_explainable_risk
        user = get_user_by_email(email)
        if not user:
            return
        scan_id = create_scan(url, user["_id"])
        risk = build_explainable_risk(response.get("results", {}), response.get("ml"))
        save_scan_results(scan_id, risk, response.get("results", {}))
        from models.scan_model import update_scan_state
        update_scan_state(scan_id, "SCANNED")
    except Exception as exc:
        logging.debug(f"scan persistence skipped: {exc}")


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


@app.get("/api/history")
@limiter.limit("60/minute")
def get_scan_history():
    """
    Return the authenticated user's scan history from MongoDB (most recent first).
    Falls back to empty list if user has no scans yet.
    """
    from flask_jwt_extended import jwt_required, get_jwt_identity
    # Manual JWT enforcement so we can return a clean 401
    from flask_jwt_extended import verify_jwt_in_request
    try:
        verify_jwt_in_request()
    except Exception:
        return jsonify({"error": "authentication required"}), 401

    email = get_jwt_identity()
    from models.user_model import get_user_by_email
    from models.scan_model import list_scans_for_user
    user = get_user_by_email(email)
    if not user:
        return jsonify({"error": "user_not_found"}), 404

    docs = list_scans_for_user(user["_id"], limit=100)
    serialised = []
    for d in docs:
        d["_id"] = str(d["_id"])
        d["submitted_by"] = str(d["submitted_by"])
        # Flatten for the frontend ScanContext history format
        risk = d.get("risk") or {}
        serialised.append({
            "scanId":        d["_id"],
            "url":           d.get("url", ""),
            "riskScore":     risk.get("total_score", 0),
            "classification": risk.get("severity_level", "UNKNOWN"),
            "scannedAt":     d.get("submitted_at", "").isoformat() if hasattr(d.get("submitted_at", ""), "isoformat") else str(d.get("submitted_at", "")),
            "state":         d.get("state", "SCANNED"),
            "userEmail":     email,
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

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_static(path):
    static_folder = os.path.join(app.root_path, "static")
    if path != "" and os.path.exists(os.path.join(static_folder, path)):
        return send_from_directory(static_folder, path)
    return send_from_directory(static_folder, "index.html")

@app.post('/api/register')
@limiter.limit("5/minute")
def register():
    data = request.get_json() or {}
    email = (data.get('email') or "").lower()
    password = data.get('password') or ""
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    if get_user_by_email(email):
        return jsonify({'error': 'Email already registered'}), 409
    hashed = bcrypt.generate_password_hash(password).decode('utf-8')
    # create_user sets role='USER', credits=10, subscription_level='free'
    create_user(email, hashed, role='USER')
    return jsonify({'message': 'Registration successful!'}), 201

@app.post('/api/login')
@limiter.limit("5/minute")
def login():
    data = request.get_json() or {}
    email = (data.get('email') or "").lower()
    password = data.get('password') or ""

    user = get_user_by_email(email)
    if (not user) or (not bcrypt.check_password_hash(user['password_hash'], password)):
        return jsonify({'error': 'Invalid credentials'}), 401
    # Embed role in token so rbac.py (roles_required decorator) can read it
    additional_claims = {"role": user.get("role", "USER")}
    token = create_access_token(identity=email, additional_claims=additional_claims)
    return jsonify({
        'token': token,
        'email': user['email'],
        'credits': user.get('credits', 10),
        'subscription_level': user.get('subscription_level', 'free'),
        'role': user.get('role', 'USER')
    })

@app.post('/api/export-logs')
@jwt_required()
def export_logs():
    email = get_jwt_identity()
    user = get_user_by_email(email)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    allowed, note = is_feature_unlocked(user, "export_logs")
    if not allowed:
        return jsonify({"error": "Feature locked!", "note": note}), 403
    return jsonify({"message": "Exported logs successfully."})

@app.post("/api/forgot-password")
def forgot_password():
    data = request.get_json() or {}
    email = data.get("email", "").lower()
    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Debug: log mail config
    app.logger.info(f"[FORGOT-PW] MAIL_USERNAME={app.config.get('MAIL_USERNAME')}, MAIL_SERVER={app.config.get('MAIL_SERVER')}")

    user = get_user_by_email(email)
    if not user:
        # Return success anyway to prevent email enumeration
        return jsonify({"message": "If the email exists, reset instructions have been sent."}), 200

    token = serializer.dumps(email, salt="password-reset")
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")  # default to Vite port
    reset_link = f"{frontend_url}/reset-password/{token}"

    msg = Message("Password Reset Request", recipients=[email])
    msg.body = f"To reset your password, click the link:\n{reset_link}\n\nThis link expires in 1 hour."
    msg.html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:auto">
      <h2 style="color:#0891b2">CheckMyURL Password Reset</h2>
      <p>Click the button below to reset your password. This link expires in <strong>1 hour</strong>.</p>
      <a href="{reset_link}" style="display:inline-block;padding:12px 24px;background:#0891b2;color:#fff;border-radius:8px;text-decoration:none;font-weight:bold">Reset Password</a>
      <p style="margin-top:24px;color:#6b7280;font-size:13px">If you didn't request this, you can safely ignore this email.</p>
    </div>
    """

    try:
        mail.send(msg)
    except Exception as e:
        app.logger.error(f"Failed to send reset email to {email}: {e}")
        err_msg = str(e)
        if "authentication" in err_msg.lower() or "535" in err_msg:
            return jsonify({"error": "Email authentication failed. Please check MAIL_USERNAME and MAIL_PASSWORD (use Gmail App Password, not regular password)."}), 500
        elif "connection" in err_msg.lower() or "timeout" in err_msg.lower():
            return jsonify({"error": "Could not connect to email server. Please check MAIL_SERVER and MAIL_PORT settings."}), 500
        else:
            return jsonify({"error": f"Failed to send email: {err_msg}"}), 500

    return jsonify({"message": f"Reset instructions sent to {email}."}), 200

@app.post("/api/reset-password")
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
    _users_col.update_one({"email": email}, {"$set": {"password_hash": hashed_pw}})
    return jsonify({"message": "Password reset successful!"}), 200

@app.get('/api/profile')
@jwt_required()
def profile():
    email = get_jwt_identity()
    user = get_user_by_email(email)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'email': user['email'],
        'credits': user.get('credits', 10),
        'subscription_level': user.get('subscription_level', 'free'),
        'role': user.get('role', 'USER'),
        'created_at': user.get('created_at')
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", os.getenv("FLASK_RUN_PORT", "5001")))
    host = os.getenv("FLASK_RUN_HOST", "0.0.0.0")
    app.run(debug=True, host=host, port=port)

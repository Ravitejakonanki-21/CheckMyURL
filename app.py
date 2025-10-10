from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS 
import os
import logging
from datetime import datetime
from urllib.parse import urlparse

from services.ssl_check import check_ssl
from services.whois_check import check_whois
from services.unicode_idn import check_unicode_domain
from services.content_rules import check_keywords
from services.headers_check import check_headers
from services.risk_engine import compute_risk
from services.simple_cache import cache
from services.utils import timed_call
from services.config import config  # DEBUG, CACHE_TTL, REQUEST_TIMEOUT

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
app.logger.setLevel(logging.INFO)

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

    # Cache lookup (normalized key)
    cache_key = url.lower()
    cached = cache.get(cache_key)
    if cached:
        return jsonify(cached)

    # Normalize and extract hostname
    parsed = urlparse(url if "://" in url else "https://" + url)
    hostname = parsed.hostname or url

    # Run checks (timed and safe)
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

    # Aggregate
    results = {
        "ssl": ssl_info,
        "whois": whois_info,
        "idn": idn_info,
        "rules": rules_info,
        "headers": headers_info,
        "timings": timings,
        "errors": errors
    }

    # Risk scoring
    risk_score, label, reasons = compute_risk(results)

    # Build response and cache it
    response = {
        "url": url,
        "results": results,
        "reasons": reasons,
        "risk_score": risk_score,
        "label": label
    }
    cache.set(cache_key, response)
    return jsonify(response)
@app.get("/stats")
def get_stats():
    # Example: replace with your database or logic
    return jsonify({
        "total_scans": 1234,
        "active_urls": 856,
        "success_rate": 94.2,
        "avg_response": 1.2,
        "recent_activity": [
            {"url": "example1.com", "time": "2 hours ago", "status": "Success"},
            {"url": "example2.com", "time": "5 hours ago", "status": "Failed"},
            {"url": "example3.com", "time": "1 day ago", "status": "Success"},
        ]
    })


if __name__ == "__main__":
    app.run(debug=config.DEBUG)

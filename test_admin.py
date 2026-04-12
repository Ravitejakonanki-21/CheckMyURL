import sys
# fake flask context
from flask import Flask
app = Flask(__name__)
with app.app_context():
    try:
        from models.mongo_client import get_collection
        def _get_users(): return get_collection("users")
        def _get_scans(): return get_collection("scans")
        
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
        print("Success! Number of docs:", len(serialised))
    except Exception as e:
        import traceback
        traceback.print_exc()

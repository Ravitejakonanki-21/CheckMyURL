import json
from services.ssl_check import check_ssl
from services.whois_check import check_whois
from services.unicode_idn import check_unicode_domain
from services.content_rules import check_keywords
from services.headers_check import check_headers
from services.risk_engine import compute_risk

def run_one(url: str):
    from urllib.parse import urlparse
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = parsed.hostname or url

    ssl_info = check_ssl(host)
    whois_info = check_whois(host)
    idn_info = check_unicode_domain(host)
    rules_info = check_keywords(url)
    headers_info = check_headers(url)

    results = {
        "ssl": ssl_info,
        "whois": whois_info,
        "idn": idn_info,
        "rules": rules_info,
        "headers": headers_info
    }
    score, label, reasons = compute_risk(results)
    out = {
        "url": url,
        "label": label,
        "score": score,
        "reasons": reasons,
        "summary": {
            "https_ok": results["ssl"].get("https_ok"),
            "expired": results["ssl"].get("expired"),
            "age_days": results["whois"].get("age_days"),
            "idn": results["idn"].get("is_idn"),
            "mixed_scripts": results["idn"].get("mixed_confusable_scripts"),
            "suspicious_words": results["rules"].get("matched_suspicious"),
            "brands": results["rules"].get("matched_brands"),
            "redirects": results["headers"].get("redirects"),
            "status": results["headers"].get("status"),
        }
    }
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    urls = [
        "https://example.com",
        "http://neverssl.com",
        "https://secure-login-example.com/verify/account",
        "https://аррӏе.com"
    ]
    for u in urls:
        print("==============================================")
        run_one(u)

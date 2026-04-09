import re
from urllib.parse import urlparse

# Only words that are genuinely phishing-specific in a URL context.
# Broad words like 'login', 'account', 'secure', 'support', 'update', 'password'
# exist on virtually ALL legitimate sites — do NOT include them here.
SUSPICIOUS_WORDS = [
    "verify-account", "account-verify", "update-account", "secure-login",
    "bank-login", "free-gift", "account-locked", "account-suspend",
    "credential", "reactivate", "unauthorized", "validate-id",
    "signin-confirm", "reset-verify"
]

# Brand impersonation — only flag if brand appears in the HOST (not the real domain)
BRAND_WORDS = [
    "paypal", "netflix", "instagram", "whatsapp",
    "apple-id", "microsoft-login", "google-verify", "amazon-security"
]

def check_keywords(url: str):
    out = {
        "has_suspicious_words": False,
        "matched_suspicious": [],
        "has_brand_words_in_host": False,
        "matched_brands": [],
        "path_depth": 0
    }
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = parsed.hostname or ""
    path = parsed.path or ""

    low_host = host.lower()
    low_path = path.lower()
    text = low_host + " " + low_path

    matched_suspicious = sorted({w for w in SUSPICIOUS_WORDS if w in text})
    matched_brands = sorted({b for b in BRAND_WORDS if b in low_host})

    out["has_suspicious_words"] = bool(matched_suspicious)
    out["matched_suspicious"] = matched_suspicious
    out["has_brand_words_in_host"] = bool(matched_brands)
    out["matched_brands"] = matched_brands
    out["path_depth"] = len([p for p in path.split("/") if p])

    return out

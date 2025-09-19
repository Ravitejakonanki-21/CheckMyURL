import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "confirm", "unlock",
    "password", "credential", "billing", "invoice",
    "urgent", "suspend", "limited", "gift", "prize",
    "support", "helpdesk", "secure", "security",
    "account", "wallet"
]

BRAND_WORDS = [
    "apple", "microsoft", "google", "facebook", "amazon",
    "paypal", "netflix", "instagram", "whatsapp", "outlook"
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

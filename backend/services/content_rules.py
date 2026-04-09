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

# Brand names commonly impersonated in phishing URLs.
# These are flagged when found in a SUBDOMAIN or PATH — but NOT when the
# brand is the actual registered domain (e.g. paypal.com itself is safe).
BRAND_WORDS = [
    "paypal", "netflix", "instagram", "whatsapp", "apple",
    "microsoft", "google", "amazon", "facebook", "twitter",
    "linkedin", "dropbox", "adobe", "zoom", "outlook",
    "wellsfargo", "chase", "citibank", "barclays", "hsbc",
]

# Official domains for each brand — if the base domain matches, skip flagging
BRAND_OFFICIAL_DOMAINS = {
    "paypal": "paypal.com",
    "netflix": "netflix.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "zoom": "zoom.us",
    "outlook": "outlook.com",
    "wellsfargo": "wellsfargo.com",
    "chase": "chase.com",
    "citibank": "citibank.com",
    "barclays": "barclays.com",
    "hsbc": "hsbc.com",
}


def _get_base_domain(hostname: str) -> str:
    """Return eTLD+1: 'sub.google.com' -> 'google.com'"""
    parts = hostname.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname.lower()


def check_keywords(url: str):
    out = {
        "has_suspicious_words": False,
        "matched_suspicious": [],
        "has_brand_words_in_host": False,
        "matched_brands": [],
        "path_depth": 0
    }

    normalized = url if "://" in url else "https://" + url
    parsed  = urlparse(normalized)
    host    = (parsed.hostname or "").lower()
    path    = (parsed.path or "").lower()
    query   = (parsed.query or "").lower()

    base_domain = _get_base_domain(host)

    # Full text for suspicious keyword scan
    full_text = host + " " + path + " " + query

    # ── Suspicious phishing keywords ─────────────────────────────────────────
    matched_suspicious = sorted({w for w in SUSPICIOUS_WORDS if w in full_text})
    out["has_suspicious_words"] = bool(matched_suspicious)
    out["matched_suspicious"]   = matched_suspicious

    # ── Brand impersonation ───────────────────────────────────────────────────
    # A brand word in the URL is suspicious UNLESS the base domain IS that brand.
    # Examples flagged:   google.verify-account.com  | paypal.secure-login.net
    # Examples NOT flagged: google.com | paypal.com | www.google.com
    matched_brands = []
    for brand in BRAND_WORDS:
        official = BRAND_OFFICIAL_DOMAINS.get(brand, f"{brand}.com")
        # Skip if this IS the real brand domain or a legitimate subdomain of it
        if base_domain == official or base_domain.endswith("." + official):
            continue
        # Brand word found in subdomain or path but base domain is NOT the real brand
        if brand in host or brand in path:
            matched_brands.append(brand)

    out["has_brand_words_in_host"] = bool(matched_brands)
    out["matched_brands"]          = sorted(set(matched_brands))
    out["path_depth"] = len([p for p in path.split("/") if p])

    return out

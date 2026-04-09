from urllib.parse import urlparse

# Domains known to be legitimate — skip heuristic keyword/brand scoring for these
WHITELISTED_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
    "twitter.com", "x.com", "linkedin.com", "github.com", "paypal.com",
    "netflix.com", "youtube.com", "instagram.com", "reddit.com", "wikipedia.org",
    "stackoverflow.com", "outlook.com", "office.com", "icloud.com", "fb.com",
    "whatsapp.com", "dropbox.com", "adobe.com", "salesforce.com", "zoom.us",
}


def _base_domain(hostname: str) -> str:
    """Return eTLD+1 e.g. 'sub.google.com' -> 'google.com'"""
    parts = hostname.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname.lower()


def compute_risk(results: dict) -> tuple:
    score = 0
    reasons = []

    ssl   = results.get("ssl", {})
    whois = results.get("whois", {})
    idn   = results.get("idn", {})
    rules = results.get("rules", {})

    # Determine base domain (from whois or SSL subject CN)
    hostname = (whois.get("domain") or "").lower().strip()
    is_whitelisted = bool(hostname) and (
        hostname in WHITELISTED_DOMAINS or
        any(hostname.endswith("." + d) for d in WHITELISTED_DOMAINS)
    )

    # ── SSL ───────────────────────────────────────────────────────────────────
    if ssl.get("is_http_only"):
        score += 35; reasons.append("http_only_url")
    elif not ssl.get("https_ok"):
        score += 30; reasons.append("no_https")
    if ssl.get("expired"):
        score += 30; reasons.append("expired_cert")

    # ── WHOIS age ─────────────────────────────────────────────────────────────
    age_days = whois.get("age_days")
    if isinstance(age_days, (int, float)):
        age_days = int(age_days)
        if age_days < 30:
            score += 30; reasons.append("very_new_domain")
        elif age_days < 180:
            score += 15; reasons.append("new_domain")

    # ── IDN / Unicode homograph ───────────────────────────────────────────────
    if idn.get("is_idn"):
        score += 10; reasons.append("idn_domain")
    if idn.get("mixed_confusable_scripts"):
        score += 25; reasons.append("mixed_scripts")

    # ── Keyword / brand checks (skip for known-legitimate domains) ────────────
    if not is_whitelisted:
        if rules.get("has_suspicious_words"):
            # Phishing-specific compound keyword in URL path/hostname
            score += 10; reasons.append("phishy_words")
        if rules.get("has_brand_words_in_host"):
            # Brand impersonation: e.g. google.verify-account.com
            # Raised to 30 — detection is now precise (skips real brand domains)
            score += 30; reasons.append("brand_impersonation")

    # Clamp 0..100
    score = max(0, min(100, score))

    if score >= 70:
        label = "High Risk"
    elif score >= 40:
        label = "Medium Risk"
    else:
        label = "Low Risk"

    return score, label, reasons

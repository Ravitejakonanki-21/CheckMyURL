# backend/services/keyword_check.py

# Common, generic keywords (never high risk on their own)
COMMON_KEYWORDS = [
    "login", "signin", "sign-in", "sign_in", "log-in", "log_in"
]

# High-risk/blacklist keywords (phishing/red-flag terms)
HIGH_RISK_KEYWORDS = [
    "secure-login",
    "update-account",
    "verify",
    "reset-password",
    "free-gift",
    "account-verify",
    "confirm",
    "bank-login",
    "urgent",
    "unauthorized",
    "account-locked",
    "account-suspend",
    "validate",
    "credential",
    "reactivate"
]

def check_url_for_keywords(url: str):
    """
    Checks the given URL for common and high-risk keywords.
    Conservative: 'login' alone is not a risk, only part of combos or with red-flags.
    Returns a dictionary with keywords found, risk score, and risk factors.
    """
    out = {
        "url": url,
        "keywords_found": [],
        "risk_score": 0,
        "risk_factors": [],
        "errors": [],
    }

    try:
        url_lower = url.lower()

        found_common = [kw for kw in COMMON_KEYWORDS if kw in url_lower]
        found_high = [kw for kw in HIGH_RISK_KEYWORDS if kw in url_lower]
        found_keywords = found_common + found_high
        out["keywords_found"] = found_keywords

        # Main risk logic
        if found_high:
            # Direct risk: e.g. 'update-account', 'free-gift', etc.
            risk = 40 + (len(found_high) - 1) * 10
            out["risk_score"] += risk
            out["risk_factors"].append("High-risk keyword(s): " + ", ".join(found_high))
        if found_common:
            if not found_high:
                # Do NOT flag 'login' (or similar) by itself
                out["risk_score"] += 0
                out["risk_factors"].append("Common term(s) found (e.g. 'login'), but not risky alone.")
            else:
                # Combo: e.g. 'login' + 'update-account'
                out["risk_score"] += 10
                out["risk_factors"].append(
                    "Combination of common and high-risk keywords increases suspicion."
                )

    except Exception as e:
        out["errors"].append(str(e))

    return out

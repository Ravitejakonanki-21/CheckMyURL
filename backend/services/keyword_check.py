# backend/services/keyword_check.py

# Generic login-type words — present in almost all legitimate sites, not risky alone
COMMON_KEYWORDS = [
    "login", "signin", "sign-in", "sign_in", "log-in", "log_in"
]

# Genuinely phishing-specific compound keywords in URLs
HIGH_RISK_KEYWORDS = [
    "secure-login",
    "update-account",
    "account-verify",
    "account-locked",
    "account-suspend",
    "bank-login",
    "free-gift",
    "signin-confirm",
    "reset-verify",
    "validate-id",
    "credential",
    "reactivate",
    "unauthorized",
]

def check_url_for_keywords(url: str):
    """
    Checks the given URL for common and high-risk keywords.
    Conservative: broad words like 'login', 'account', 'verify' alone are NOT flagged.
    Only genuine phishing compound patterns trigger a risk score.
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
        found_high   = [kw for kw in HIGH_RISK_KEYWORDS if kw in url_lower]
        out["keywords_found"] = found_common + found_high

        if found_high:
            # Each high-risk compound keyword is a meaningful signal
            risk = 40 + (len(found_high) - 1) * 10
            out["risk_score"] += risk
            out["risk_factors"].append("High-risk phishing keyword(s): " + ", ".join(found_high))

            if found_common:
                # Combo of common + high-risk = extra suspicion
                out["risk_score"] += 10
                out["risk_factors"].append(
                    "Common login term combined with high-risk keyword increases suspicion."
                )
        # 'login' alone → no score, no flag

    except Exception as e:
        out["errors"].append(str(e))

    return out

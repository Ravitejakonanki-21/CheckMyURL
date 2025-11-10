import ipaddress
import os
import re
from functools import lru_cache
from urllib.parse import parse_qs, urlparse

import joblib
import numpy as np

MODEL_FILENAME = "phishing_rf_phiusiil.pkl"
MODEL_PATH = os.path.join(os.path.dirname(__file__), MODEL_FILENAME)
RANDOM_TOKEN_RE = re.compile(r"[A-Za-z0-9]{15,}")

# Whitelist of well-known legitimate domains to reduce false positives
LEGITIMATE_DOMAINS = {
    "google.com", "www.google.com", "google.co.uk", "google.ca", "google.com.au",
    "microsoft.com", "www.microsoft.com", "office.com", "outlook.com", "live.com",
    "apple.com", "www.apple.com", "icloud.com", "appleid.apple.com",
    "amazon.com", "www.amazon.com", "amazon.co.uk", "amazon.ca",
    "facebook.com", "www.facebook.com", "fb.com",
    "twitter.com", "www.twitter.com", "x.com",
    "linkedin.com", "www.linkedin.com",
    "github.com", "www.github.com",
    "paypal.com", "www.paypal.com",
    "netflix.com", "www.netflix.com",
    "youtube.com", "www.youtube.com",
    "instagram.com", "www.instagram.com",
    "reddit.com", "www.reddit.com",
    "wikipedia.org", "www.wikipedia.org",
    "stackoverflow.com", "www.stackoverflow.com",
    "example.com", "www.example.com",  # RFC 2606 reserved domain
    "example.org", "www.example.org",
    "example.net", "www.example.net",
}


class ModelNotAvailableError(RuntimeError):
    """Raised when the ML model file is missing or cannot be loaded."""


def _ensure_model_exists(path: str) -> None:
    if not os.path.exists(path):
        raise ModelNotAvailableError(
            f"Expected ML model pickle at {path}, but the file was not found."
        )


@lru_cache(maxsize=1)
def _load_model():
    """Load and cache the trained RandomForest model."""
    _ensure_model_exists(MODEL_PATH)
    return joblib.load(MODEL_PATH)


def _default_features():
    model = _load_model()
    return {name: 0.0 for name in model.feature_names_in_}


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if "://" not in url:
        return "https://" + url
    return url


def _count_numeric_chars(value: str) -> int:
    return sum(ch.isdigit() for ch in value)


def _extract_feature_values(url: str, results: dict) -> dict:
    features = _default_features()

    normalized_url = _normalize_url(url)
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    host_parts = [part for part in hostname.split(".") if part]
    base_domain = host_parts[-2] if len(host_parts) >= 2 else (host_parts[-1] if host_parts else "")
    subdomain = ".".join(host_parts[:-2]) if len(host_parts) > 2 else ""

    rules_info = results.get("rules") or {}

    features["id"] = 0.0
    features["NumDots"] = float(hostname.count(".") + path.count("."))
    features["SubdomainLevel"] = float(max(len(host_parts) - 2, 0))
    features["PathLevel"] = float(len([segment for segment in path.split("/") if segment]))
    features["UrlLength"] = float(len(normalized_url))
    features["NumDash"] = float(normalized_url.count("-"))
    features["NumDashInHostname"] = float(hostname.count("-"))
    features["AtSymbol"] = float("@" in normalized_url)
    features["TildeSymbol"] = float("~" in normalized_url)
    features["NumUnderscore"] = float(normalized_url.count("_"))
    features["NumPercent"] = float(normalized_url.count("%"))
    features["NumQueryComponents"] = float(len(parse_qs(query, keep_blank_values=True)))
    features["NumAmpersand"] = float(normalized_url.count("&"))
    features["NumHash"] = float(normalized_url.count("#"))
    features["NumNumericChars"] = float(_count_numeric_chars(normalized_url))
    features["NoHttps"] = float(parsed.scheme.lower() != "https")
    features["RandomString"] = float(bool(RANDOM_TOKEN_RE.search(path + query)))

    try:
        ipaddress.ip_address(hostname)
        features["IpAddress"] = 1.0
    except ValueError:
        features["IpAddress"] = 0.0

    features["DomainInSubdomains"] = float(bool(subdomain and base_domain and base_domain in subdomain))
    features["DomainInPaths"] = float(bool(base_domain and base_domain in path))
    features["HttpsInHostname"] = float("https" in hostname)
    features["HostnameLength"] = float(len(hostname))
    features["PathLength"] = float(len(path))
    features["QueryLength"] = float(len(query))
    features["DoubleSlashInPath"] = float("//" in path)
    features["NumSensitiveWords"] = float(len(rules_info.get("matched_suspicious") or []))
    features["EmbeddedBrandName"] = float(bool(rules_info.get("has_brand_words_in_host")))

    whois_info = results.get("whois") or {}
    whois_domain = (whois_info.get("domain") or "").lower()
    if hostname and whois_domain:
        features["FrequentDomainNameMismatch"] = float(not hostname.endswith(whois_domain))
    else:
        features["FrequentDomainNameMismatch"] = 0.0

    passthrough_defaults = {
        "PctExtHyperlinks": 0.0,
        "PctExtResourceUrls": 0.0,
        "ExtFavicon": 0.0,
        "InsecureForms": 0.0,
        "RelativeFormAction": 0.0,
        "ExtFormAction": 0.0,
        "AbnormalFormAction": 0.0,
        "PctNullSelfRedirectHyperlinks": 0.0,
        "FakeLinkInStatusBar": 0.0,
        "RightClickDisabled": 0.0,
        "PopUpWindow": 0.0,
        "SubmitInfoToEmail": 0.0,
        "IframeOrFrame": 0.0,
        "MissingTitle": 0.0,
        "ImagesOnlyInForm": 0.0,
        "SubdomainLevelRT": lambda: features["SubdomainLevel"],
        "UrlLengthRT": lambda: features["UrlLength"],
        "PctExtResourceUrlsRT": 0.0,
        "AbnormalExtFormActionR": 0.0,
        "ExtMetaScriptLinkRT": 0.0,
        "PctExtNullSelfRedirectHyperlinksRT": 0.0,
        "CLASS_LABEL": 0.0,
    }

    for name, fallback in passthrough_defaults.items():
        if name not in features:
            continue
        if callable(fallback):
            features[name] = float(fallback())
        else:
            features[name] = float(fallback)

    return features


def score_url_with_model(url: str, results: dict) -> dict:
    """Run the trained ML model on the provided URL/results bundle."""
    model = _load_model()
    features = _extract_feature_values(url, results)
    ordered = np.array([[features[name] for name in model.feature_names_in_]], dtype=float)
    proba = float(model.predict_proba(ordered)[0][1])
    score = int(round(proba * 100))
    
    # Check if domain is in whitelist of legitimate domains
    parsed = urlparse(_normalize_url(url))
    hostname = (parsed.hostname or "").lower()
    is_whitelisted = hostname in LEGITIMATE_DOMAINS or any(
        hostname.endswith(f".{domain}") for domain in LEGITIMATE_DOMAINS
    )
    
    # Adjust score for whitelisted domains (reduce false positives)
    original_score = score
    if is_whitelisted and score > 20:
        # Reduce score significantly for whitelisted domains, but keep some base score
        score = max(5, min(20, score // 3))
        whitelist_adjusted = True
    else:
        whitelist_adjusted = False

    if score >= 70:
        label = "High Risk"
    elif score >= 40:
        label = "Medium Risk"
    else:
        label = "Low Risk"

    reasons = []
    if whitelist_adjusted:
        reasons.append(f"Domain is whitelisted as legitimate (original ML score: {original_score}, adjusted to: {score}).")
    if score >= 70:
        reasons.append("ML model predicts high probability of phishing.")
    elif score >= 40:
        reasons.append("ML model predicts moderate risk.")
    else:
        reasons.append("ML model predicts low risk.")

    return {
        "score": score,
        "label": label,
        "probability": proba,
        "reasons": reasons,
        "features": features,
        "original_ml_score": original_score if whitelist_adjusted else None,
        "whitelisted": is_whitelisted,
    }
